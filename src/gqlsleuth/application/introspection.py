"""Coordinate discovery, GraphQL detection, and raw introspection retrieval."""

from dataclasses import dataclass, replace

from gqlsleuth.application.graphql_detection import (
    GraphQLDetectionResult,
    discover_and_detect_graphql,
)
from gqlsleuth.application.progressive_introspection import (
    ProgressiveRecoveryResult,
    recover_schema,
)
from gqlsleuth.application.scan_configuration import map_scan_inputs
from gqlsleuth.domain.exceptions import HttpError
from gqlsleuth.domain.models import ConfidenceLevel, Evidence, EvidenceType, ScanMode
from gqlsleuth.graphql.introspection import (
    FULL_INTROSPECTION_QUERY,
    MINIMAL_INTROSPECTION_QUERY,
    REDUCED_INTROSPECTION_QUERY,
    IntrospectionFallbackReason,
    IntrospectionResponseClassification,
    IntrospectionStatus,
    SchemaRetrievalStatus,
    classify_introspection_response,
    reduced_introspection_fallback_reason,
)
from gqlsleuth.graphql.progressive_introspection import AssembledSchema
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest, HttpResponse

INTROSPECTION_SOURCE = "gqlsleuth.application.introspection"


@dataclass(frozen=True)
class EndpointIntrospectionResult:
    """Retained retrieval outcomes, including optional reduced and progressive provenance."""

    endpoint: str
    status: IntrospectionStatus
    minimal_response: HttpResponse | None
    minimal_error_type: str | None
    minimal_error_message: str | None
    full_retrieval_attempted: bool
    full_response: HttpResponse | None
    full_error_type: str | None
    full_error_message: str | None
    reason: str
    reduced_retrieval_attempted: bool = False
    reduced_response: HttpResponse | None = None
    reduced_error_type: str | None = None
    reduced_error_message: str | None = None
    fallback_reason: IntrospectionFallbackReason | None = None
    progressive: ProgressiveRecoveryResult | None = None

    @property
    def minimal_result(self) -> IntrospectionResponseClassification:
        """Expose the probe fact without replacing the legacy final-stage status."""
        if self.minimal_response is not None:
            return classify_introspection_response(
                self.minimal_response.status_code, self.minimal_response.body
            )
        return IntrospectionResponseClassification(
            IntrospectionStatus.NETWORK_FAILURE,
            self.minimal_error_message or self.reason,
        )

    @property
    def full_result(self) -> IntrospectionResponseClassification | None:
        """Classify retained retrieval facts locally; never send another request."""
        if not self.full_retrieval_attempted:
            return None
        if self.full_response is not None:
            return classify_introspection_response(
                self.full_response.status_code, self.full_response.body
            )
        return IntrospectionResponseClassification(
            IntrospectionStatus.NETWORK_FAILURE,
            self.full_error_message or self.reason,
        )

    @property
    def reduced_result(self) -> IntrospectionResponseClassification | None:
        """Expose the one fallback outcome without changing the legacy full-stage status."""
        if not self.reduced_retrieval_attempted:
            return None
        if self.reduced_response is not None:
            return classify_introspection_response(
                self.reduced_response.status_code, self.reduced_response.body
            )
        return IntrospectionResponseClassification(
            IntrospectionStatus.NETWORK_FAILURE, self.reduced_error_message or self.reason
        )

    @property
    def selected_schema_response(self) -> HttpResponse | None:
        """Select retained schema bytes; parsing remains a separate local stage."""
        if self.progressive is not None:
            return None
        if self.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL:
            return self.reduced_response
        if self.status is IntrospectionStatus.ENABLED and not self.reduced_retrieval_attempted:
            return self.full_response
        return None

    @property
    def selected_schema_source(self) -> HttpResponse | AssembledSchema | None:
        """Expose an explicit local source only after complete reconstruction validates."""
        if self.progressive is not None:
            return self.progressive.assembled
        return self.selected_schema_response

    @property
    def schema_retrieval_summary(self) -> str | None:
        """Describe exceptional retrieval paths without exposing target response text."""
        if self.progressive is not None:
            return (
                "Full retrieval and reduced fallback rejected by query-shape limits. "
                + self.progressive.summary
            )
        full = self.full_result
        if full is None or full.status is IntrospectionStatus.ENABLED:
            return None
        if not self.reduced_retrieval_attempted:
            status = f" (HTTP {self.full_response.status_code})" if self.full_response else ""
            return f"Full retrieval unsuccessful{status}; reduced fallback not attempted."
        restriction = (
            self.fallback_reason.value.replace("_", " ")
            if self.fallback_reason
            else "query restriction"
        )
        prefix = f"Full retrieval rejected by {restriction}; one reduced fallback attempted"
        if self.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL:
            return prefix + " and succeeded; coverage may be incomplete."
        outcome = (
            "was also rejected"
            if self.schema_retrieval_status is SchemaRetrievalStatus.BLOCKED
            else "failed"
        )
        return prefix + f" and {outcome}; no schema selected."

    @property
    def schema_retrieval_reason(self) -> str | None:
        if self.reduced_retrieval_attempted:
            return self.reason
        full = self.full_result
        if full is None:
            return None
        summary = self.schema_retrieval_summary
        return f"{summary} {full.reason}" if summary else full.reason

    @property
    def schema_retrieval_status(self) -> SchemaRetrievalStatus:
        if self.progressive is not None:
            return self.progressive.status
        full = self.full_result
        if full is None:
            return SchemaRetrievalStatus.NOT_ATTEMPTED
        if full.status is IntrospectionStatus.ENABLED:
            return SchemaRetrievalStatus.RETRIEVED
        reduced = self.reduced_result
        if reduced is not None:
            if reduced.status is IntrospectionStatus.ENABLED:
                return SchemaRetrievalStatus.PARTIAL
            full = reduced
        if full.status in {
            IntrospectionStatus.DISABLED,
            IntrospectionStatus.AUTHENTICATION_REQUIRED,
            IntrospectionStatus.AUTHORIZATION_DENIED,
            IntrospectionStatus.ENDPOINT_ERROR,
        }:
            return SchemaRetrievalStatus.BLOCKED
        return SchemaRetrievalStatus.FAILED


@dataclass(frozen=True)
class IntrospectionScanResult:
    """Complete Phase 4 result and ordered Phase 5 introspection outcomes."""

    detection: GraphQLDetectionResult
    introspections: tuple[EndpointIntrospectionResult, ...]
    introspection_evidence: tuple[Evidence, ...]

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        """Return Phase 3, Phase 4, and Phase 5 evidence in order."""
        return self.detection.evidence + self.introspection_evidence


def run_introspection_scan(
    target_url: str,
    *,
    mode: ScanMode = ScanMode.SAFE,
    http_settings: HttpClientSettings | None = None,
) -> IntrospectionScanResult:
    """Run Phases 3–5 through one shared synchronous HTTP client."""
    target, settings = map_scan_inputs(target_url, mode=mode)
    with HttpClient(http_settings) as client:
        detection = discover_and_detect_graphql(target, mode=settings.mode, client=client)
        return introspect_detected_endpoints(detection, client=client)


def introspect_detected_endpoints(
    detection: GraphQLDetectionResult,
    *,
    client: HttpClient,
) -> IntrospectionScanResult:
    """Introspect only confirmed or probable endpoints, isolating failures."""
    results: list[EndpointIntrospectionResult] = []
    evidence: list[Evidence] = []

    for candidate in detection.detections:
        if candidate.confidence not in {
            ConfidenceLevel.CONFIRMED,
            ConfidenceLevel.PROBABLE,
        }:
            continue
        result = _introspect_endpoint(candidate.candidate_url, client)
        results.append(result)
        evidence.append(_introspection_evidence(detection, result))
        if result.progressive is not None:
            for attempt in result.progressive.attempts:
                response = attempt.response
                evidence.append(
                    Evidence(
                        evidence_type=EvidenceType.INTROSPECTION_RESULT,
                        target=detection.discovery.target,
                        endpoint=result.endpoint,
                        timestamp=attempt.timestamp,
                        summary=f"Progressive introspection request: {attempt.shape}.",
                        source=INTROSPECTION_SOURCE,
                        notes=(
                            f"Recovery shape: {attempt.shape}",
                            f"Response classification: {attempt.classification}",
                            *(
                                f"Unsupported includeDeprecated: {key}"
                                for key in attempt.unsupported_arguments
                            ),
                            *(
                                f"Compatibility omission: {key}.includeDeprecated"
                                for key in attempt.omitted_arguments
                            ),
                            "Original server response; not locally assembled schema.",
                        ),
                        query=attempt.query,
                        variables=attempt.variables,
                        request_method="POST",
                        response_status_code=response.status_code if response else None,
                        response_headers=response.headers if response else None,
                        response_body=response.body if response else None,
                        duration_seconds=response.duration_seconds if response else None,
                        error_type=attempt.error_type,
                        error_message=attempt.error_message,
                    )
                )

    return IntrospectionScanResult(
        detection=detection,
        introspections=tuple(results),
        introspection_evidence=tuple(evidence),
    )


def _introspect_endpoint(endpoint: str, client: HttpClient) -> EndpointIntrospectionResult:
    try:
        minimal_response = _send_query(client, endpoint, MINIMAL_INTROSPECTION_QUERY)
    except HttpError as error:
        error_type = type(error).__name__
        return EndpointIntrospectionResult(
            endpoint=endpoint,
            status=IntrospectionStatus.NETWORK_FAILURE,
            minimal_response=None,
            minimal_error_type=error_type,
            minimal_error_message=str(error),
            full_retrieval_attempted=False,
            full_response=None,
            full_error_type=None,
            full_error_message=None,
            reason=f"Minimal introspection probe failed with {error_type}.",
        )

    minimal = classify_introspection_response(
        minimal_response.status_code,
        minimal_response.body,
    )
    if minimal.status is not IntrospectionStatus.ENABLED:
        return EndpointIntrospectionResult(
            endpoint=endpoint,
            status=minimal.status,
            minimal_response=minimal_response,
            minimal_error_type=None,
            minimal_error_message=None,
            full_retrieval_attempted=False,
            full_response=None,
            full_error_type=None,
            full_error_message=None,
            reason=minimal.reason,
        )

    try:
        full_response = _send_query(client, endpoint, FULL_INTROSPECTION_QUERY)
    except HttpError as error:
        error_type = type(error).__name__
        return EndpointIntrospectionResult(
            endpoint=endpoint,
            status=IntrospectionStatus.NETWORK_FAILURE,
            minimal_response=minimal_response,
            minimal_error_type=None,
            minimal_error_message=None,
            full_retrieval_attempted=True,
            full_response=None,
            full_error_type=error_type,
            full_error_message=str(error),
            reason=f"Minimal probe enabled introspection; full retrieval failed with {error_type}.",
        )

    full = classify_introspection_response(full_response.status_code, full_response.body)
    reason = (
        "Minimal probe enabled introspection and the full introspection response was retrieved."
        if full.status is IntrospectionStatus.ENABLED
        else f"Minimal probe enabled introspection; full retrieval result: {full.reason}"
    )
    result = EndpointIntrospectionResult(
        endpoint=endpoint,
        status=full.status,
        minimal_response=minimal_response,
        minimal_error_type=None,
        minimal_error_message=None,
        full_retrieval_attempted=True,
        full_response=full_response,
        full_error_type=None,
        full_error_message=None,
        reason=reason,
    )
    fallback = reduced_introspection_fallback_reason(full_response.status_code, full_response.body)
    if fallback is None:
        return result
    prefix = f"Minimal probe enabled introspection; full retrieval rejected by {fallback.value}. "
    try:
        reduced_response = _send_query(client, endpoint, REDUCED_INTROSPECTION_QUERY)
    except HttpError as error:
        return replace(
            result,
            reduced_retrieval_attempted=True,
            fallback_reason=fallback,
            reduced_error_type=type(error).__name__,
            reduced_error_message=str(error),
            reason=prefix + f"One reduced fallback failed with {type(error).__name__}.",
        )
    reduced = classify_introspection_response(reduced_response.status_code, reduced_response.body)
    result = replace(
        result,
        reduced_retrieval_attempted=True,
        fallback_reason=fallback,
        reduced_response=reduced_response,
        reason=prefix
        + (
            "One reduced introspection fallback succeeded; schema retrieval PARTIAL. "
            "Operation and schema coverage may be incomplete."
            if reduced.status is IntrospectionStatus.ENABLED
            else f"One reduced fallback did not retrieve a schema: {reduced.reason}"
        ),
    )
    if (
        reduced_introspection_fallback_reason(reduced_response.status_code, reduced_response.body)
        is not None
    ):
        progressive = recover_schema(endpoint, client)
        return replace(
            result,
            progressive=progressive,
            reason=prefix
            + f"Reduced retrieval: {reduced.reason} "
            + progressive.summary
            + " "
            + progressive.last_result.reason
            + " "
            + " ".join(progressive.inventory_notes),
        )
    return result


def _send_query(client: HttpClient, endpoint: str, query: str) -> HttpResponse:
    return client.send(
        HttpRequest(
            method="POST",
            url=endpoint,
            json_body={"query": query},
        )
    )


def _introspection_evidence(
    detection: GraphQLDetectionResult,
    result: EndpointIntrospectionResult,
) -> Evidence:
    notes = [
        f"Introspection status: {result.status.value}",
        f"Full retrieval attempted: {'yes' if result.full_retrieval_attempted else 'no'}",
    ]
    if result.reduced_retrieval_attempted:
        reduced = result.reduced_result
        notes.extend(
            (
                f"Minimal introspection: {result.minimal_result.status.value}",
                f"Full restriction: {result.fallback_reason}",
                "Reduced fallback attempted: yes",
                f"Schema retrieval: {result.schema_retrieval_status.value}",
            )
        )
        if reduced is not None:
            notes.append(f"Reduced retrieval outcome: {reduced.status.value}")
        if result.reduced_error_type:
            notes.append(f"Reduced retrieval failure: {result.reduced_error_type}")
    if result.minimal_error_type is not None:
        notes.append(f"Minimal probe failure: {result.minimal_error_type}")
    if result.full_error_type is not None:
        notes.append(f"Full retrieval failure: {result.full_error_type}")
    if result.progressive is not None:
        notes.extend(
            (
                "Recovery method: PROGRESSIVE",
                f"Recovery stop reason: {result.progressive.stop_reason}",
                *result.progressive.inventory_notes,
            )
        )

    return Evidence(
        evidence_type=EvidenceType.INTROSPECTION_RESULT,
        target=detection.discovery.target,
        endpoint=result.endpoint,
        summary=(
            f"{result.schema_retrieval_status.value.upper()} — {result.reason}"
            if result.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
            or result.progressive is not None
            else f"{result.status.value.upper()} — {result.reason}"
        ),
        source=INTROSPECTION_SOURCE,
        notes=tuple(notes),
    )
