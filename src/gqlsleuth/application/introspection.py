"""Coordinate discovery, GraphQL detection, and raw introspection retrieval."""

from dataclasses import dataclass

from gqlsleuth.application.graphql_detection import (
    GraphQLDetectionResult,
    discover_and_detect_graphql,
)
from gqlsleuth.application.scan_configuration import map_scan_inputs
from gqlsleuth.domain.exceptions import HttpError
from gqlsleuth.domain.models import ConfidenceLevel, Evidence, EvidenceType, ScanMode
from gqlsleuth.graphql.introspection import (
    FULL_INTROSPECTION_QUERY,
    MINIMAL_INTROSPECTION_QUERY,
    IntrospectionStatus,
    classify_introspection_response,
)
from gqlsleuth.infrastructure.http import HttpClient, HttpRequest, HttpResponse

INTROSPECTION_SOURCE = "gqlsleuth.application.introspection"


@dataclass(frozen=True)
class EndpointIntrospectionResult:
    """Minimal and full introspection outcomes for one GraphQL endpoint."""

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
) -> IntrospectionScanResult:
    """Run Phases 3–5 through one shared synchronous HTTP client."""
    target, settings = map_scan_inputs(target_url, mode=mode)
    with HttpClient() as client:
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
    return EndpointIntrospectionResult(
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
    if result.minimal_error_type is not None:
        notes.append(f"Minimal probe failure: {result.minimal_error_type}")
    if result.full_error_type is not None:
        notes.append(f"Full retrieval failure: {result.full_error_type}")

    return Evidence(
        evidence_type=EvidenceType.INTROSPECTION_RESULT,
        target=detection.discovery.target,
        endpoint=result.endpoint,
        summary=f"{result.status.value.upper()} — {result.reason}",
        source=INTROSPECTION_SOURCE,
        notes=tuple(notes),
    )
