"""Run independent SAFE scans, then compare retained facts without issuing requests."""

from dataclasses import dataclass
from itertools import combinations
from uuid import UUID

from pydantic import ValidationError

from gqlsleuth.application.graphql_detection import CandidateDetectionResult
from gqlsleuth.application.safe_execution import (
    QueryExecutionResult,
    SafeExecutionScanResult,
    run_safe_execution_scan,
)
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.differential import (
    ComparisonLimitation,
    ContextObservation,
    ContextPairReview,
    DifferenceKind,
    DifferentialReviewCandidate,
    NamedAuthContext,
    validate_context_names,
)
from gqlsleuth.domain.exceptions import GQLSleuthError, HttpConfigurationError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode, Target
from gqlsleuth.domain.schema import ParsedSchema
from gqlsleuth.infrastructure.http import HttpClientSettings


@dataclass(frozen=True)
class ContextScanResult:
    name: str
    scan: SafeExecutionScanResult | None
    error_code: str | None = None


@dataclass(frozen=True)
class DifferentialScanResult:
    target: Target
    contexts: tuple[ContextScanResult, ...]
    pairs: tuple[ContextPairReview, ...]

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        return tuple(
            item for context in self.contexts if context.scan for item in context.scan.evidence
        )


def run_differential_scan(
    target_url: str,
    *,
    contexts: tuple[NamedAuthContext, ...],
    http_settings: HttpClientSettings | None = None,
    mode: ScanMode = ScanMode.SAFE,
) -> DifferentialScanResult:
    """Validate all configuration before scanning; never share clients or cookie jars."""
    target = Target.parse(target_url)
    validate_context_names(tuple(context.name for context in contexts))
    base = http_settings or HttpClientSettings()
    if mode is not ScanMode.SAFE:
        raise HttpConfigurationError("Differential scans support SAFE mode only.")
    if base.custom_headers:
        raise HttpConfigurationError("Common headers cannot be mixed with named contexts.")
    try:
        settings = tuple(
            HttpClientSettings(
                **base.model_dump(exclude={"custom_headers"}), custom_headers=context.headers
            )
            for context in contexts
        )
    except ValidationError:
        raise HttpConfigurationError("Invalid named context HTTP settings.") from None
    results = []
    for context, configured in zip(contexts, settings, strict=True):
        try:
            scan = run_safe_execution_scan(target_url, mode=ScanMode.SAFE, http_settings=configured)
        except GQLSleuthError as error:
            # Keep only the project-owned exception class, never a supplied value or raw dump.
            results.append(ContextScanResult(context.name, None, type(error).__name__))
        else:
            results.append(ContextScanResult(context.name, scan))
    return compare_context_scans(target, tuple(results))


def compare_context_scans(
    target: Target, contexts: tuple[ContextScanResult, ...]
) -> DifferentialScanResult:
    """Compare exact candidate URLs and root field names; missing data is not absence."""
    validate_context_names(tuple(context.name for context in contexts))
    for context in contexts:
        if context.scan:
            schema_scan = context.scan.query_generation.operation_analysis.schema_scan
            discovery = schema_scan.introspection.detection.discovery
            if discovery.mode is not ScanMode.SAFE or discovery.target != target:
                raise HttpConfigurationError(
                    "Comparison requires SAFE results for the same target."
                )
    return DifferentialScanResult(
        target, contexts, tuple(_compare_pair(a, b) for a, b in combinations(contexts, 2))
    )


def _evidence_ids(
    scan: SafeExecutionScanResult, endpoint: str, kind: EvidenceType
) -> tuple[UUID, ...]:
    return tuple(
        item.evidence_id
        for item in scan.evidence
        if item.endpoint == endpoint and item.evidence_type is kind
    )


def _execution_observation(
    scan: SafeExecutionScanResult, item: QueryExecutionResult
) -> ContextObservation:
    artifact = item.generated_query
    ids = tuple(
        fact.evidence_id
        for fact in scan.execution_evidence
        if fact.endpoint == item.endpoint
        and fact.query == artifact.query_text
        and fact.variables == artifact.variables
    )
    return ContextObservation(
        item.status.value, item.response.status_code if item.response else None, item.attempted, ids
    )


def _endpoint_observation(
    scan: SafeExecutionScanResult, detection: CandidateDetectionResult
) -> ContextObservation:
    discovery = (
        scan.query_generation.operation_analysis.schema_scan.introspection.detection.discovery
    )
    probe = next(
        (item for item in discovery.probes if item.candidate_url == detection.candidate_url), None
    )
    response = detection.post_response or (probe.response if probe else None)
    error_type = detection.post_error_type or (probe.error_type if probe else None)
    return ContextObservation(
        error_type or detection.confidence.value,
        response.status_code if response else None,
        evidence_ids=_evidence_ids(
            scan, detection.candidate_url, EvidenceType.GRAPHQL_CONFIRMATION
        ),
    )


def _root_names(schema: ParsedSchema, kind: OperationKind) -> tuple[str, ...]:
    root = schema.query_root if kind is OperationKind.QUERY else schema.mutation_root
    named = schema.type_named(root) if root else None
    return tuple(field.name for field in named.fields) if named else ()


def _compare_pair(a: ContextScanResult, b: ContextScanResult) -> ContextPairReview:
    candidates: list[DifferentialReviewCandidate] = []
    limitations: list[ComparisonLimitation] = []
    if a.scan is None or b.scan is None:
        missing = ", ".join(item.name for item in (a, b) if item.scan is None)
        return ContextPairReview(
            a.name,
            b.name,
            (),
            (ComparisonLimitation(None, "scan", f"No completed scan for context(s): {missing}."),),
        )
    left, right = a.scan, b.scan
    schemas_a = left.query_generation.operation_analysis.schema_scan
    schemas_b = right.query_generation.operation_analysis.schema_scan
    detections_a = {
        item.candidate_url: item for item in schemas_a.introspection.detection.detections
    }
    detections_b = {
        item.candidate_url: item for item in schemas_b.introspection.detection.detections
    }
    introspections_a = {item.endpoint: item for item in schemas_a.introspection.introspections}
    introspections_b = {item.endpoint: item for item in schemas_b.introspection.introspections}
    parsed_a = {
        item.endpoint: item.schema for item in schemas_a.schemas if item.success and item.schema
    }
    parsed_b = {
        item.endpoint: item.schema for item in schemas_b.schemas if item.success and item.schema
    }
    for endpoint in dict.fromkeys((*detections_a, *detections_b)):
        da, db = detections_a.get(endpoint), detections_b.get(endpoint)
        if da is None or db is None:
            limitations.append(
                ComparisonLimitation(
                    endpoint,
                    "endpoint",
                    "Endpoint was not observed in both contexts; discovery may stop "
                    "at the preferred endpoint.",
                )
            )
        else:
            ea, eb = _endpoint_observation(left, da), _endpoint_observation(right, db)
            if (ea.state, ea.http_status) != (eb.state, eb.http_status):
                candidates.append(
                    DifferentialReviewCandidate(
                        DifferenceKind.ENDPOINT_ACCESS_DIFFERENCE,
                        endpoint,
                        ea,
                        eb,
                    )
                )
        ia, ib = introspections_a.get(endpoint), introspections_b.get(endpoint)
        if ia is None or ib is None:
            limitations.append(
                ComparisonLimitation(
                    endpoint, "introspection", "Introspection was not observed in both contexts."
                )
            )
        elif ia.status != ib.status:
            candidates.append(
                DifferentialReviewCandidate(
                    DifferenceKind.INTROSPECTION_DIFFERENCE,
                    endpoint,
                    ContextObservation(
                        ia.status.value,
                        evidence_ids=_evidence_ids(
                            left, endpoint, EvidenceType.INTROSPECTION_RESULT
                        ),
                    ),
                    ContextObservation(
                        ib.status.value,
                        evidence_ids=_evidence_ids(
                            right, endpoint, EvidenceType.INTROSPECTION_RESULT
                        ),
                    ),
                )
            )
        sa, sb = parsed_a.get(endpoint), parsed_b.get(endpoint)
        if sa is None or sb is None:
            limitations.append(
                ComparisonLimitation(
                    endpoint,
                    "schema",
                    "Parsed schema unavailable in at least one context; operation visibility "
                    "and Query outcomes cannot be compared.",
                )
            )
            continue
        for kind in (OperationKind.QUERY, OperationKind.MUTATION):
            names_a, names_b = _root_names(sa, kind), _root_names(sb, kind)
            for name in dict.fromkeys((*names_a, *names_b)):
                if (name in names_a) != (name in names_b):
                    candidates.append(
                        DifferentialReviewCandidate(
                            DifferenceKind.OPERATION_VISIBILITY_DIFFERENCE,
                            endpoint,
                            ContextObservation(
                                "visible" if name in names_a else "absent",
                                evidence_ids=_evidence_ids(
                                    left, endpoint, EvidenceType.SCHEMA_ARTIFACT
                                ),
                            ),
                            ContextObservation(
                                "visible" if name in names_b else "absent",
                                evidence_ids=_evidence_ids(
                                    right, endpoint, EvidenceType.SCHEMA_ARTIFACT
                                ),
                            ),
                            kind,
                            name,
                        )
                    )
                elif kind is OperationKind.QUERY:
                    _compare_execution(left, right, endpoint, name, candidates, limitations)
    return ContextPairReview(a.name, b.name, tuple(candidates), tuple(limitations))


def _compare_execution(
    left: SafeExecutionScanResult,
    right: SafeExecutionScanResult,
    endpoint: str,
    name: str,
    candidates: list[DifferentialReviewCandidate],
    limitations: list[ComparisonLimitation],
) -> None:
    a = next(
        (
            item
            for item in left.executions
            if item.endpoint == endpoint and item.operation_name == name
        ),
        None,
    )
    b = next(
        (
            item
            for item in right.executions
            if item.endpoint == endpoint and item.operation_name == name
        ),
        None,
    )
    if a is None or b is None:
        limitations.append(
            ComparisonLimitation(
                endpoint,
                "execution",
                f"Query {name}: execution result unavailable in at least one context "
                "(for example, generation did not succeed).",
            )
        )
        return
    oa, ob = _execution_observation(left, a), _execution_observation(right, b)
    if (oa.state, oa.http_status, oa.attempted) != (ob.state, ob.http_status, ob.attempted):
        candidates.append(
            DifferentialReviewCandidate(
                DifferenceKind.EXECUTION_OUTCOME_DIFFERENCE,
                endpoint,
                oa,
                ob,
                OperationKind.QUERY,
                name,
            )
        )
    if (a.generated_query.query_text, a.generated_query.variables) != (
        b.generated_query.query_text,
        b.generated_query.variables,
    ):
        limitations.append(
            ComparisonLimitation(
                endpoint,
                "execution",
                f"Query {name}: generated documents or placeholder variables differ; "
                "outcomes are not from equivalent requests.",
            )
        )
