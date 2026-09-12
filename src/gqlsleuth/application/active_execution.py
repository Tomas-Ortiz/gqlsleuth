"""Prepare active previews and independently gate sequential selected Mutation execution."""

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from time import perf_counter

from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.active import (
    MAX_MUTATION_EXECUTIONS,
    MutationDecision,
    MutationExecutionEvidence,
    MutationGenerationResult,
    MutationPreview,
)
from gqlsleuth.domain.analysis import OperationAnalysis, OperationKind
from gqlsleuth.domain.exceptions import GQLSleuthError, HttpError, QueryGenerationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import Evidence, ScanMode
from gqlsleuth.domain.schema import ParsedSchema
from gqlsleuth.graphql.active_execution import assess_mutation
from gqlsleuth.graphql.query_generation import DEFAULT_MAX_SELECTION_DEPTH, generate_mutation
from gqlsleuth.graphql.safe_execution import classify_execution_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest, HttpResponse


@dataclass(frozen=True)
class ActiveMutationPreviewResult:
    """Complete Phase 9 result plus ordered, locally prepared Mutation candidates."""

    safe_execution: SafeExecutionScanResult
    candidates: tuple[MutationPreview, ...]

    @property
    def mode(self) -> ScanMode:
        schema_scan = self.safe_execution.query_generation.operation_analysis.schema_scan
        return schema_scan.introspection.detection.discovery.mode

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        return self.safe_execution.evidence


@dataclass(frozen=True)
class MutationExecutionResult:
    """One ordered decision with response classification only when HTTP was attempted."""

    preview: MutationPreview
    selected: bool
    decision: MutationDecision
    reason: str
    status: QueryExecutionStatus | None = None
    response: HttpResponse | None = None
    error_type: str | None = None
    error_message: str | None = None

    @property
    def attempted(self) -> bool:
        return self.decision is MutationDecision.EXECUTED


@dataclass(frozen=True)
class ActiveExecutionScanResult:
    """Preserve previews, explicit selection, confirmation, decisions, and actual evidence."""

    preview: ActiveMutationPreviewResult
    selected_indices: tuple[int, ...]
    confirmed: bool
    executions: tuple[MutationExecutionResult, ...]
    execution_evidence: tuple[MutationExecutionEvidence, ...]

    @property
    def safe_execution(self) -> SafeExecutionScanResult:
        return self.preview.safe_execution

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        return self.preview.evidence + self.execution_evidence


def prepare_active_mutations(
    safe_result: SafeExecutionScanResult,
    *,
    max_selection_depth: int = DEFAULT_MAX_SELECTION_DEPTH,
) -> ActiveMutationPreviewResult:
    """Generate only in ACTIVE, without HTTP or terminal interaction; isolate failures."""
    preview = ActiveMutationPreviewResult(safe_result, ())
    if preview.mode is not ScanMode.ACTIVE:
        return preview
    schemas = _schemas(safe_result)
    candidates: list[MutationPreview] = []
    for operation in _mutations(safe_result):
        schema = schemas.get(operation.endpoint)
        try:
            if schema is None:
                raise QueryGenerationError("Parsed schema is unavailable for this endpoint.")
            artifact = generate_mutation(schema, operation, max_selection_depth=max_selection_depth)
        except QueryGenerationError as error:
            artifact = MutationGenerationResult(operation, None, {}, (), str(error))
        candidates.append(assess_mutation(schema, artifact))
    return replace(preview, candidates=tuple(candidates))


def execute_selected_mutations(
    preview: ActiveMutationPreviewResult,
    *,
    selected_indices: tuple[int, ...] = (),
    confirmed: bool = False,
    client: HttpClient | None = None,
    http_settings: HttpClientSettings | None = None,
) -> ActiveExecutionScanResult:
    """Execute at most five explicitly selected, confirmed, revalidated active operations.

    Indices are one-based preview indices. Duplicate indices are deduplicated; execution
    follows retained Phase 7 order regardless of selection or supplied preview ordering.
    Blocked/invalid selections remain structured decisions and never consume the limit.
    """
    if client is None:
        with HttpClient(http_settings) as active_client:
            return execute_selected_mutations(
                preview,
                selected_indices=selected_indices,
                confirmed=confirmed,
                client=active_client,
            )
    if any(
        type(index) is not int or not 1 <= index <= len(preview.candidates)
        for index in selected_indices
    ):
        raise GQLSleuthError("Mutation selection contains an unknown candidate index.")
    selected = frozenset(selected_indices)
    schemas = _schemas(preview.safe_execution)
    operations = _mutations(preview.safe_execution)
    order = {
        (operation.endpoint, operation.name): index for index, operation in enumerate(operations)
    }
    retained = {(operation.endpoint, operation.name): operation for operation in operations}
    indexed = sorted(
        enumerate(preview.candidates, start=1),
        key=lambda item: order.get(
            (item[1].generated_mutation.endpoint, item[1].generated_mutation.operation_name),
            len(order),
        ),
    )
    results: list[MutationExecutionResult] = []
    evidence: list[MutationExecutionEvidence] = []
    seen: set[tuple[str, str]] = set()
    for index, candidate in indexed:
        artifact = candidate.generated_mutation
        key = (artifact.endpoint, artifact.operation_name)
        checked = assess_mutation(schemas.get(artifact.endpoint), artifact)
        if retained.get(key) != artifact.operation or key in seen:
            checked = MutationPreview(
                artifact,
                MutationDecision.INVALID_ARTIFACT,
                "Mutation metadata is absent from retained Phase 7 analysis or duplicated.",
            )
        seen.add(key)
        decision, reason = checked.decision, checked.reason
        if preview.mode is not ScanMode.ACTIVE:
            decision, reason = (
                MutationDecision.MODE_DISABLED,
                "Mutation execution requires ACTIVE mode.",
            )
        elif checked.selectable:
            if index not in selected:
                decision, reason = MutationDecision.NOT_SELECTED, "Mutation was not selected."
            elif confirmed is not True:
                decision, reason = (
                    MutationDecision.DECLINED,
                    "Final batch confirmation was not given.",
                )
            elif len(evidence) >= MAX_MUTATION_EXECUTIONS:
                decision, reason = (
                    MutationDecision.SKIPPED_LIMIT,
                    "Five-Mutation scan limit reached.",
                )
            else:
                result, item_evidence = _execute_one(preview, checked, client)
                results.append(result)
                evidence.append(item_evidence)
                continue
        results.append(MutationExecutionResult(checked, index in selected, decision, reason))
    return ActiveExecutionScanResult(
        preview, tuple(sorted(selected)), confirmed is True, tuple(results), tuple(evidence)
    )


def _schemas(result: SafeExecutionScanResult) -> dict[str, ParsedSchema]:
    return {
        item.endpoint: item.schema
        for item in result.query_generation.operation_analysis.schema_scan.schemas
        if item.success and item.schema is not None
    }


def _mutations(result: SafeExecutionScanResult) -> tuple[OperationAnalysis, ...]:
    return tuple(
        operation
        for endpoint in result.query_generation.operation_analysis.endpoints
        if endpoint.success
        for operation in endpoint.operations
        if operation.kind is OperationKind.MUTATION
    )


def _execute_one(
    preview: ActiveMutationPreviewResult,
    candidate: MutationPreview,
    client: HttpClient,
) -> tuple[MutationExecutionResult, MutationExecutionEvidence]:
    # Snapshot mutable JSON containers before transport so evidence keeps the sent values.
    artifact = replace(
        candidate.generated_mutation, variables=deepcopy(candidate.generated_mutation.variables)
    )
    candidate = replace(candidate, generated_mutation=artifact)
    timestamp = datetime.now(UTC)
    started = perf_counter()
    response = None
    error_type = error_message = None
    try:
        response = client.send(
            HttpRequest(
                method="POST",
                url=artifact.endpoint,
                json_body={"query": artifact.query_text, "variables": deepcopy(artifact.variables)},
            )
        )
        classification = classify_execution_response(response.status_code, response.body)
        status, reason = classification.status, classification.reason
    except HttpError as error:
        error_type, error_message = type(error).__name__, str(error)
        status = QueryExecutionStatus.NETWORK_FAILURE
        reason = f"Mutation request failed with {error_type}."
    duration = response.duration_seconds if response is not None else perf_counter() - started
    result = MutationExecutionResult(
        candidate,
        True,
        MutationDecision.EXECUTED,
        reason,
        status,
        response,
        error_type,
        error_message,
    )
    evidence = MutationExecutionEvidence(
        target=(
            preview.safe_execution.query_generation.operation_analysis.schema_scan.introspection.detection.discovery.target
        ),
        endpoint=artifact.endpoint,
        timestamp=timestamp,
        summary=f"Mutation '{artifact.operation_name}' execution produced {status.value.upper()}.",
        source="gqlsleuth.application.active_execution",
        notes=(
            "Execution evidence is not vulnerability confirmation.",
            *artifact.manual_adjustments,
        ),
        query=artifact.query_text,
        variables=deepcopy(artifact.variables),
        request_method="POST",
        response_status_code=response.status_code if response is not None else None,
        response_headers=response.headers if response is not None else None,
        response_body=response.body if response is not None else None,
        duration_seconds=duration,
        error_type=error_type,
        error_message=error_message,
        execution_status=status,
        operation=artifact.operation,
    )
    return result, evidence
