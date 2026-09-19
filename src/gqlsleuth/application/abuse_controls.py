"""One exact retained request, independent consent and a fixed terminal repetition budget."""

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from time import perf_counter
from uuid import NAMESPACE_URL, uuid5

from graphql import GraphQLError

from gqlsleuth.application.active_execution import ActiveExecutionScanResult
from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.abuse_controls import (
    MAX_PHASE27_MUTATION_REQUESTS,
    MAX_PHASE27_QUERY_REQUESTS,
    AbuseControlCandidate,
    AbuseControlEvidence,
    AbuseControlFinding,
    AbuseControlOutcome,
    AbuseControlResult,
)
from gqlsleuth.domain.active import MutationExecutionEvidence, MutationGenerationResult
from gqlsleuth.domain.analysis import PRIORITY_RANK, OperationCategory, OperationKind
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.query_generation import OperationGenerationResult
from gqlsleuth.graphql.abuse_controls import (
    AbuseControlResponse,
    classify_abuse_response,
    eligible_baseline,
)
from gqlsleuth.graphql.active_execution import assess_mutation
from gqlsleuth.graphql.object_authorization import validate_object_document
from gqlsleuth.graphql.safe_execution import side_effect_tokens, validate_operation_artifact
from gqlsleuth.graphql.schema_parser import load_introspection_schema
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest, HttpResponse
from gqlsleuth.infrastructure.probe_evidence import (
    capture_probe_response,
    request_context_material,
    same_origin,
)

_SENSITIVE_CATEGORIES = frozenset(
    {
        OperationCategory.AUTHENTICATION,
        OperationCategory.PASSWORD_MANAGEMENT,
        OperationCategory.ACCOUNT_RECOVERY,
        OperationCategory.TOKENS_AND_SESSIONS,
    }
)


@dataclass(frozen=True)
class _Baseline:
    artifact: OperationGenerationResult
    kind: OperationKind
    status: QueryExecutionStatus
    response: HttpResponse
    evidence: tuple[Evidence, ...]


def _baselines(
    result: SafeExecutionScanResult | ActiveExecutionScanResult,
) -> tuple[_Baseline, ...]:
    safe = result.safe_execution if isinstance(result, ActiveExecutionScanResult) else result
    sources = [
        _Baseline(
            item.generated_query,
            OperationKind.QUERY,
            item.status,
            item.response,
            safe.execution_evidence,
        )
        for item in safe.executions
        if item.attempted is True
        and item.response is not None
        and item.generated_query in safe.query_generation.queries
    ]
    if isinstance(result, ActiveExecutionScanResult) and result.confirmed is True:
        for item in result.executions:
            artifact = item.preview.generated_mutation
            selected = any(
                index in result.selected_indices and candidate.generated_mutation == artifact
                for index, candidate in enumerate(result.preview.candidates, 1)
            )
            if (
                item.attempted
                and item.selected is True
                and selected
                and item.status is not None
                and item.response is not None
            ):
                sources.append(
                    _Baseline(
                        artifact,
                        OperationKind.MUTATION,
                        item.status,
                        item.response,
                        result.execution_evidence,
                    )
                )
    return tuple(sources)


def prepare_abuse_controls(
    result: SafeExecutionScanResult | ActiveExecutionScanResult,
    *,
    enabled: bool = False,
    selected_index: int | None = None,
) -> AbuseControlResult:
    """Build only from ordinary execution containers, never the aggregated probe evidence."""
    safe = result.safe_execution if isinstance(result, ActiveExecutionScanResult) else result
    analysis = safe.query_generation.operation_analysis
    scan = analysis.schema_scan
    if enabled is not True or scan.introspection.detection.discovery.mode is not ScanMode.ACTIVE:
        return AbuseControlResult(
            limitations=("Abuse-control testing requires ACTIVE and explicit enablement.",)
        )
    operations = tuple(op for endpoint in analysis.endpoints for op in endpoint.operations)
    candidates = []
    seen = set()
    for source in _baselines(result):
        artifact, response = source.artifact, source.response
        try:
            if artifact.operation not in operations or artifact.operation.kind is not source.kind:
                continue
            if not eligible_baseline(source.status, response.status_code, response.body):
                continue
            if not same_origin(artifact.endpoint, response.final_url):
                continue
            schemas = [
                item.schema
                for item in scan.schemas
                if item.endpoint == artifact.endpoint and item.success and item.schema is not None
            ]
            raw = [
                item.full_response
                for item in scan.introspection.introspections
                if item.endpoint == artifact.endpoint and item.full_response is not None
            ]
            if len(schemas) != 1 or len(raw) != 1 or response.request_url != artifact.endpoint:
                continue
            validate_operation_artifact(schemas[0], artifact, expected_kind=source.kind)
            if source.kind is OperationKind.QUERY:
                if side_effect_tokens(artifact.operation_name):
                    continue
            elif (
                not isinstance(artifact, MutationGenerationResult)
                or not assess_mutation(schemas[0], artifact).selectable
            ):
                continue
            validate_object_document(
                load_introspection_schema(raw[0].body),
                artifact.query_text or "",
                artifact.variables,
                kind=source.kind,
            )
            evidence_type = (
                EvidenceType.QUERY_EXECUTION
                if source.kind is OperationKind.QUERY
                else EvidenceType.MUTATION_EXECUTION
            )
            source_name = (
                "gqlsleuth.application.safe_execution"
                if source.kind is OperationKind.QUERY
                else "gqlsleuth.application.active_execution"
            )
            matching = [
                item
                for item in source.evidence
                if item.evidence_type is evidence_type
                and item.source == source_name
                and item.endpoint == artifact.endpoint
                and item.query == artifact.query_text
                and exact_variables(item.variables) == exact_variables(artifact.variables)
                and item.request_method == "POST"
                and item.error_type is None
                and item.response_status_code == response.status_code
                and item.response_body == response.body
                and (
                    source.kind is OperationKind.QUERY
                    or (
                        isinstance(item, MutationExecutionEvidence)
                        and item.operation == artifact.operation
                        and item.execution_status is source.status
                        and item.execution_mode is ScanMode.ACTIVE
                    )
                )
            ]
            if len(matching) != 1 or matching[0].evidence_id in seen:
                continue
            seen.add(matching[0].evidence_id)
            candidates.append(
                AbuseControlCandidate(
                    0,
                    artifact.operation,
                    artifact.query_text or "",
                    deepcopy(artifact.variables),
                    matching[0].evidence_id,
                    evidence_type,
                    source.status,
                    response.status_code,
                    MAX_PHASE27_QUERY_REQUESTS
                    if source.kind is OperationKind.QUERY
                    else MAX_PHASE27_MUTATION_REQUESTS,
                )
            )
        except (
            SafeExecutionValidationError,
            SchemaParsingError,
            GraphQLError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            continue
    # Python's stable sort preserves retained Phase 7 order inside a priority/category group.
    order = {(op.endpoint, op.kind, op.name): index for index, op in enumerate(operations)}
    candidates.sort(
        key=lambda item: (
            not bool(_SENSITIVE_CATEGORIES.intersection(item.operation.categories)),
            PRIORITY_RANK[item.operation.priority],
            order[(item.endpoint, item.operation.kind, item.operation.name)],
        )
    )
    ordered = tuple(replace(item, index=index) for index, item in enumerate(candidates, 1))
    if selected_index is not None and (
        type(selected_index) is not int or not 1 <= selected_index <= len(ordered)
    ):
        raise HttpConfigurationError(
            "Select exactly one eligible abuse-control candidate index, or none."
        )
    selected = ordered[selected_index - 1] if selected_index is not None else None
    return AbuseControlResult(
        candidates=ordered,
        selected=selected,
        policy_id=uuid5(
            NAMESPACE_URL, "gqlsleuth:abuse-control:" + str(selected.baseline_evidence_id)
        )
        if selected
        else None,
        limitations=()
        if ordered
        else (
            "No eligible ordinary Query or executed generic Mutation baseline. "
            "Malformed, unavailable, ambiguous and already-controlled baselines are excluded.",
        ),
    )


def _matches(left: AbuseControlResult, right: AbuseControlResult) -> bool:
    try:
        return (
            type(left) is AbuseControlResult
            and left == right
            and type(left.confirmed) is bool
            and all(type(item.index) is int for item in left.candidates)
            and (left.selected is None or type(left.selected.index) is int)
            and exact_variables(tuple(item.variables for item in left.candidates))
            == exact_variables(tuple(item.variables for item in right.candidates))
            and exact_variables(left.selected.variables if left.selected else None)
            == exact_variables(right.selected.variables if right.selected else None)
        )
    except (ValueError, TypeError, RecursionError):
        return False


class AbuseControlSession:
    """One immutable selection; each invocation finishes the session, even when declined."""

    def __init__(
        self,
        result: SafeExecutionScanResult | ActiveExecutionScanResult,
        *,
        http_settings: HttpClientSettings,
        enabled: bool = False,
        selected_index: int | None = None,
    ) -> None:
        self._scan, self._settings = result, http_settings
        self._settings_snapshot = http_settings.model_dump_json()
        self._enabled, self._index = enabled, selected_index
        self._preview = self._prepare()
        self._result = self._preview
        self._finished = False
        self._attempts = 0

    def _prepare(self) -> AbuseControlResult:
        return prepare_abuse_controls(self._scan, enabled=self._enabled, selected_index=self._index)

    @property
    def preview(self) -> AbuseControlResult:
        return deepcopy(self._preview)

    def execute(
        self, *, preview: AbuseControlResult, confirmed: bool = False
    ) -> AbuseControlResult:
        if self._finished:
            return deepcopy(self._result)
        self._finished = True
        plan = self._preview
        selected = plan.selected
        self._result = replace(plan, confirmed=confirmed is True)
        if confirmed is not True or selected is None:
            self._result = replace(
                self._result,
                limitations=(
                    *plan.limitations,
                    "No selected operation with separate abuse-control confirmation; "
                    "zero repeats sent.",
                ),
            )
            return deepcopy(self._result)
        evidence = []
        limitations = list(plan.limitations)
        policy = PolicyStatus.UNRESOLVED
        limit = (
            MAX_PHASE27_MUTATION_REQUESTS
            if selected.operation.kind is OperationKind.MUTATION
            else MAX_PHASE27_QUERY_REQUESTS
        )
        for attempt in range(1, limit + 1):
            try:
                fresh = self._prepare()
            except HttpConfigurationError:
                fresh = None
            if (
                fresh is None
                or not _matches(plan, fresh)
                or not _matches(preview, fresh)
                or self._settings.model_dump_json() != self._settings_snapshot
                or self._attempts != attempt - 1
                or self._attempts >= limit
            ):
                limitations.append(
                    "Retained request, context or selection changed; remaining attempts not sent."
                )
                break
            assert fresh.selected is not None and fresh.policy_id is not None
            self._attempts += 1
            item = _request(self._scan, fresh, self._settings, attempt)
            evidence.append(item)
            if item.outcome is AbuseControlOutcome.CONTROL_SIGNAL_OBSERVED:
                policy = PolicyStatus.SATISFIED
                break
            if item.outcome is not AbuseControlOutcome.NO_CONTROL_SIGNAL:
                limitations.append(
                    "Sequence stopped on an indeterminate response or transport failure; "
                    "no remaining repeats sent."
                )
                break
        findings: tuple[AbuseControlFinding, ...] = ()
        if len(evidence) == limit and all(
            item.outcome is AbuseControlOutcome.NO_CONTROL_SIGNAL for item in evidence
        ):
            policy = PolicyStatus.VIOLATED
            assert plan.policy_id is not None
            findings = (
                AbuseControlFinding(
                    selected.operation,
                    selected.baseline_evidence_id,
                    tuple(item.evidence_id for item in evidence),
                    plan.policy_id,
                    limit,
                    len(evidence),
                    "The operator selected this exact operation as expected to trigger an "
                    "abuse-control signal within the bounded test. GQLSleuth replayed the "
                    f"identical request {limit} times sequentially and observed no explicit "
                    "rate-limit, lockout or challenge signal.",
                ),
            )
        self._result = replace(
            plan,
            confirmed=True,
            attempts=tuple(evidence),
            policy_result=policy,
            findings=findings,
            limitations=tuple(limitations),
        )
        return deepcopy(self._result)


def _request(
    scan: SafeExecutionScanResult | ActiveExecutionScanResult,
    plan: AbuseControlResult,
    settings: HttpClientSettings,
    attempt: int,
) -> AbuseControlEvidence:
    selected = plan.selected
    assert selected is not None and plan.policy_id is not None
    timestamp, started = datetime.now(UTC), perf_counter()
    response = None
    error_type = None
    try:
        # Fresh clients prevent response cookies from changing the next exact request context.
        with HttpClient(settings) as client:
            response = client.send(
                HttpRequest(
                    method="POST",
                    url=selected.endpoint,
                    json_body={"query": selected.query, "variables": deepcopy(selected.variables)},
                )
            )
    except HttpError as error:
        error_type = type(error).__name__
        classification = AbuseControlResponse(
            AbuseControlOutcome.NETWORK_FAILURE, QueryExecutionStatus.NETWORK_FAILURE
        )
    else:
        classification = classify_abuse_response(
            response.status_code,
            response.body,
            baseline_status=selected.baseline_status,
            baseline_http_status=selected.baseline_http_status,
        )
        if not same_origin(selected.endpoint, response.final_url):
            classification = AbuseControlResponse(
                AbuseControlOutcome.INDETERMINATE, classification.repeat_status
            )
    headers, body, withheld = capture_probe_response(
        response,
        request_context_material(settings),
        additional_headers=(
            "ratelimit",
            "ratelimit-policy",
            "ratelimit-limit",
            "ratelimit-remaining",
            "ratelimit-reset",
        ),
    )
    safe = scan.safe_execution if isinstance(scan, ActiveExecutionScanResult) else scan
    schema_scan = safe.query_generation.operation_analysis.schema_scan
    return AbuseControlEvidence(
        target=schema_scan.introspection.detection.discovery.target,
        endpoint=selected.endpoint,
        timestamp=timestamp,
        source="gqlsleuth.application.abuse_controls",
        summary=f"Abuse-control attempt {attempt}: {classification.outcome.value.upper()}.",
        operation=selected.operation,
        baseline_evidence_id=selected.baseline_evidence_id,
        baseline_status=selected.baseline_status,
        baseline_http_status=selected.baseline_http_status,
        policy_id=plan.policy_id,
        attempt_index=attempt,
        planned_attempts=selected.planned_attempts,
        repeat_status=classification.repeat_status,
        outcome=classification.outcome,
        signal=classification.signal,
        query=selected.query,
        variables=deepcopy(selected.variables),
        request_method="POST",
        response_status_code=response.status_code if response else None,
        response_headers=headers,
        response_body=body,
        response_material_withheld=withheld,
        duration_seconds=response.duration_seconds if response else perf_counter() - started,
        error_type=error_type,
        error_message="Target transport failed." if error_type else None,
    )
