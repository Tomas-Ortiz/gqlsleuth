"""One independently consented Mutation attempt; rebuild the exact preview before sending."""

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from time import perf_counter

from graphql import GraphQLError

from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.discovery.endpoint_candidates import normalize_discovery_url
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.authorization_policy import ExpectedPolicy, PolicyStatus
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    QueryGenerationError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.models import EvidenceType, ScanMode, Target
from gqlsleuth.domain.mutation_authorization import (
    MAX_PHASE23_REQUESTS,
    MutationAuthorizationCase,
    MutationAuthorizationEvaluation,
    MutationAuthorizationEvidence,
    MutationAuthorizationExecution,
    MutationAuthorizationOutcome,
    MutationAuthorizationResult,
    MutationAuthorizationViolation,
    PreparedMutationAuthorizationProbe,
    parse_mutation_cases,
)
from gqlsleuth.domain.object_authorization import ObjectOutcome
from gqlsleuth.graphql.active_execution import destructive_tokens
from gqlsleuth.graphql.mutation_authorization import build_mutation_probe
from gqlsleuth.graphql.object_authorization import classify_object_response
from gqlsleuth.graphql.query_generation import generate_mutation
from gqlsleuth.graphql.schema_parser import load_introspection_schema, parse_introspection_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest


def prepare_mutation_authorization(
    safe: SafeExecutionScanResult,
    *,
    cases: tuple[MutationAuthorizationCase, ...],
    enabled: bool = False,
    http_settings: HttpClientSettings | None = None,
) -> MutationAuthorizationResult:
    """Generate locally from retained Mutation analysis/schema, never from discovered IDs."""
    result = MutationAuthorizationResult(
        cases, has_supplied_context_headers=bool(http_settings and http_settings.custom_headers)
    )
    scan = safe.query_generation.operation_analysis.schema_scan
    discovery = scan.introspection.detection.discovery
    if enabled is not True or discovery.mode is not ScanMode.ACTIVE:
        return replace(
            result,
            limitations=("Mutation authorization requires explicit enablement and ACTIVE mode.",),
        )
    if any(
        not isinstance(case, MutationAuthorizationCase)
        or type(case.index) is not int
        or case.expected is not ExpectedPolicy.DENY
        or any(type(value) is not str for value in (case.operation, case.argument, case.identifier))
        for case in cases
    ):
        raise HttpConfigurationError("Mutation authorization requires a validated DENY case.")
    if parse_mutation_cases([f"{c.operation}:{c.argument}={c.identifier}" for c in cases]) != cases:
        raise HttpConfigurationError("Mutation authorization case identity/order is invalid.")
    case = cases[0]
    if destructive_tokens(case.operation):
        return replace(
            result,
            limitations=(
                "Explicitly destructive Mutation names are unsupported for "
                "Mutation authorization validation.",
            ),
        )
    try:
        operations = tuple(
            operation
            for endpoint in safe.query_generation.operation_analysis.endpoints
            if endpoint.success
            for operation in endpoint.operations
            if operation.kind is OperationKind.MUTATION and operation.name == case.operation
        )
        exact = tuple(
            op
            for op in operations
            if op.endpoint == normalize_discovery_url(discovery.target.original_url)
        )
        operations = exact or operations
        if len(operations) != 1:
            raise SafeExecutionValidationError(
                "Requires one unambiguous Mutation operation/endpoint."
            )
        operation = operations[0]
        schemas = tuple(
            item.schema
            for item in scan.schemas
            if item.endpoint == operation.endpoint and item.success and item.schema is not None
        )
        responses = tuple(
            item.full_response
            for item in scan.introspection.introspections
            if item.endpoint == operation.endpoint and item.full_response is not None
        )
        if (
            len(schemas) != 1
            or len(responses) != 1
            or parse_introspection_response(responses[0].body) != schemas[0]
        ):
            raise SafeExecutionValidationError("Retained schema is unavailable or inconsistent.")
        native = load_introspection_schema(responses[0].body)
        artifact = generate_mutation(schemas[0], operation)
        query, variables = build_mutation_probe(schemas[0], native, artifact, case)
        references = tuple(
            item.evidence_id
            for item in safe.evidence
            if item.endpoint == operation.endpoint
            and item.evidence_type is EvidenceType.SCHEMA_ARTIFACT
        )
        probe = PreparedMutationAuthorizationProbe(
            case,
            operation.endpoint,
            query,
            variables,
            (case.operation, "id"),
            references,
            artifact.manual_adjustments,
        )
        return replace(result, probe=probe)
    except (
        SafeExecutionValidationError,
        SchemaParsingError,
        QueryGenerationError,
        GraphQLError,
        ValueError,
        TypeError,
        RecursionError,
    ):
        return replace(
            result,
            limitations=(
                "Compatible Mutation, direct ID argument, concrete output/direct id or valid "
                "unambiguous retained schema/artifact is unavailable.",
            ),
        )


class MutationAuthorizationSession:
    """Application-owned one-attempt budget for a scan, separate from immutable report data.

    Repeated execute calls return the completed result, including after a transport failure.
    A caller's preview is never used as the request source. Settings stay outside report models.
    """

    def __init__(
        self,
        safe: SafeExecutionScanResult,
        *,
        cases: tuple[MutationAuthorizationCase, ...],
        enabled: bool = False,
        http_settings: HttpClientSettings | None = None,
    ) -> None:
        self._safe = safe
        self._cases = cases
        self._enabled = enabled
        self._settings = http_settings or HttpClientSettings()
        self._attempts = 0
        self._preview = self._prepare()
        self._result = self._preview

    def _prepare(self) -> MutationAuthorizationResult:
        return prepare_mutation_authorization(
            self._safe, cases=self._cases, enabled=self._enabled, http_settings=self._settings
        )

    @property
    def preview(self) -> MutationAuthorizationResult:
        return deepcopy(self._preview)

    def execute(
        self,
        *,
        preview: MutationAuthorizationResult,
        confirmed: bool = False,
    ) -> MutationAuthorizationResult:
        if self._attempts >= MAX_PHASE23_REQUESTS:
            return deepcopy(self._result)
        fresh = self._prepare()
        reason = None
        if confirmed is not True:
            reason = "Separate Mutation authorization confirmation was not given."
        elif not _matches(preview, fresh) or not _matches(self._preview, fresh):
            reason = "Prepared Mutation authorization does not match the rebuilt exact request."
        elif fresh.probe is None:
            reason = "No eligible Mutation authorization request."
        if reason or fresh.probe is None:
            reason = reason or "No eligible Mutation authorization request."
            return replace(
                fresh,
                confirmed=confirmed is True,
                limitations=(*fresh.limitations, reason),
                evaluation=MutationAuthorizationEvaluation(PolicyStatus.UNRESOLVED, None, reason),
            )
        # Reserve before transport. Any normalized failure consumes the only attempt.
        self._attempts += 1
        scan = self._safe.query_generation.operation_analysis.schema_scan
        target = scan.introspection.detection.discovery.target
        evidence = _request(fresh.probe, self._settings, target)
        evaluation = _evaluate(evidence)
        self._result = replace(
            fresh,
            confirmed=True,
            attempted_request_count=self._attempts,
            execution=MutationAuthorizationExecution(
                evidence.outcome, evidence.returned_id_matches, evidence
            ),
            evaluation=evaluation,
            violation=MutationAuthorizationViolation(evaluation)
            if evaluation.status is PolicyStatus.VIOLATED
            else None,
        )
        return deepcopy(self._result)


def _matches(plan: MutationAuthorizationResult, fresh: MutationAuthorizationResult) -> bool:
    try:
        return (
            plan == fresh
            and type(plan.has_supplied_context_headers) is bool
            and exact_variables(plan.probe.variables if plan.probe else {})
            == exact_variables(fresh.probe.variables if fresh.probe else {})
        )
    except (TypeError, ValueError, RecursionError):
        return False


def _evaluate(evidence: MutationAuthorizationEvidence) -> MutationAuthorizationEvaluation:
    status = PolicyStatus.UNRESOLVED
    reason = "Observed outcome cannot resolve the operator-supplied DENY policy."
    if evidence.outcome is MutationAuthorizationOutcome.TARGET_MUTATION_RETURNED:
        status = PolicyStatus.VIOLATED
        reason = (
            "The selected Mutation returned the exact target object under the current request "
            "context, contradicting the operator-supplied DENY policy. Review the resulting "
            "server-side state manually."
        )
    elif evidence.outcome is MutationAuthorizationOutcome.EXPLICIT_DENIAL:
        status = PolicyStatus.SATISFIED
        reason = (
            "An explicit access denial for this exact Mutation request is consistent with "
            "the operator-supplied DENY policy."
        )
    return MutationAuthorizationEvaluation(
        status, evidence.outcome, reason, (evidence.evidence_id,)
    )


def _request(
    probe: PreparedMutationAuthorizationProbe,
    settings: HttpClientSettings,
    target: Target,
) -> MutationAuthorizationEvidence:
    timestamp, started = datetime.now(UTC), perf_counter()
    response = None
    error_type = None
    try:
        with HttpClient(settings) as client:
            response = client.send(
                HttpRequest(
                    method="POST",
                    url=probe.endpoint,
                    json_body={"query": probe.query, "variables": deepcopy(probe.variables)},
                )
            )
    except HttpError as error:
        error_type = type(error).__name__
        outcome, matches, reason = (
            MutationAuthorizationOutcome.NETWORK_FAILURE,
            None,
            "Target transport failed.",
        )
    else:
        observed, matches, reason = classify_object_response(
            response.status_code, response.body, probe.case.operation, probe.case.identifier
        )
        outcome = (
            MutationAuthorizationOutcome.TARGET_MUTATION_RETURNED
            if observed is ObjectOutcome.TARGET_RETURNED
            else MutationAuthorizationOutcome(observed.value)
        )
        if observed is ObjectOutcome.TARGET_RETURNED:
            reason = (
                "The Mutation returned the exact target object; "
                "side effects require manual verification."
            )
    return MutationAuthorizationEvidence(
        target=target,
        endpoint=probe.endpoint,
        timestamp=timestamp,
        summary=reason,
        source="gqlsleuth.application.mutation_authorization",
        root_operation=probe.case.operation,
        identifier_argument=probe.case.argument,
        identifier=probe.case.identifier,
        query=probe.query,
        variables=deepcopy(probe.variables),
        source_evidence_ids=probe.source_evidence_ids,
        request_method="POST",
        outcome=outcome,
        returned_id_matches=matches,
        response_status_code=response.status_code if response else None,
        response_headers=response.headers if response else None,
        response_body=response.body if response else None,
        duration_seconds=response.duration_seconds if response else perf_counter() - started,
        error_type=error_type,
        error_message="Target transport failed." if error_type else None,
    )
