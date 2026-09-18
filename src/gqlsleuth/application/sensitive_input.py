"""One independently confirmed field/value DENY probe, without exploration or persistence reads."""

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from time import perf_counter

from graphql import GraphQLError

from gqlsleuth.application.mutation_preparation import retained_mutation
from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.authorization_policy import ExpectedPolicy, PolicyStatus
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    QueryGenerationError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.domain.sensitive_input import (
    MAX_PHASE24_REQUESTS,
    PreparedSensitiveInputProbe,
    SensitiveInputCase,
    SensitiveInputEvaluation,
    SensitiveInputEvidence,
    SensitiveInputOutcome,
    SensitiveInputTarget,
    SensitiveInputValidationResult,
    SensitiveInputViolation,
    parse_sensitive_case,
)
from gqlsleuth.graphql.query_generation import generate_mutation
from gqlsleuth.graphql.sensitive_input import build_sensitive_probe, classify_sensitive_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest


def prepare_sensitive_input(
    safe: SafeExecutionScanResult,
    *,
    case: SensitiveInputCase,
    enabled: bool = False,
    http_settings: HttpClientSettings | None = None,
) -> SensitiveInputValidationResult:
    result = SensitiveInputValidationResult(
        case, has_supplied_context_headers=bool(http_settings and http_settings.custom_headers)
    )
    scan = safe.query_generation.operation_analysis.schema_scan
    if enabled is not True or scan.introspection.detection.discovery.mode is not ScanMode.ACTIVE:
        return replace(
            result,
            limitations=(
                "Sensitive input validation requires explicit enablement and ACTIVE mode.",
            ),
        )
    if (
        not isinstance(case, SensitiveInputCase)
        or case.expected is not ExpectedPolicy.DENY
        or any(
            type(value) is not str
            for value in (case.operation, case.argument, case.field, case.value)
        )
        or (
            case.target is not None
            and (
                not isinstance(case.target, SensitiveInputTarget)
                or type(case.target.argument) is not str
                or type(case.target.identifier) is not str
            )
        )
    ):
        raise HttpConfigurationError("Sensitive input validation requires a validated DENY case.")
    target_text = f"{case.target.argument}={case.target.identifier}" if case.target else None
    if (
        parse_sensitive_case(
            [f"{case.operation}:{case.argument}.{case.field}={case.value}"], target_text
        )
        != case
    ):
        raise HttpConfigurationError("Sensitive input case identity is invalid.")
    try:
        schema, native, operation, references = retained_mutation(safe, case.operation)
        artifact = generate_mutation(schema, operation)
        query, variables, value, value_type = build_sensitive_probe(schema, native, artifact, case)
        return replace(
            result,
            probe=PreparedSensitiveInputProbe(
                case,
                operation.endpoint,
                query,
                variables,
                value,
                value_type,
                references,
                artifact.manual_adjustments,
            ),
        )
    except SafeExecutionValidationError as error:
        # All messages from the structural/value gate are project-owned and exclude supplied values.
        return replace(result, limitations=(str(error),))
    except (
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
                "Compatible retained Mutation/schema or deterministic input construction "
                "is unavailable.",
            ),
        )


class SensitiveInputSession:
    """Own a single scan's attempt budget; prepared/report models cannot reset it."""

    def __init__(
        self,
        safe: SafeExecutionScanResult,
        *,
        case: SensitiveInputCase,
        enabled: bool = False,
        http_settings: HttpClientSettings | None = None,
    ) -> None:
        self._safe, self._case, self._enabled = safe, case, enabled
        self._settings = http_settings or HttpClientSettings()
        self._attempts = 0
        self._preview = self._prepare()
        self._result = self._preview

    def _prepare(self) -> SensitiveInputValidationResult:
        return prepare_sensitive_input(
            self._safe, case=self._case, enabled=self._enabled, http_settings=self._settings
        )

    @property
    def preview(self) -> SensitiveInputValidationResult:
        return deepcopy(self._preview)

    def execute(
        self, *, preview: SensitiveInputValidationResult, confirmed: bool = False
    ) -> SensitiveInputValidationResult:
        if self._attempts >= MAX_PHASE24_REQUESTS:
            return deepcopy(self._result)
        fresh = self._prepare()
        reason = None
        if confirmed is not True:
            reason = "Separate sensitive input confirmation was not given."
        elif not _matches(preview, fresh) or not _matches(self._preview, fresh):
            reason = "Prepared sensitive input request does not match the rebuilt exact plan."
        elif fresh.probe is None:
            reason = "No eligible sensitive input request."
        if reason or fresh.probe is None:
            reason = reason or "No eligible sensitive input request."
            return replace(
                fresh,
                confirmed=confirmed is True,
                limitations=(*fresh.limitations, reason),
                evaluation=SensitiveInputEvaluation(PolicyStatus.UNRESOLVED, None, reason),
            )
        self._attempts += 1
        scan = self._safe.query_generation.operation_analysis.schema_scan
        evidence = _request(
            fresh.probe, self._settings, scan.introspection.detection.discovery.target
        )
        status = PolicyStatus.UNRESOLVED
        reason = "Observed outcome cannot resolve the operator-supplied DENY policy."
        if evidence.outcome is SensitiveInputOutcome.TARGET_VALUE_RETURNED:
            status = PolicyStatus.VIOLATED
            reason = (
                "The Mutation returned the operator-supplied value for "
                f"{fresh.case.argument}.{fresh.case.field} "
                "under the current request context, contradicting the explicit DENY policy. "
                "Persistence and broader business impact were not verified."
            )
        elif evidence.outcome is SensitiveInputOutcome.EXPLICIT_DENIAL:
            status = PolicyStatus.SATISFIED
            reason = (
                "An explicit denial for this exact field/value request is consistent with "
                "the operator-supplied DENY policy."
            )
        evaluation = SensitiveInputEvaluation(
            status, evidence.outcome, reason, (evidence.evidence_id,)
        )
        self._result = replace(
            fresh,
            confirmed=True,
            execution=evidence,
            attempted_request_count=self._attempts,
            evaluation=evaluation,
            violation=SensitiveInputViolation(evaluation)
            if status is PolicyStatus.VIOLATED
            else None,
        )
        return deepcopy(self._result)


def _matches(plan: SensitiveInputValidationResult, fresh: SensitiveInputValidationResult) -> bool:
    try:
        return (
            plan == fresh
            and type(plan.has_supplied_context_headers) is bool
            and exact_variables(
                (plan.probe.variables, plan.probe.typed_value) if plan.probe else ()
            )
            == exact_variables(
                (fresh.probe.variables, fresh.probe.typed_value) if fresh.probe else ()
            )
        )
    except (TypeError, ValueError, RecursionError):
        return False


def _request(
    probe: PreparedSensitiveInputProbe, settings: HttpClientSettings, target: Target
) -> SensitiveInputEvidence:
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
        outcome, identity, matches = SensitiveInputOutcome.NETWORK_FAILURE, None, None
    else:
        outcome, identity, matches = classify_sensitive_response(
            response.status_code, response.body, probe.case, probe.typed_value, probe.value_type
        )
    return SensitiveInputEvidence(
        target=target,
        endpoint=probe.endpoint,
        timestamp=timestamp,
        summary=(
            f"Sensitive input validation observed {outcome.value.upper()}; "
            "persistence was not verified."
        ),
        source="gqlsleuth.application.sensitive_input",
        root_operation=probe.case.operation,
        input_path=f"{probe.case.argument}.{probe.case.field}",
        supplied_value=probe.typed_value,
        target_argument=probe.case.target.argument if probe.case.target else None,
        target_identifier=probe.case.target.identifier if probe.case.target else None,
        query=probe.query,
        variables=deepcopy(probe.variables),
        request_method="POST",
        source_evidence_ids=probe.source_evidence_ids,
        outcome=outcome,
        target_id_matches=identity,
        value_matches=matches,
        response_status_code=response.status_code if response else None,
        response_headers=response.headers if response else None,
        response_body=response.body if response else None,
        duration_seconds=response.duration_seconds if response else perf_counter() - started,
        error_type=error_type,
        error_message="Target transport failed." if error_type else None,
    )
