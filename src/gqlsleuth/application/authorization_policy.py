"""Pure local validation of supplied policy against retained Phase 20 classifications."""

import json
from uuid import UUID

from gqlsleuth.domain.authorization_policy import (
    AuthorizationPolicyAssertion,
    AuthorizationPolicyEvaluation,
    AuthorizationPolicyResult,
    AuthorizationPolicyViolation,
    ExpectedPolicy,
    PolicyProvenance,
    PolicyStatus,
    parse_policy_assertions,
)
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.object_authorization import (
    MAX_PHASE20_REQUESTS,
    ObjectAuthorizationCase,
    ObjectAuthorizationEvidence,
    ObjectAuthorizationMode,
    ObjectAuthorizationResult,
    ObjectContext,
    ObjectExecution,
    ObjectOutcome,
    PreparedObjectProbe,
)


def _retained_execution(
    result: ObjectAuthorizationResult,
    case: ObjectAuthorizationCase,
    context: str,
    names: tuple[str, ...],
) -> tuple[ObjectExecution | None, str | None]:
    """Verify source identity only. Raw response bodies/values are deliberately never read."""
    probes = tuple(probe for probe in result.probes if probe.case.index == case.index)
    matches = tuple(
        item
        for item in result.executions
        if item.case_index == case.index and item.context.name == context
    )
    if len(probes) != 1 or len(matches) != 1:
        return None, "Referenced Phase 20 probe/outcome is unavailable or ambiguous."
    probe, execution = probes[0], matches[0]
    if (
        probe.case != case
        or type(probe.case.index) is not int
        or probe.case.mode is not case.mode
        or tuple(item.name for item in probe.contexts) != names
        or probe.response_id_path != (case.operation, "id")
        or execution.context not in probe.contexts
        or any(type(item.has_supplied_context_headers) is not bool for item in probe.contexts)
        or type(execution.attempted) is not bool
        or type(execution.case_index) is not int
        or (
            case.mode is ObjectAuthorizationMode.ANONYMOUS_ONLY
            and execution.context.has_supplied_context_headers
        )
    ):
        return None, "Retained Phase 20 case/context identity is inconsistent."
    evidence = execution.evidence
    if not execution.attempted:
        if (
            evidence is not None
            or execution.outcome is not None
            or execution.returned_id_matches is not None
        ):
            return None, "Unattempted Phase 20 outcome contains inconsistent execution facts."
        return execution, None
    if (
        not isinstance(evidence, ObjectAuthorizationEvidence)
        or type(execution.outcome) is not ObjectOutcome
        or evidence.evidence_type is not EvidenceType.OBJECT_AUTHORIZATION_PROBE
        or evidence.execution_mode is not ScanMode.SAFE
        or evidence.object_mode is not case.mode
        or evidence.context != context
        or evidence.has_supplied_context_headers
        is not execution.context.has_supplied_context_headers
        or evidence.declared_authorized_context != case.declared_authorized_context
        or evidence.root_operation != case.operation
        or evidence.identifier_argument != case.argument
        or evidence.identifier != case.identifier
        or evidence.endpoint != probe.endpoint
        or evidence.request_method != "POST"
        or evidence.query != probe.query
        or evidence.source_evidence_ids != probe.source_evidence_ids
        or evidence.outcome is not execution.outcome
        or evidence.returned_id_matches is not execution.returned_id_matches
        or (
            execution.outcome is ObjectOutcome.TARGET_RETURNED
            and execution.returned_id_matches is not True
        )
        or not isinstance(evidence.evidence_id, UUID)
        or sum(
            item.evidence is not None and item.evidence.evidence_id == evidence.evidence_id
            for item in result.executions
        )
        != 1
    ):
        return None, "Source Phase 20 execution evidence is missing or inconsistent."
    try:
        same_inputs = json.dumps(evidence.variables, sort_keys=True, allow_nan=False) == json.dumps(
            probe.variables, sort_keys=True, allow_nan=False
        )
    except (TypeError, ValueError, RecursionError):
        same_inputs = False
    if not same_inputs:
        return None, "Source Phase 20 request inputs do not match the retained probe."
    return execution, None


def evaluate_authorization_policy(
    result: ObjectAuthorizationResult | None,
    *,
    assertions: tuple[AuthorizationPolicyAssertion, ...],
    cases: tuple[ObjectAuthorizationCase, ...],
    context_names: tuple[str, ...] = (),
    enabled: bool = False,
    object_review_enabled: bool = False,
    mode: ScanMode = ScanMode.SAFE,
) -> AuthorizationPolicyResult:
    """No scanner/generator dependency: only source checks and the fixed DENY outcome matrix."""
    if enabled is not True or object_review_enabled is not True or mode is not ScanMode.SAFE:
        raise HttpConfigurationError(
            "Policy evaluation requires explicit Phase 20/21 enablement and SAFE mode."
        )
    if any(
        not isinstance(item, AuthorizationPolicyAssertion)
        or type(item.index) is not int
        or type(item.case_index) is not int
        or type(item.context) is not str
        or type(item.implicit_anonymous) is not bool
        or item.expected is not ExpectedPolicy.DENY
        or item.provenance is not PolicyProvenance.OPERATOR_SUPPLIED
        for item in assertions
    ):
        raise HttpConfigurationError(
            "Policy assertions must be typed operator-supplied DENY references."
        )
    canonical = parse_policy_assertions(
        [
            str(item.case_index) + (":" + item.context if context_names else "")
            for item in assertions
        ],
        cases=cases,
        context_names=context_names,
    )
    if assertions != canonical:
        raise HttpConfigurationError(
            "Policy assertion identity/order does not match normalized input."
        )
    names = context_names or ("anonymous",)
    global_error = None
    if result is None:
        global_error = "Retained Phase 20 results are unavailable; policy cannot be evaluated."
    elif any(
        not isinstance(item, ObjectExecution)
        or type(item.attempted) is not bool
        or type(item.case_index) is not int
        or not isinstance(item.context, ObjectContext)
        or (
            item.evidence is not None and not isinstance(item.evidence, ObjectAuthorizationEvidence)
        )
        for item in result.executions
    ) or any(
        not isinstance(probe, PreparedObjectProbe)
        or not isinstance(probe.case, ObjectAuthorizationCase)
        or any(not isinstance(context, ObjectContext) for context in probe.contexts)
        for probe in result.probes
    ):
        global_error = "Retained Phase 20 record types are inconsistent."
    elif (
        result.cases != cases
        or result.mode is not cases[0].mode
        or any(case.mode is not result.mode or type(case.index) is not int for case in result.cases)
        or type(result.attempted_request_count) is not int
        or not 0 <= result.attempted_request_count <= MAX_PHASE20_REQUESTS
        or result.attempted_request_count != sum(item.attempted for item in result.executions)
    ):
        global_error = "Retained Phase 20 case identity/mode or attempt accounting is inconsistent."
    evaluations = []
    limitations = []
    for assertion in assertions:
        case = cases[assertion.case_index - 1]
        execution = None
        problem = global_error
        if problem is None and result is not None:
            execution, problem = _retained_execution(result, case, assertion.context, names)
            if (
                execution
                and execution.attempted
                and case.mode is ObjectAuthorizationMode.DIFFERENTIAL
            ):
                owner, owner_problem = _retained_execution(
                    result, case, case.declared_authorized_context or "", names
                )
                if (
                    owner_problem
                    or owner is None
                    or not owner.attempted
                    or owner.outcome is not ObjectOutcome.TARGET_RETURNED
                ):
                    problem = (
                        "Referenced Phase 20 comparison lacks a valid declared-context "
                        "TARGET_RETURNED baseline."
                    )
        status = PolicyStatus.UNRESOLVED
        observed = None
        ids: tuple[UUID, ...] = ()
        if problem:
            reason = problem
            limitations.append(f"Assertion {assertion.index}: {problem}")
        elif execution is None:
            reason = "Retained Phase 20 observation is unavailable."
            limitations.append(f"Assertion {assertion.index}: {reason}")
        elif not execution.attempted:
            reason = (
                "The referenced Phase 20 context was not executed; "
                "no policy conclusion is possible."
            )
            if case.mode is ObjectAuthorizationMode.DIFFERENTIAL:
                reason += (
                    " The object-auth case did not reach an attempted cross-context validation."
                )
        else:
            observed = execution.outcome
            assert execution.evidence is not None
            ids = (execution.evidence.evidence_id,)
            if observed is ObjectOutcome.TARGET_RETURNED:
                status = PolicyStatus.VIOLATED
                reason = (
                    "The observed object-access behavior contradicts the "
                    "operator-supplied DENY policy assertion."
                )
            elif observed is ObjectOutcome.EXPLICIT_DENIAL:
                status = PolicyStatus.SATISFIED
                reason = (
                    "The explicit denial observed for this exact request is consistent "
                    "with the operator-supplied DENY policy."
                )
            else:
                reason = (
                    "The retained Phase 20 outcome does not resolve the operator-supplied "
                    "DENY policy; it is not evidence of explicit enforcement."
                )
        evaluations.append(
            AuthorizationPolicyEvaluation(assertion, case, observed, status, ids, reason)
        )
    return AuthorizationPolicyResult(
        assertions,
        tuple(evaluations),
        tuple(
            AuthorizationPolicyViolation(item)
            for item in evaluations
            if item.status is PolicyStatus.VIOLATED
        ),
        tuple(limitations),
    )
