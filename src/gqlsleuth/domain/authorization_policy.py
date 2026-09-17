"""Operator-supplied DENY assertions and local policy results, separate from HTTP evidence."""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.object_authorization import (
    ObjectAuthorizationCase,
    ObjectAuthorizationMode,
    ObjectOutcome,
    parse_object_cases,
)

MAX_PHASE21_ASSERTIONS = 9
POLICY_NOTICE = (
    "Validation compares operator-supplied DENY policy with retained Phase 20 outcomes. "
    "The operator's intended-policy assertion is not independently verified. Results apply "
    "only to the exact tested object, context and request; no vulnerability classification "
    "or global enforcement conclusion is made. This local stage adds zero target requests."
)


class ExpectedPolicy(StrEnum):
    DENY = "deny"


class PolicyProvenance(StrEnum):
    OPERATOR_SUPPLIED = "operator_supplied"


class PolicyStatus(StrEnum):
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class AuthorizationPolicyAssertion:
    index: int
    case_index: int
    context: str
    implicit_anonymous: bool
    expected: ExpectedPolicy = ExpectedPolicy.DENY
    provenance: PolicyProvenance = PolicyProvenance.OPERATOR_SUPPLIED


@dataclass(frozen=True)
class AuthorizationPolicyEvaluation:
    assertion: AuthorizationPolicyAssertion
    case: ObjectAuthorizationCase
    observed: ObjectOutcome | None
    status: PolicyStatus
    source_evidence_ids: tuple[UUID, ...]
    reason: str


@dataclass(frozen=True)
class AuthorizationPolicyViolation:
    """Composition retains the exact policy/case/source reference without network evidence."""

    evaluation: AuthorizationPolicyEvaluation
    result_type: Literal["authorization_policy_violation"] = "authorization_policy_violation"


@dataclass(frozen=True)
class AuthorizationPolicyResult:
    assertions: tuple[AuthorizationPolicyAssertion, ...]
    evaluations: tuple[AuthorizationPolicyEvaluation, ...]
    violations: tuple[AuthorizationPolicyViolation, ...] = ()
    limitations: tuple[str, ...] = ()


def validate_policy_cases(
    cases: tuple[ObjectAuthorizationCase, ...], context_names: tuple[str, ...]
) -> None:
    """Reuse Phase 20 normalization; policy never defines a second case ordering."""
    if any(
        not isinstance(case, ObjectAuthorizationCase)
        or type(case.index) is not int
        or type(case.mode) is not ObjectAuthorizationMode
        or any(type(value) is not str for value in (case.operation, case.argument, case.identifier))
        or (
            case.declared_authorized_context is not None
            and type(case.declared_authorized_context) is not str
        )
        for case in cases
    ):
        raise HttpConfigurationError("Policy requires normalized Phase 20 cases.")
    entries = [
        (case.declared_authorized_context + ":" if case.declared_authorized_context else "")
        + f"{case.operation}:{case.argument}={case.identifier}"
        for case in cases
    ]
    if parse_object_cases(entries, context_names) != cases:
        raise HttpConfigurationError("Policy requires normalized Phase 20 case identity/order.")


def parse_policy_assertions(
    entries: list[str],
    *,
    cases: tuple[ObjectAuthorizationCase, ...],
    context_names: tuple[str, ...] = (),
) -> tuple[AuthorizationPolicyAssertion, ...]:
    """Resolve references before scanning; reject duplicates and never echo raw policy input."""
    validate_policy_cases(cases, context_names)
    if not 1 <= len(entries) <= MAX_PHASE21_ASSERTIONS:
        raise HttpConfigurationError("--auth-policy-review requires 1–9 --expect-deny assertions.")
    assertions = []
    seen = set()
    for index, entry in enumerate(entries, 1):
        parts = entry.split(":")
        number = parts[0].lstrip("0")
        if (
            re.fullmatch(r"[0-9]+", parts[0]) is None
            or not number
            or len(number) > len(str(len(cases)))
            or int(number) > len(cases)
            or len(parts) not in {1, 2}
            or (not context_names and len(parts) != 1)
            or (len(context_names) > 1 and len(parts) != 2)
            or (len(parts) == 2 and parts[1] not in context_names)
        ):
            raise HttpConfigurationError(
                f"expect-deny #{index}: invalid Phase 20 case index or context reference."
            )
        case_index = int(number)
        context = (
            parts[1] if len(parts) == 2 else context_names[0] if context_names else "anonymous"
        )
        if context == cases[case_index - 1].declared_authorized_context:
            raise HttpConfigurationError(
                "DENY assertion targets the operator-declared authorized context "
                f"for object-auth case #{case_index}."
            )
        if (case_index, context) in seen:
            raise HttpConfigurationError(f"expect-deny #{index}: duplicate DENY assertion.")
        seen.add((case_index, context))
        assertions.append(
            AuthorizationPolicyAssertion(index, case_index, context, not context_names)
        )
    return tuple(assertions)
