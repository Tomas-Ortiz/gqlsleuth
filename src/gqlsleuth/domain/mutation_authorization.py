"""Exact, operator-supplied DENY cases and independently confirmed Mutation observations."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from gqlsleuth.domain.authorization_policy import ExpectedPolicy, PolicyStatus
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.object_authorization import parse_object_cases

MAX_PHASE23_CASES = 1
MAX_PHASE23_REQUESTS = 1
MUTATION_AUTHORIZATION_NOTICE = (
    "Validation compares an operator-supplied DENY policy with this exact Mutation request. "
    "A matching returned object does not prove every intended side effect occurred. "
    "Review the resulting server-side state manually. No vulnerability classification or "
    "general authorization conclusion is made."
)


class MutationAuthorizationOutcome(StrEnum):
    TARGET_MUTATION_RETURNED = "target_mutation_returned"
    EXPLICIT_DENIAL = "explicit_denial"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


@dataclass(frozen=True)
class MutationAuthorizationCase:
    operation: str
    argument: str
    identifier: str
    index: int = 1
    expected: ExpectedPolicy = ExpectedPolicy.DENY


def parse_mutation_cases(entries: list[str]) -> tuple[MutationAuthorizationCase, ...]:
    """Reuse exact textual object-ID validation, with one entry and no context prefix."""
    if len(entries) != MAX_PHASE23_CASES or any(type(item) is not str for item in entries):
        raise HttpConfigurationError(
            "Mutation authorization requires exactly one --mutation-auth-case."
        )
    try:
        case = parse_object_cases(entries)[0]
    except HttpConfigurationError:
        raise HttpConfigurationError(
            "Invalid mutation-auth-case; use OPERATION:ARGUMENT=ID with a non-empty, "
            "control-free identifier of at most 256 UTF-8 bytes."
        ) from None
    return (MutationAuthorizationCase(case.operation, case.argument, case.identifier),)


@dataclass(frozen=True)
class PreparedMutationAuthorizationProbe:
    case: MutationAuthorizationCase
    endpoint: str
    query: str
    variables: dict[str, JsonValue]
    response_id_path: tuple[str, str]
    source_evidence_ids: tuple[UUID, ...]
    manual_adjustments: tuple[str, ...] = ()


class MutationAuthorizationEvidence(Evidence):
    evidence_type: Literal[EvidenceType.MUTATION_AUTHORIZATION_PROBE] = (
        EvidenceType.MUTATION_AUTHORIZATION_PROBE
    )
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    root_operation: str
    identifier_argument: str
    identifier: str
    expected: Literal[ExpectedPolicy.DENY] = ExpectedPolicy.DENY
    outcome: MutationAuthorizationOutcome
    returned_id_matches: bool | None
    source_evidence_ids: tuple[UUID, ...]


@dataclass(frozen=True)
class MutationAuthorizationExecution:
    outcome: MutationAuthorizationOutcome
    returned_id_matches: bool | None
    evidence: MutationAuthorizationEvidence
    attempted: Literal[True] = True


@dataclass(frozen=True)
class MutationAuthorizationEvaluation:
    status: PolicyStatus
    observed: MutationAuthorizationOutcome | None
    reason: str
    source_evidence_ids: tuple[UUID, ...] = ()
    expected: ExpectedPolicy = ExpectedPolicy.DENY


@dataclass(frozen=True)
class MutationAuthorizationViolation:
    evaluation: MutationAuthorizationEvaluation
    result_type: Literal["mutation_authorization_policy_violation"] = (
        "mutation_authorization_policy_violation"
    )


@dataclass(frozen=True)
class MutationAuthorizationResult:
    cases: tuple[MutationAuthorizationCase, ...]
    probe: PreparedMutationAuthorizationProbe | None = None
    has_supplied_context_headers: bool = False
    confirmed: bool = False
    execution: MutationAuthorizationExecution | None = None
    evaluation: MutationAuthorizationEvaluation | None = None
    violation: MutationAuthorizationViolation | None = None
    limitations: tuple[str, ...] = ()
    attempted_request_count: int = 0

    @property
    def evidence(self) -> tuple[MutationAuthorizationEvidence, ...]:
        return (self.execution.evidence,) if self.execution else ()
