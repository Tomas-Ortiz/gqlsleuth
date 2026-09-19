"""Fixed exact-request abuse-control plans, observations and scoped policy findings."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from gqlsleuth.domain.analysis import OperationAnalysis, OperationKind
from gqlsleuth.domain.authorization_policy import PolicyProvenance, PolicyStatus
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode

MAX_PHASE27_SELECTED_OPERATIONS = 1
MAX_PHASE27_QUERY_REQUESTS = 5
MAX_PHASE27_MUTATION_REQUESTS = 3
ABUSE_CONTROL_POLICY = (
    "Selecting and confirming declares that this exact operation is expected to expose an "
    "explicit rate-limit, lockout or challenge signal within the fixed bounded sequence."
)
ABUSE_CONTROL_LIMITATION = (
    "This does not establish that no rate limit exists at a higher threshold or over a "
    "different time window. Earlier scan requests may have contributed to server state. "
    "A signal's attempt index is not the application's rate-limit threshold."
)
MUTATION_REPLAY_WARNING = (
    "WARNING: This exact Mutation will be repeated up to 3 times and may cause repeated "
    "application side effects. GQLSleuth does not attempt rollback or deduplication."
)


class AbuseControlOutcome(StrEnum):
    CONTROL_SIGNAL_OBSERVED = "control_signal_observed"
    NO_CONTROL_SIGNAL = "no_control_signal"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


class AbuseControlKind(StrEnum):
    RATE_LIMIT = "rate_limit"
    LOCKOUT = "lockout"
    CHALLENGE = "challenge"


@dataclass(frozen=True)
class AbuseControlSignal:
    kind: AbuseControlKind
    source: Literal["http_status", "graphql_code", "graphql_message"]
    matched_rule: str


@dataclass(frozen=True)
class AbuseControlCandidate:
    index: int
    operation: OperationAnalysis
    query: str
    variables: dict[str, JsonValue]
    baseline_evidence_id: UUID
    baseline_source: EvidenceType
    baseline_status: QueryExecutionStatus
    baseline_http_status: int
    planned_attempts: int

    @property
    def endpoint(self) -> str:
        return self.operation.endpoint

    @property
    def mutation_warning(self) -> str | None:
        return MUTATION_REPLAY_WARNING if self.operation.kind is OperationKind.MUTATION else None


class AbuseControlEvidence(Evidence):
    evidence_type: Literal[EvidenceType.ABUSE_CONTROL_PROBE] = EvidenceType.ABUSE_CONTROL_PROBE
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    operation: OperationAnalysis
    baseline_evidence_id: UUID
    baseline_status: QueryExecutionStatus
    baseline_http_status: int
    policy_id: UUID
    attempt_index: int
    planned_attempts: int
    repeat_status: QueryExecutionStatus
    outcome: AbuseControlOutcome
    signal: AbuseControlSignal | None = None
    response_material_withheld: bool = False


@dataclass(frozen=True)
class AbuseControlFinding:
    operation: OperationAnalysis
    baseline_evidence_id: UUID
    attempt_evidence_ids: tuple[UUID, ...]
    policy_id: UUID
    planned_attempts: int
    actual_attempts: int
    reason: str
    finding_type: Literal["abuse_control_policy_violation"] = "abuse_control_policy_violation"
    provenance: PolicyProvenance = PolicyProvenance.OPERATOR_SUPPLIED
    policy_result: PolicyStatus = PolicyStatus.VIOLATED
    operator_policy: str = ABUSE_CONTROL_POLICY
    limitation: str = ABUSE_CONTROL_LIMITATION


@dataclass(frozen=True)
class AbuseControlResult:
    candidates: tuple[AbuseControlCandidate, ...] = ()
    selected: AbuseControlCandidate | None = None
    policy_id: UUID | None = None
    confirmed: bool = False
    attempts: tuple[AbuseControlEvidence, ...] = ()
    policy_result: PolicyStatus = PolicyStatus.UNRESOLVED
    findings: tuple[AbuseControlFinding, ...] = ()
    limitations: tuple[str, ...] = ()
    operator_policy: str = ABUSE_CONTROL_POLICY
    scope_limitation: str = ABUSE_CONTROL_LIMITATION
    attempted_request_count: int = field(init=False)
    first_signal_attempt: int | None = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attempted_request_count", len(self.attempts))
        object.__setattr__(
            self,
            "first_signal_attempt",
            next((item.attempt_index for item in self.attempts if item.signal is not None), None),
        )

    @property
    def evidence(self) -> tuple[AbuseControlEvidence, ...]:
        return self.attempts
