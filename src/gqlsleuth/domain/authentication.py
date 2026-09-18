"""Safe token metadata, exact retained baselines and scoped authentication results."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from gqlsleuth.domain.authorization_policy import PolicyProvenance, PolicyStatus
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.nested_authorization import NestedOutcome

MAX_PHASE26_REQUESTS = 3
MAX_PHASE26_SELECTED_QUERIES = 1
JWT_CLOCK_SKEW_SECONDS = 60
AUTHENTICATION_NOTICE = (
    "Selecting a Query declares that this exact Query requires the supplied Bearer authentication. "
    "Results apply only to this Query and request context, not the entire application. "
    "Other supplied headers remain present. JWT inspection is unverified; missing claims "
    "and common algorithm names alone are not vulnerabilities."
)


class AuthenticationProbe(StrEnum):
    AUTHORIZATION_REMOVED = "authorization_removed"
    JWT_SIGNATURE_TAMPERED = "jwt_signature_tampered"
    JWT_ALG_NONE = "jwt_alg_none"


class AuthenticationFindingKind(StrEnum):
    AUTHENTICATION_ENFORCEMENT_FAILURE = "authentication_enforcement_failure"
    JWT_SIGNATURE_VALIDATION_FAILURE = "jwt_signature_validation_failure"
    JWT_NONE_ALGORITHM_ACCEPTED = "jwt_none_algorithm_accepted"
    EXPIRED_JWT_ACCEPTED = "expired_jwt_accepted"
    NOT_YET_VALID_JWT_ACCEPTED = "not_yet_valid_jwt_accepted"


@dataclass(frozen=True)
class TokenSecurityReview:
    token_type: Literal["jwt", "opaque"]
    algorithm: str | None = None
    header_presence: tuple[tuple[str, bool], ...] = ()
    claim_presence: tuple[tuple[str, bool], ...] = ()
    temporal_states: tuple[tuple[str, str], ...] = ()
    observations: tuple[str, ...] = ()
    unsigned: bool = False


@dataclass(frozen=True)
class AuthenticationQueryCandidate:
    index: int
    endpoint: str
    operation: str
    query: str
    variables: dict[str, JsonValue]
    baseline_evidence_id: UUID
    baseline_started_at: datetime
    baseline_completed_at: datetime


class AuthenticationProbeEvidence(Evidence):
    evidence_type: Literal[EvidenceType.AUTHENTICATION_SECURITY_PROBE] = (
        EvidenceType.AUTHENTICATION_SECURITY_PROBE
    )
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    operation: str
    baseline_evidence_id: UUID
    probe_type: AuthenticationProbe
    token_review: TokenSecurityReview
    outcome: NestedOutcome
    policy_result: PolicyStatus
    response_material_withheld: bool = False


@dataclass(frozen=True)
class AuthenticationProbeExecution:
    probe_type: AuthenticationProbe
    reason: str
    evidence: AuthenticationProbeEvidence | None = None


@dataclass(frozen=True)
class AuthenticationSecurityFinding:
    finding_type: AuthenticationFindingKind
    endpoint: str
    operation: str
    baseline_evidence_id: UUID
    probe_evidence_id: UUID
    control_evidence_id: UUID
    condition: str
    reason: str
    provenance: PolicyProvenance = PolicyProvenance.OPERATOR_SUPPLIED
    limitation: str = AUTHENTICATION_NOTICE


@dataclass(frozen=True)
class AuthenticationSecurityResult:
    token_review: TokenSecurityReview
    candidates: tuple[AuthenticationQueryCandidate, ...] = ()
    available_probes: tuple[AuthenticationProbe, ...] = ()
    selected_query: AuthenticationQueryCandidate | None = None
    selected_probes: tuple[AuthenticationProbe, ...] = ()
    confirmed: bool = False
    executions: tuple[AuthenticationProbeExecution, ...] = ()
    findings: tuple[AuthenticationSecurityFinding, ...] = ()
    limitations: tuple[str, ...] = ()
    attempted_request_count: int = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attempted_request_count", len(self.evidence))

    @property
    def evidence(self) -> tuple[AuthenticationProbeEvidence, ...]:
        return tuple(item.evidence for item in self.executions if item.evidence is not None)
