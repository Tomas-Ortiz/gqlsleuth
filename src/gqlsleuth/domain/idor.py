"""Operator-policy IDOR/BOLA results; no inferred ownership or severity."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from gqlsleuth.domain.authorization_policy import PolicyProvenance
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.object_authorization import ObjectOutcome
from gqlsleuth.domain.sequential_discovery import SequentialDiscoveryProbe, SequentialDiscoverySeed

IDOR_NOTICE = (
    "Findings depend on the operator-supplied DENY expectation. Confirm that the tested "
    "object should not be accessible to this context. Intentionally public or legitimately "
    "shared objects invalidate that expectation. Object ownership, tenant membership and "
    "business policy are not inferred. Returned objects may contain application data."
)


class IdorContextType(StrEnum):
    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"


class IdorPolicyResult(StrEnum):
    BASELINE_CONFIRMED = "baseline_confirmed"
    BASELINE_UNUSABLE = "baseline_unusable"
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    UNRESOLVED = "unresolved"


class IdorProbeEvidence(Evidence):
    evidence_type: Literal[EvidenceType.IDOR_BOLA_PROBE] = EvidenceType.IDOR_BOLA_PROBE
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    context_type: IdorContextType
    context_label: str | None
    root_operation: str
    identifier_argument: str
    operator_seed: str
    requested_identifier: str
    offset: Literal[-1, 0, 1]
    role: Literal["seed", "baseline", "alternate"]
    expected: Literal["allow", "deny"]
    policy_result: IdorPolicyResult
    provenance: PolicyProvenance = PolicyProvenance.OPERATOR_SUPPLIED
    source_evidence_ids: tuple[UUID, ...]
    outcome: ObjectOutcome
    returned_id_matches: bool | None


@dataclass(frozen=True)
class IdorExecution:
    probe: SequentialDiscoveryProbe
    role: Literal["seed", "baseline", "alternate"]
    expected: Literal["allow", "deny"]
    policy_result: IdorPolicyResult
    reason: str
    evidence: IdorProbeEvidence | None = None

    @property
    def attempted(self) -> bool:
        return self.evidence is not None


@dataclass(frozen=True)
class IdorFinding:
    endpoint: str
    operation: str
    identifier_argument: str
    identifier: str
    context_type: IdorContextType
    context_label: str | None
    reason: str
    evidence_id: UUID
    baseline_evidence_id: UUID | None
    source_evidence_ids: tuple[UUID, ...]
    finding_type: Literal["object_level_authorization_failure"] = (
        "object_level_authorization_failure"
    )
    classification: Literal["IDOR / BOLA"] = "IDOR / BOLA"
    expected: Literal["deny"] = "deny"
    observed: Literal[ObjectOutcome.TARGET_RETURNED] = ObjectOutcome.TARGET_RETURNED
    policy_result: Literal[IdorPolicyResult.VIOLATED] = IdorPolicyResult.VIOLATED
    provenance: PolicyProvenance = PolicyProvenance.OPERATOR_SUPPLIED
    limitation: str = IDOR_NOTICE


@dataclass(frozen=True)
class IdorDetectionResult:
    seeds: tuple[SequentialDiscoverySeed, ...]
    context_type: IdorContextType
    context_label: str | None = None
    probes: tuple[SequentialDiscoveryProbe, ...] = ()
    confirmed: bool = False
    executions: tuple[IdorExecution, ...] = ()
    findings: tuple[IdorFinding, ...] = ()
    limitations: tuple[str, ...] = ()
    attempted_request_count: int = 0

    @property
    def evidence(self) -> tuple[IdorProbeEvidence, ...]:
        return tuple(item.evidence for item in self.executions if item.evidence is not None)


def expected_policy(
    context: IdorContextType, probe: SequentialDiscoveryProbe
) -> tuple[Literal["seed", "baseline", "alternate"], Literal["allow", "deny"]]:
    if probe.offset != 0:
        return "alternate", "deny"
    return ("baseline", "allow") if context is IdorContextType.AUTHENTICATED else ("seed", "deny")


def evaluate_idor_policy(expected: str, outcome: ObjectOutcome | None) -> IdorPolicyResult:
    if expected == "allow":
        return (
            IdorPolicyResult.BASELINE_CONFIRMED
            if outcome is ObjectOutcome.TARGET_RETURNED
            else IdorPolicyResult.BASELINE_UNUSABLE
        )
    if outcome is ObjectOutcome.TARGET_RETURNED:
        return IdorPolicyResult.VIOLATED
    if outcome is ObjectOutcome.EXPLICIT_DENIAL:
        return IdorPolicyResult.SATISFIED
    return IdorPolicyResult.UNRESOLVED
