"""SAFE nested-path observations; no ownership, value comparison or policy inference."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from gqlsleuth.domain.analysis import RuleMatch
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.query_generation import QueryGenerationResult

MAX_PHASE19_CANDIDATES = 3
MAX_NESTED_AUTH_SELECTION_DEPTH = 5
MAX_NESTED_AUTH_LIST_EDGES = 1
MAX_PHASE19_REQUESTS = 9
NESTED_NOTICE = (
    "The same Query and variables are compared structurally across tester-defined contexts. "
    "Differences are review candidates, not vulnerabilities. Validate against the application's "
    "intended access policy. No ownership, privilege order or business-value equality is inferred."
)


class NestedOutcome(StrEnum):
    RETURNED = "returned"
    EXPLICIT_DENIAL = "explicit_denial"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


class NestedDifference(StrEnum):
    NESTED_ACCESS_DIFFERENCE = "nested_access_difference"
    NESTED_FIELD_VISIBILITY_DIFFERENCE = "nested_field_visibility_difference"


@dataclass(frozen=True)
class NestedPathCandidate:
    base: QueryGenerationResult
    path: tuple[str, ...]
    terminal_type: str
    matched_rules: tuple[RuleMatch, ...]
    query: str | None
    selection_depth: int
    list_edges: int
    source_evidence_ids: tuple[UUID, ...]


class NestedAuthorizationEvidence(Evidence):
    evidence_type: Literal[EvidenceType.NESTED_AUTHORIZATION_PROBE] = (
        EvidenceType.NESTED_AUTHORIZATION_PROBE
    )
    execution_mode: Literal[ScanMode.SAFE] = ScanMode.SAFE
    context: str
    root_operation: str
    nested_path: tuple[str, ...]
    rule_ids: tuple[str, ...]
    categories: tuple[str, ...]
    outcome: NestedOutcome


@dataclass(frozen=True)
class NestedExecution:
    candidate_index: int
    context: str
    attempted: bool
    outcome: NestedOutcome | None
    reason: str
    evidence: NestedAuthorizationEvidence | None = None


@dataclass(frozen=True)
class NestedPairReview:
    candidate_index: int
    context_a: str
    context_b: str
    kind: NestedDifference
    state_a: str
    state_b: str
    source_evidence_ids: tuple[UUID, ...]
    reason: str


@dataclass(frozen=True)
class NestedAuthorizationResult:
    candidates: tuple[NestedPathCandidate, ...] = ()
    executions: tuple[NestedExecution, ...] = ()
    pairs: tuple[NestedPairReview, ...] = ()
    limitations: tuple[str, ...] = ()

    @property
    def evidence(self) -> tuple[NestedAuthorizationEvidence, ...]:
        return tuple(item.evidence for item in self.executions if item.evidence is not None)

    @property
    def request_count(self) -> int:
        return sum(item.attempted for item in self.executions)
