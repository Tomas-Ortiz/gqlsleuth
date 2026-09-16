"""Independent bounded depth decisions and behavior evidence; never security findings."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.query_generation import QueryGenerationResult

MAX_PHASE18_REQUESTS = 1
MAX_LIST_EDGES = 1
MAX_CONSTRUCTED_SELECTION_DEPTH = 6
DEPTH_NOTICE = (
    "GQLSleuth selection depth counts nested field nodes, including the root and terminal leaf. "
    "Only this bounded Query shape is assessed. Acceptance is not vulnerability confirmation "
    "and does not establish unlimited depth or absence of complexity controls. "
    "Rejection does not establish a global policy."
)


class QueryDepthDecision(StrEnum):
    NOT_SELECTED = "not_selected"
    DECLINED = "declined"
    MODE_DISABLED = "mode_disabled"
    INVALID_ARTIFACT = "invalid_artifact"
    SKIPPED_LIMIT = "skipped_limit"
    EXECUTED = "executed"


class QueryDepthObservation(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


@dataclass(frozen=True)
class QueryDepthProbePreview:
    base: QueryGenerationResult
    query: str
    baseline_status: QueryExecutionStatus
    baseline_depth: int
    probe_depth: int
    recursive_path: tuple[str, ...]
    list_edges: int
    source_evidence_ids: tuple[UUID, ...]


class QueryDepthEvidence(Evidence):
    evidence_type: Literal[EvidenceType.GRAPHQL_BEHAVIOR_PROBE] = (
        EvidenceType.GRAPHQL_BEHAVIOR_PROBE
    )
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    probe_type: Literal["controlled_query_depth"] = "controlled_query_depth"
    representative_operation: str
    baseline_status: QueryExecutionStatus
    baseline_depth: int
    probe_depth: int
    recursive_path: tuple[str, ...]
    list_edges: int
    source_evidence_ids: tuple[UUID, ...]
    observation: QueryDepthObservation


@dataclass(frozen=True)
class QueryDepthExecutionResult:
    candidate: QueryDepthProbePreview
    selected: bool
    decision: QueryDepthDecision
    reason: str
    evidence: QueryDepthEvidence | None = None


@dataclass(frozen=True)
class QueryDepthValidationResult:
    candidates: tuple[QueryDepthProbePreview, ...]
    selected_indices: tuple[int, ...]
    confirmed: bool
    executions: tuple[QueryDepthExecutionResult, ...]
    limitations: tuple[str, ...]

    @property
    def evidence(self) -> tuple[QueryDepthEvidence, ...]:
        return tuple(item.evidence for item in self.executions if item.evidence is not None)
