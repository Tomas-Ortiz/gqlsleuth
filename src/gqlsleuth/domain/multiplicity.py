"""Bounded behavior observations, separate from ordinary execution and findings."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import JsonValue

from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.query_generation import QueryGenerationResult

ALIAS_COUNT = 3
BATCH_SIZE = 2
MAX_PHASE17_REQUESTS = 2
MULTIPLICITY_NOTICE = (
    "Only the representative Query and fixed multiplicities (3 aliases / 2 batch entries) "
    "are assessed. Acceptance is behavior, not vulnerability confirmation, and does not "
    "establish higher thresholds, missing controls, or a denial-of-service condition."
)


class MultiplicityProbeType(StrEnum):
    ALIAS_MULTIPLICITY = "alias_multiplicity"
    HTTP_BATCHING = "http_batching"


class MultiplicityDecision(StrEnum):
    EXECUTABLE = "executable"
    INVALID_ARTIFACT = "invalid_artifact"
    NOT_SELECTED = "not_selected"
    DECLINED = "declined"
    MODE_DISABLED = "mode_disabled"
    SKIPPED_LIMIT = "skipped_limit"
    EXECUTED = "executed"


class MultiplicityObservation(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


@dataclass(frozen=True)
class MultiplicityProbePreview:
    probe_type: MultiplicityProbeType
    base: QueryGenerationResult
    query: str
    request_json: JsonValue


class MultiplicityEvidence(Evidence):
    evidence_type: Literal[EvidenceType.GRAPHQL_BEHAVIOR_PROBE] = (
        EvidenceType.GRAPHQL_BEHAVIOR_PROBE
    )
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    probe_type: MultiplicityProbeType
    representative_operation: str
    multiplicity: int
    request_json: JsonValue
    observation: MultiplicityObservation
    entry_statuses: tuple[QueryExecutionStatus, ...] = ()


@dataclass(frozen=True)
class MultiplicityProbeExecutionResult:
    candidate: MultiplicityProbePreview
    selected: bool
    decision: MultiplicityDecision
    reason: str
    evidence: MultiplicityEvidence | None = None


@dataclass(frozen=True)
class MultiplicityValidationResult:
    candidates: tuple[MultiplicityProbePreview, ...]
    selected_indices: tuple[int, ...]
    confirmed: bool
    executions: tuple[MultiplicityProbeExecutionResult, ...]
    limitations: tuple[str, ...]

    @property
    def evidence(self) -> tuple[MultiplicityEvidence, ...]:
        return tuple(item.evidence for item in self.executions if item.evidence is not None)
