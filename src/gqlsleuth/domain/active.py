"""Mutation artifacts, safety decisions, and evidence without terminal or HTTP dependencies."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from gqlsleuth.domain.analysis import OperationAnalysis
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.query_generation import OperationGenerationResult

MAX_MUTATION_EXECUTIONS = 5


@dataclass(frozen=True)
class MutationGenerationResult(OperationGenerationResult):
    """Generation outcome for one Mutation; generation never implies permission to execute."""


class MutationDecision(StrEnum):
    """Preparation and execution decisions, separate from HTTP response classification."""

    EXECUTABLE = "executable"
    BLOCKED_SAFETY = "blocked_safety"
    GENERATION_FAILED = "generation_failed"
    INVALID_ARTIFACT = "invalid_artifact"
    NOT_SELECTED = "not_selected"
    DECLINED = "declined"
    SKIPPED_LIMIT = "skipped_limit"
    MODE_DISABLED = "mode_disabled"
    EXECUTED = "executed"


@dataclass(frozen=True)
class MutationPreview:
    generated_mutation: MutationGenerationResult
    decision: MutationDecision
    reason: str

    @property
    def selectable(self) -> bool:
        return self.decision is MutationDecision.EXECUTABLE


class MutationExecutionEvidence(Evidence):
    """An actual attempted active request and its Phase 7 context, never a finding."""

    evidence_type: Literal[EvidenceType.MUTATION_EXECUTION] = EvidenceType.MUTATION_EXECUTION
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    execution_status: QueryExecutionStatus
    operation: OperationAnalysis
