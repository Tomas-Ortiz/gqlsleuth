"""Allowlisted AI input and bounded interpretation models, separate from Evidence."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from gqlsleuth.domain.active import MutationDecision
from gqlsleuth.domain.analysis import InterestPriority, OperationCategory, OperationKind
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import ScanMode

MAX_AI_OPERATIONS = 20
MAX_CONTEXT_BYTES = 12_000
DEFAULT_AI_MODEL = "qwen3:8b"
AI_NOTICE = "Model-generated interpretation — not evidence or vulnerability confirmation."


class AIAnalysisStatus(StrEnum):
    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    HTTP_ERROR = "http_error"
    INVALID_RESPONSE = "invalid_response"


class AIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AIOperation(AIModel):
    """Only structural identifiers, deterministic rankings, and normalized states."""

    operation: str
    kind: OperationKind
    name: str
    return_type: str | None
    priority: InterestPriority
    interest_score: int
    categories: tuple[OperationCategory, ...]
    generated: bool
    manual_adjustment_required: bool
    execution_status: QueryExecutionStatus | None
    http_status: int | None
    attempted: bool
    mutation_safety: MutationDecision | None
    selectable: bool
    selected: bool
    mutation_decision: MutationDecision | None


class AISchemaSummary(AIModel):
    endpoint: str
    query_root: str | None
    mutation_root: str | None
    total_types: int
    queries: int
    mutations: int
    subscriptions: int


class AIContextMetadata(AIModel):
    operations_total: int
    operations_included: int
    operations_omitted: int
    schemas_total: int
    schemas_included: int
    context_truncated: bool


class AIContext(AIModel):
    mode: ScanMode
    final_batch_confirmed: bool | None
    metadata: AIContextMetadata
    operations: tuple[AIOperation, ...]
    schemas: tuple[AISchemaSummary, ...]
    counts: dict[str, int]


AIText = Annotated[str, Field(strict=True, min_length=1, max_length=600)]
OperationReference = Annotated[str, Field(strict=True, min_length=1, max_length=180)]


class AIStatement(AIModel):
    """References live in explicit fields, including summary/suggestions/limitations."""

    text: AIText
    operations: tuple[OperationReference, ...] = Field(max_length=MAX_AI_OPERATIONS)


class AIOperationExplanation(AIModel):
    operation: OperationReference
    explanation: AIText


class AIInterpretation(AIModel):
    scan_summary: AIStatement
    review_focus: tuple[AIOperationExplanation, ...] = Field(max_length=5)
    operation_explanations: tuple[AIOperationExplanation, ...] = Field(max_length=10)
    manual_review_suggestions: tuple[AIStatement, ...] = Field(max_length=10)
    limitations: tuple[AIStatement, ...] = Field(max_length=10)


@dataclass(frozen=True)
class AIInterpretationResult:
    status: AIAnalysisStatus
    model: str
    generated_at: datetime
    duration_seconds: float
    context_metadata: AIContextMetadata
    interpretation: AIInterpretation | None = None
    error_code: str | None = None
    error_message: str | None = None


class AIServiceError(Exception):
    """Normalized AI-only failure; never carries a raw response or exception dump."""

    def __init__(self, status: AIAnalysisStatus, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
