"""Optional one-way interpretation of a completed SAFE/ACTIVE result."""

from datetime import UTC, datetime
from time import perf_counter

from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import (
    DEFAULT_AI_MODEL,
    AIAnalysisStatus,
    AIContextMetadata,
    AIInterpretationResult,
    AIServiceError,
)
from gqlsleuth.application.active_execution import ActiveExecutionScanResult
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.infrastructure.ollama import OllamaClient


def interpret_completed_scan(
    result: SafeExecutionScanResult | ActiveExecutionScanResult,
    *,
    client: OllamaClient | None = None,
) -> AIInterpretationResult:
    """Never call scanner stages or alter results; expected AI failures are non-fatal."""
    started = perf_counter()
    generated_at = datetime.now(UTC)
    try:
        context = build_ai_context(result)
    except (ValueError, TypeError, RecursionError):
        return AIInterpretationResult(
            AIAnalysisStatus.INVALID_RESPONSE,
            DEFAULT_AI_MODEL,
            generated_at,
            perf_counter() - started,
            AIContextMetadata(
                operations_total=0,
                operations_included=0,
                operations_omitted=0,
                schemas_total=0,
                schemas_included=0,
                context_truncated=True,
            ),
            error_code="invalid_context",
            error_message="Could not build a safe bounded AI context.",
        )
    try:
        interpretation = (client or OllamaClient()).interpret(context)
    except AIServiceError as error:
        return AIInterpretationResult(
            error.status,
            DEFAULT_AI_MODEL,
            generated_at,
            perf_counter() - started,
            context.metadata,
            error_code=error.code,
            error_message=str(error),
        )
    return AIInterpretationResult(
        AIAnalysisStatus.SUCCESS,
        DEFAULT_AI_MODEL,
        generated_at,
        perf_counter() - started,
        context.metadata,
        interpretation=interpretation,
    )
