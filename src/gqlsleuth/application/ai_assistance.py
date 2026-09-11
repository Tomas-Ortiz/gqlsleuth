"""Optional one-way interpretation of a completed SAFE/ACTIVE result."""

from datetime import UTC, datetime
from time import perf_counter

from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import (
    DEFAULT_AI_MODEL,
    AIAnalysisStatus,
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
    context = build_ai_context(result)
    started = perf_counter()
    generated_at = datetime.now(UTC)
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
