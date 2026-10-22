"""Optional one-way interpretation of a completed SAFE/ACTIVE result."""

from collections.abc import Callable
from datetime import UTC, datetime
from time import perf_counter

from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import (
    DEFAULT_AI_MODEL,
    DEFAULT_AI_TIMEOUT_SECONDS,
    MAX_AI_ATTEMPTS,
    AIAnalysisStatus,
    AIAttemptUsage,
    AIContextMetadata,
    AIInterpretationResult,
    AIProgress,
    AIProviderUsage,
    AIReferenceProjection,
    AIServiceError,
)
from gqlsleuth.ai.prompt import collect_interpretation_quality_warnings, execution_summary
from gqlsleuth.ai.regeneration import corrective_instruction
from gqlsleuth.ai.usage import summarize_usage
from gqlsleuth.application.active_execution import ActiveExecutionScanResult
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.infrastructure.ollama import OllamaClient


def interpret_completed_scan(
    result: SafeExecutionScanResult | ActiveExecutionScanResult,
    *,
    client: OllamaClient | None = None,
    timeout_seconds: float = DEFAULT_AI_TIMEOUT_SECONDS,
    on_progress: Callable[[AIProgress], None] | None = None,
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
    if not (context.schemas or context.operations or context.security_facts):
        return AIInterpretationResult(
            AIAnalysisStatus.NOT_RUN,
            DEFAULT_AI_MODEL,
            generated_at,
            perf_counter() - started,
            context.metadata,
            error_code="insufficient_deterministic_context",
            error_message=(
                "AI interpretation was not run because insufficient deterministic facts "
                "were available."
            ),
        )
    try:
        provider = client or OllamaClient(timeout_seconds=timeout_seconds)
    except ValueError:
        return AIInterpretationResult(
            AIAnalysisStatus.UNAVAILABLE,
            DEFAULT_AI_MODEL,
            generated_at,
            perf_counter() - started,
            context.metadata,
            error_code="invalid_configuration",
            error_message="AI timeout must be finite and positive.",
        )
    failures: list[str] = []
    attempts: list[AIAttemptUsage] = []
    references = AIReferenceProjection(
        operations=context.operations, security_facts=context.security_facts
    )
    canonical_summary = execution_summary(context)
    usage = AIProviderUsage()

    def record_usage(value: AIProviderUsage) -> None:
        nonlocal usage
        usage = value

    for attempt in range(1, MAX_AI_ATTEMPTS + 1):
        usage = AIProviderUsage()
        if on_progress:
            on_progress(AIProgress(attempt, "started"))
        try:
            interpretation = (
                provider.interpret(context, on_usage=record_usage)
                if not failures
                else provider.interpret(
                    context,
                    validation_codes=tuple(dict.fromkeys(failures)),
                    attempt=attempt,
                    on_usage=record_usage,
                )
            )
        except AIServiceError as error:
            retryable = (
                error.status is AIAnalysisStatus.INVALID_RESPONSE
                and corrective_instruction(error.code, attempt + 1) is not None
            )
            if error.code != "context_too_large":
                attempts.append(
                    AIAttemptUsage(
                        attempt,
                        usage,
                        validation_failure=error.code if retryable else None,
                        provider_failure=error.status.value if not retryable else None,
                    )
                )
            if retryable:
                failures.append(error.code)
                if on_progress:
                    on_progress(AIProgress(attempt, "rejected", error.code))
                if attempt < MAX_AI_ATTEMPTS:
                    continue
            return AIInterpretationResult(
                error.status,
                DEFAULT_AI_MODEL,
                generated_at,
                perf_counter() - started,
                context.metadata,
                error_code=error.code,
                error_message=(
                    "AI assistance could not produce a valid interpretation "
                    f"after {attempt} attempts."
                    if retryable
                    else str(error)
                ),
                attempt_count=0 if error.code == "context_too_large" else attempt,
                validation_failures=tuple(failures),
                references=references,
                execution_summary=canonical_summary,
                attempts=tuple(attempts),
                usage=summarize_usage(tuple(attempts), accepted=False),
            )
        attempts.append(AIAttemptUsage(attempt, usage))
        if on_progress:
            on_progress(AIProgress(attempt, "accepted"))
        return AIInterpretationResult(
            AIAnalysisStatus.SUCCESS,
            DEFAULT_AI_MODEL,
            generated_at,
            perf_counter() - started,
            context.metadata,
            interpretation=interpretation,
            quality_warnings=collect_interpretation_quality_warnings(interpretation, context),
            attempt_count=attempt,
            validation_failures=tuple(failures),
            references=references,
            execution_summary=canonical_summary,
            attempts=tuple(attempts),
            usage=summarize_usage(tuple(attempts), accepted=True),
        )
    raise AssertionError("Bounded AI loop must return at its final attempt")
