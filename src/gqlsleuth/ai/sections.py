"""Shared interpretation presentation and application-owned reference metadata."""

from gqlsleuth.ai.models import AIInterpretationResult
from gqlsleuth.presentation.terminology import category_label


def operation_metadata(
    result: AIInterpretationResult, reference: str
) -> tuple[tuple[str, str], ...]:
    operation = next((o for o in result.references.operations if o.operation == reference), None)
    if operation is None:
        return (("Metadata", "Reference projection unavailable"),)
    return (
        ("Operation", operation.name),
        ("Kind", operation.kind.value.title()),
        ("Review interest", operation.priority.value.upper().replace("_", " ")),
        ("Categories", ", ".join(category_label(c.value) for c in operation.categories) or "None"),
        ("Attempted", "Yes" if operation.attempted else "No"),
        (
            "Execution",
            (
                operation.execution_status.value
                if operation.execution_status
                else operation.mutation_decision.value
                if operation.mutation_decision
                else "not_attempted"
            ).upper(),
        ),
    )


def usage_rows(result: AIInterpretationResult) -> tuple[tuple[str, str], ...]:
    usage = result.usage
    if usage is None:
        return (("Attempts", str(result.attempt_count)),)

    def value(count: int | None) -> str:
        return f"{count:,}" if count is not None else "Not reported"

    rows: tuple[tuple[str, str], ...] = (
        ("Attempts", str(result.attempt_count)),
        ("Prompt tokens (session total)", value(usage.total_prompt_tokens)),
        ("Completion tokens (session total)", value(usage.total_completion_tokens)),
        ("Output limit hits", str(usage.output_limit_hit_count)),
        (
            "Provider done reasons",
            "; ".join(f"{key}: {count}" for key, count in usage.done_reason_counts),
        ),
    )
    if usage.accepted_attempt is not None:
        final = result.attempts[usage.accepted_attempt - 1].usage
        rows += (
            (
                "Accepted completion tokens / limit",
                f"{value(final.completion_tokens)} / {value(final.completion_token_limit)}",
            ),
            ("Completion tokens remaining", value(final.completion_tokens_remaining)),
            ("Configured context token limit", value(final.context_token_limit)),
            ("Approx. context tokens remaining", value(final.approx_context_tokens_remaining)),
        )
    return rows


def interpretation_sections(
    result: AIInterpretationResult,
) -> tuple[tuple[str, tuple[tuple[tuple[str, ...], str], ...]], ...]:
    interpretation = result.interpretation
    if interpretation is None:
        return ()
    summary = interpretation.summary_interpretation
    return (
        ("Interpretive Summary", (((*summary.operations, *summary.security_facts), summary.text),)),
        (
            "Operation Analysis",
            tuple(
                (
                    (item.operation,),
                    "\n".join(
                        f"{label}: {value}"
                        for label, value in operation_metadata(result, item.operation)
                    )
                    + "\nAI interpretation: "
                    + item.interpretation
                    + "\nManual follow-up: "
                    + item.manual_follow_up,
                )
                for item in interpretation.operation_interpretations
            ),
        ),
        (
            "Cross-Operation Review Themes",
            tuple(
                (
                    (*item.operations, *item.security_facts),
                    item.interpretation + "\nManual follow-up: " + item.manual_follow_up,
                )
                for item in interpretation.review_insights
            ),
        ),
        (
            "Limitations",
            tuple(
                ((*item.operations, *item.security_facts), item.text)
                for item in interpretation.limitations
            ),
        ),
    )
