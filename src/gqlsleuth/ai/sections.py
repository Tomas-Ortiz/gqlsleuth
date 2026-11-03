"""Shared interpretation presentation and application-owned reference metadata."""

from gqlsleuth.ai.models import AIInterpretationResult
from gqlsleuth.presentation.terminology import category_label

QUALITY_WARNING_DESCRIPTIONS = {
    "unsupported_security_assurance": (
        "The interpretation may offer unsupported overall security assurance."
    ),
    "false_absence_claim": (
        "An absence claim may contradict supplied Findings or security-relevant observations."
    ),
    "unsupported_outcome_inference": (
        "An execution outcome may be used to infer an unsupported cause or security conclusion."
    ),
    "unsupported_control_claim": (
        "A claim that a security control is present, effective or absent "
        "may lack supporting evidence."
    ),
    "unsupported_review_conclusion": (
        "A review conclusion may exceed what the supplied facts and schema coverage support."
    ),
    "unsupported_execution_claim": (
        "An execution claim may conflict with supplied execution counts or outcomes."
    ),
    "incomplete_security_summary": "The interpretive summary may be incomplete or cut off.",
    "incomplete_prose": "Other interpretation text may be incomplete or cut off.",
}


def quality_warning_description(code: str) -> str:
    """Human wording only; retain unknown warnings without interpreting their identifiers."""
    return QUALITY_WARNING_DESCRIPTIONS.get(
        code, "Unrecognized AI quality warning; consult canonical JSON for its identifier."
    )


def quality_summary_lines(result: AIInterpretationResult) -> tuple[str, ...]:
    """Count recorded field decisions, never model wording or rendered output.

    These presentation-only counters do not change the canonical result schema. A field
    with several warning categories is counted once; two fields may affect one operation.
    """
    if result.interpretation is None or result.withheld_fields is None:
        return ()
    withheld = set(result.withheld_fields)
    operations = {item.index for item in withheld if item.section == "operation_interpretations"}
    interpretation_count = sum(
        item.section == "operation_interpretations" and item.field == "interpretation"
        for item in withheld
    )
    follow_up_count = sum(
        item.section == "operation_interpretations" and item.field == "manual_follow_up"
        for item in withheld
    )
    total = len(result.interpretation.operation_interpretations)
    warning_count = len(set(result.quality_warnings))
    category = "category" if warning_count == 1 else "categories"
    summary_count = sum(item.section == "summary_interpretation" for item in withheld)
    theme_count = sum(item.section == "review_insights" for item in withheld)
    limitation_count = sum(item.section == "limitations" for item in withheld)
    return (
        f"AI quality: {warning_count} warning {category}; {len(withheld)} text fields withheld.",
        f"Operation interpretations: {total - interpretation_count} retained / {total} supplied; "
        f"{interpretation_count} withheld; {len(operations)} operations affected.",
        f"Other withheld fields: {follow_up_count} operation follow-ups; "
        f"{summary_count} summary; {theme_count} cross-operation; {limitation_count} limitations.",
    )


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
