"""Shared interpretation presentation and application-owned reference metadata."""

from dataclasses import dataclass

from gqlsleuth.ai.models import AIInterpretationResult
from gqlsleuth.ai.quality import INCOMPLETE_PROSE, WITHHELD_PROSE
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


def quality_summary_lines(
    result: AIInterpretationResult, *, compact: bool = False
) -> tuple[str, ...]:
    """Count recorded field decisions, never model wording or rendered output.

    These presentation-only counters do not change the canonical result schema. A field
    with several warning categories is counted once; two fields may affect one operation.
    """
    if result.interpretation is None:
        return ()
    total = len(result.interpretation.operation_interpretations)
    if result.withheld_fields is None:
        return (
            (f"Operation interpretations: {total} supplied; withholding accounting unavailable.",)
            if compact
            else ()
        )
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
    warning_count = len(set(result.quality_warnings))
    category = "category" if warning_count == 1 else "categories"
    summary_count = sum(item.section == "summary_interpretation" for item in withheld)
    theme_count = sum(item.section == "review_insights" for item in withheld)
    limitation_count = sum(item.section == "limitations" for item in withheld)
    if compact:
        return (
            f"Operation interpretations: {total - interpretation_count}/{total} retained; "
            f"{interpretation_count} withheld."
            if total
            else "No operation interpretations supplied.",
            f"Quality: {warning_count} warning {category}; {len(withheld)} "
            f"{'field' if len(withheld) == 1 else 'fields'} withheld."
            if warning_count or withheld
            else "Quality: no withholding recorded.",
        )
    return (
        f"AI quality: {warning_count} warning {category}; {len(withheld)} text "
        f"{'field' if len(withheld) == 1 else 'fields'} withheld.",
        f"Operation interpretations: {total - interpretation_count} retained / {total} supplied; "
        f"{interpretation_count} withheld; {len(operations)} "
        f"{'operation' if len(operations) == 1 else 'operations'} affected.",
        f"Other withheld fields: {follow_up_count} operation "
        f"{'follow-up' if follow_up_count == 1 else 'follow-ups'}; "
        f"{summary_count} summary; {theme_count} cross-operation; {limitation_count} "
        f"{'limitation' if limitation_count == 1 else 'limitations'}.",
    )


def operation_metadata(
    result: AIInterpretationResult, reference: str
) -> tuple[tuple[str, str], ...]:
    operation = next((o for o in result.references.operations if o.operation == reference), None)
    if operation is None:
        return (("Metadata", "Reference projection unavailable"),)
    return (
        ("Review interest", operation.priority.value.upper().replace("_", " ")),
        *(
            (("Categories", ", ".join(category_label(c.value) for c in operation.categories)),)
            if operation.categories
            else ()
        ),
    ) + (
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


def operation_label(result: AIInterpretationResult, reference: str) -> str:
    """Resolve a supplied identity; opaque endpoint labels disambiguate multiple surfaces."""
    operation = next((o for o in result.references.operations if o.operation == reference), None)
    if operation is None:
        return reference
    label = f"{operation.kind.value.title()}: {operation.name}"
    endpoints = {o.operation.split("/", 1)[0] for o in result.references.operations}
    if len(endpoints) > 1:
        label += " (" + reference.split("/", 1)[0] + ")"
    return label


def prose_label(text: str) -> str:
    """Shorten only application-owned markers; never edit retained model prose."""
    return {
        WITHHELD_PROSE: "Withheld — unsupported by supplied facts",
        INCOMPLETE_PROSE: "Withheld — incomplete model text",
    }.get(text, text)


@dataclass(frozen=True)
class AIProseBlock:
    """Human-only prose layout shared by the console and report projections."""

    title: str = ""
    details: tuple[tuple[str, str], ...] = ()
    paragraphs: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


def interpretation_sections(
    result: AIInterpretationResult,
) -> tuple[tuple[str, tuple[AIProseBlock, ...]], ...]:
    interpretation = result.interpretation
    if interpretation is None:
        return ()
    summary = interpretation.summary_interpretation
    return (
        (
            "Interpretive Summary",
            (
                AIProseBlock(
                    paragraphs=(prose_label(summary.text),),
                    references=(*summary.operations, *summary.security_facts),
                ),
            ),
        ),
        (
            "Operation Analysis",
            tuple(
                AIProseBlock(
                    title=operation_label(result, item.operation),
                    details=operation_metadata(result, item.operation),
                    paragraphs=(
                        "Interpretation: " + prose_label(item.interpretation),
                        "Manual follow-up: " + prose_label(item.manual_follow_up),
                    ),
                    references=(item.operation,),
                )
                for item in interpretation.operation_interpretations
            ),
        ),
        (
            "Cross-Operation Review Themes",
            tuple(
                AIProseBlock(
                    title="; ".join(operation_label(result, ref) for ref in item.operations)
                    or "Security-fact review",
                    paragraphs=(
                        prose_label(item.interpretation),
                        "Manual follow-up: " + prose_label(item.manual_follow_up),
                    ),
                    references=(*item.operations, *item.security_facts),
                )
                for item in interpretation.review_insights
            ),
        ),
        (
            "Limitations",
            tuple(
                AIProseBlock(
                    paragraphs=(prose_label(item.text),),
                    references=(*item.operations, *item.security_facts),
                )
                for item in interpretation.limitations
            ),
        ),
    )
