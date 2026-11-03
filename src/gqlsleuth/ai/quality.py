"""Withhold unsupported prose before constructing the shared public AI result."""

from dataclasses import replace

from gqlsleuth.ai.models import (
    AIContext,
    AIInterpretation,
    AISummaryInterpretation,
    AIWithheldField,
)
from gqlsleuth.ai.prompt import QUALITY_WARNING_ORDER, collect_interpretation_quality_warnings

WITHHELD_PROSE = "AI text withheld: the supplied facts do not support this interpretation."
INCOMPLETE_PROSE = "AI text withheld: the model supplied incomplete text."
_NEUTRAL = "Manual review remains necessary."


def enforce_interpretation_grounding(
    interpretation: AIInterpretation, context: AIContext
) -> tuple[AIInterpretation, tuple[str, ...], tuple[AIWithheldField, ...]]:
    """Keep references and valid sibling fields, never repair or retain rejected prose.

    Evaluate each field in its original section so summary aggregate scope and operation
    reference scope keep their existing meanings. Incomplete fields are unavailable, not repaired.
    The static unavailable marker preserves required v2 fields without inventing guidance.
    """
    # Each actual prose field is checked once in its section/reference scope. Avoid
    # first validating the entire reply and then rechecking every field for withholding.
    warnings: set[str] = set()
    withheld: list[AIWithheldField] = []
    empty = AIInterpretation(
        summary_interpretation=AISummaryInterpretation(text=_NEUTRAL, references=()),
        operation_interpretations=(),
        review_insights=(),
        limitations=(),
    )

    def replacement(probe: AIInterpretation, decision: AIWithheldField) -> str | None:
        codes = collect_interpretation_quality_warnings(probe, context)
        warnings.update(codes)
        rejected = any(
            code.startswith("unsupported_") or code == "false_absence_claim" for code in codes
        )
        incomplete = any(code.startswith("incomplete_") for code in codes)
        if rejected or incomplete:
            withheld.append(
                replace(
                    decision,
                    rule_codes=tuple(code for code in QUALITY_WARNING_ORDER if code in codes),
                )
            )
            return WITHHELD_PROSE if rejected else INCOMPLETE_PROSE
        return None

    summary = interpretation.summary_interpretation
    if marker := replacement(
        empty.model_copy(update={"summary_interpretation": summary}),
        AIWithheldField("summary_interpretation", 0, "text"),
    ):
        summary = summary.model_copy(update={"text": marker})
    operations = []
    for index, item in enumerate(interpretation.operation_interpretations):
        changes = {}
        for field, sibling in (
            ("interpretation", "manual_follow_up"),
            ("manual_follow_up", "interpretation"),
        ):
            probe = empty.model_copy(
                update={"operation_interpretations": (item.model_copy(update={sibling: _NEUTRAL}),)}
            )
            if marker := replacement(
                probe,
                AIWithheldField(
                    "operation_interpretations",
                    index,
                    "interpretation" if field == "interpretation" else "manual_follow_up",
                ),
            ):
                changes[field] = marker
        operations.append(item.model_copy(update=changes))
    insights = []
    for index, item_insight in enumerate(interpretation.review_insights):
        changes = {}
        for field, sibling in (
            ("interpretation", "manual_follow_up"),
            ("manual_follow_up", "interpretation"),
        ):
            probe = empty.model_copy(
                update={"review_insights": (item_insight.model_copy(update={sibling: _NEUTRAL}),)}
            )
            if marker := replacement(
                probe,
                AIWithheldField(
                    "review_insights",
                    index,
                    "interpretation" if field == "interpretation" else "manual_follow_up",
                ),
            ):
                changes[field] = marker
        insights.append(item_insight.model_copy(update=changes))
    limitations = tuple(
        item.model_copy(update={"text": marker})
        if (
            marker := replacement(
                empty.model_copy(update={"limitations": (item,)}),
                AIWithheldField("limitations", index, "text"),
            )
        )
        else item
        for index, item in enumerate(interpretation.limitations)
    )
    return (
        interpretation.model_copy(
            update={
                "summary_interpretation": summary,
                "operation_interpretations": tuple(operations),
                "review_insights": tuple(insights),
                "limitations": limitations,
            }
        ),
        tuple(code for code in QUALITY_WARNING_ORDER if code in warnings),
        tuple(withheld),
    )
