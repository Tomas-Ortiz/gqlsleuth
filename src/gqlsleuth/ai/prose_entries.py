"""One traversal of generated prose and its explicit references for existing guards."""

import re
from collections.abc import Iterator

from gqlsleuth.ai.models import AIInterpretation


def prose_clauses(text: str) -> tuple[str, ...]:
    """Separate sentences and coordinated finite assertions, not arbitrary English clauses.

    Keep dotted input paths and conjunctions inside noun phrases intact. A new finite
    assertion after 'and' cannot borrow a preceding review-question/conditional exemption.
    This is only a validator view; model text is never rewritten.
    """
    return tuple(
        re.split(
            r"[!?](?=\s|$)|[;\n]|\.(?!\w)|\b(?:but|however|yet)\b|"
            r",?\s+and\s+(?=(?:(?:(?:the|this|that|these|those)\s+\w+|it|they)\s+)?"
            r"(?:actually\s+)?(?:returns?|retrieves?|accepts?|has|have|lacks?|"
            r"was|were|is|are|does|do|executed|succeeded)\b)",
            text,
            flags=re.I,
        )
    )


def prose_entries(
    interpretation: AIInterpretation,
) -> Iterator[tuple[str, tuple[str, ...], tuple[str, ...]]]:
    summary = interpretation.summary_interpretation
    yield summary.text, summary.operations, summary.security_facts
    for operation in interpretation.operation_interpretations:
        yield operation.interpretation, (operation.operation,), ()
        yield operation.manual_follow_up, (operation.operation,), ()
    for insight in interpretation.review_insights:
        yield insight.interpretation, insight.operations, insight.security_facts
        yield insight.manual_follow_up, insight.operations, insight.security_facts
    for limitation in interpretation.limitations:
        yield limitation.text, limitation.operations, limitation.security_facts
