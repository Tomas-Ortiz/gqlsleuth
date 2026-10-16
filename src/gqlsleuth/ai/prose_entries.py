"""One traversal of generated prose and its explicit references for existing guards."""

from collections.abc import Iterator

from gqlsleuth.ai.models import AIInterpretation


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
