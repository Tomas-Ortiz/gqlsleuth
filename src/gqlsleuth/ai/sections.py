"""Shared human presentation of validated AI prose; no scanner interpretation."""

from gqlsleuth.ai.models import AIInterpretation


def interpretation_sections(
    interpretation: AIInterpretation,
) -> tuple[tuple[str, tuple[tuple[tuple[str, ...], str], ...]], ...]:
    return (
        (
            "Security Summary",
            (
                (
                    interpretation.security_summary.security_facts,
                    interpretation.security_summary.text,
                ),
            ),
        ),
        (
            "Security Fact Reviews",
            tuple(
                (
                    (item.security_fact_ref,),
                    item.interpretation + " Manual review: " + item.manual_follow_up,
                )
                for item in interpretation.security_fact_reviews
            ),
        ),
        (
            "Security Controls Observed",
            tuple(
                ((item.security_fact_ref,), item.text)
                for item in interpretation.control_observations
            ),
        ),
        (
            "Cross-Capability Analysis",
            tuple(
                (item.security_facts, item.text)
                for item in interpretation.cross_capability_insights
            ),
        ),
        (
            "Operation Review",
            tuple(
                ((item.operation,), item.explanation) for item in interpretation.operation_review
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
