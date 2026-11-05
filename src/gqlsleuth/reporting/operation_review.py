"""Join human review blocks by retained endpoint, root kind and field identity only."""

from gqlsleuth.ai.sections import AIProseBlock, interpretation_sections
from gqlsleuth.presentation.terminology import category_label
from gqlsleuth.reporting.models import ReportContext
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def operation_review_section(report: ReportContext) -> ReportSection:
    """Keep deterministic reasons and optional model prose separately attributed.

    An unmapped AI identity stays a standalone opaque-reference block. Never infer an
    endpoint from a matching name, even when only one candidate currently has that name.
    """
    ai = report.ai_interpretation
    urls = dict(report.ai_endpoint_urls)
    blocks = dict(interpretation_sections(ai)).get("Operation Analysis", ()) if ai else ()
    by_key = {}
    for block in blocks:
        reference = block.references[0]
        endpoint, kind, name = reference.split("/", 2)
        if endpoint in urls:
            by_key[(urls[endpoint], kind, name)] = block
    executions = {
        (i.generated.endpoint, i.generated.operation.kind.value, i.generated.operation_name): i
        for i in (*report.queries, *(report.active.candidates if report.active else ()))
    }
    entries = []
    used = set()
    for operation in report.review_candidates:
        key = (operation.endpoint, operation.kind.value, operation.name)
        matched_block: AIProseBlock | None = by_key.get(key)
        artifact = executions.get(key)
        execution = artifact.execution if artifact else None
        state = (
            (execution.status or execution.decision or "not_recorded").upper()
            if execution
            else "NOT_ATTEMPTED"
        )
        details: tuple[tuple[str, str], ...] = (
            ("Endpoint", operation.endpoint),
            ("Review interest", operation.priority.value.replace("_", " ").upper()),
            ("Execution", state),
        )
        if operation.categories:
            details += (
                ("Categories", ", ".join(category_label(c.value) for c in operation.categories)),
            )
        # Preserve meaningful semantic reasons and matched terms; raw score arithmetic and
        # exact matching locations remain in the unchanged canonical analysis.
        paragraphs = tuple(
            "Deterministic review: "
            + match.reason
            + " Matched terms: "
            + ", ".join(match.matched_keywords)
            + "."
            for match in operation.matched_rules
        ) or tuple("Deterministic review: " + reason for reason in operation.reasons)
        references: tuple[str, ...] = ()
        if matched_block:
            used.add(matched_block.references[0])
            references = matched_block.references
            paragraphs += tuple(
                "AI " + text if text.startswith("Interpretation:") else text
                for text in matched_block.paragraphs
            )
        elif ai and ai.interpretation:
            paragraphs += (
                "No AI operation entry supplied; bounded context does not cover every operation.",
            )
        entries.append(
            ReportEntry(
                f"{operation.kind.value.title()}: {operation.name}",
                details=details,
                paragraphs=paragraphs,
                references=references,
            )
        )
    for block in blocks:
        if block.references[0] in used:
            continue
        resolved_endpoint = urls.get(block.references[0].split("/", 1)[0])
        entries.append(
            ReportEntry(
                block.title,
                details=((("Endpoint", resolved_endpoint),) if resolved_endpoint else ())
                + block.details,
                paragraphs=tuple(
                    "AI " + text if text.startswith("Interpretation:") else text
                    for text in block.paragraphs
                ),
                references=block.references,
            )
        )
    return ReportSection(
        "Operation Review",
        paragraphs=(
            "Review interest is not vulnerability severity. Deterministic reasons and "
            "optional AI interpretation are separately attributed; AI requires manual validation.",
        )
        + (() if entries else ("None recorded.",)),
        entries=tuple(entries),
    )
