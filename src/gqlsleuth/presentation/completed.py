"""Completed assessment console, composed from pure shared human presentation."""

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from gqlsleuth.ai.models import AIInterpretationResult
from gqlsleuth.application.active_execution import ActiveExecutionScanResult
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.presentation.assessment import (
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_LIMITATIONS,
    DEFAULT_MAX_MANUAL_REVIEW_ITEMS,
    AssessmentItem,
    build_assessment,
)
from gqlsleuth.presentation.capabilities import capability_wording
from gqlsleuth.presentation.console import _section, _table
from gqlsleuth.presentation.priorities import style_priority_terms
from gqlsleuth.reporting.assessment import grouped_technical_sections
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.presentation import ReportSection, technical_sections


def _rows(console: Console, rows: tuple[tuple[str, str], ...]) -> None:
    table = Table.grid(padding=(0, 2), expand=False)
    table.add_column(ratio=1)
    table.add_column(ratio=2, overflow="fold")
    for label, value in rows:
        table.add_row(Text(label), Text(value))
    console.print(table)


def _items(
    console: Console, title: str, items: tuple[AssessmentItem, ...], cap: int | None
) -> None:
    if not items:
        return
    _section(console, title)
    table = _table("Result / review", "Operation")
    multiple = len({i.endpoint for i in items if i.endpoint}) > 1
    for item in items if cap is None else items[:cap]:
        prefix = item.state + ": " if title == "Manual Review" else ""
        if item.state in {"VIOLATION", "UNRESOLVED"}:
            prefix += item.capability + " — "
        table.add_row(
            style_priority_terms(prefix + item.label),
            Text(
                item.operation + ("\n" + item.endpoint if multiple and item.endpoint else ""),
                style="gql.metadata",
            ),
        )
    console.print(table)
    if cap is not None and len(items) > cap:
        console.print(
            f"{len(items) - cap} additional {title.lower()} items not shown; "
            "use --verbose or a report."
        )


def render_completed_assessment(
    console: Console,
    result: SafeExecutionScanResult | ActiveExecutionScanResult,
    *,
    verbose: bool = False,
    ai_result: AIInterpretationResult | None = None,
) -> None:
    report = build_report(result, ai_interpretation=ai_result)
    view = build_assessment(report)
    _section(console, "GQLSleuth Assessment")
    console.print(Text("Target: " + view.target, style="gql.metadata"))
    console.print("Mode: " + view.mode)
    _section(console, "GraphQL Overview")
    _rows(console, view.overview)
    _section(console, "Security Validation")
    _rows(console, view.validation_rows)
    if view.capabilities:
        console.print()
        table = _table("Capability", "Result")
        for capability, status in view.capabilities:
            table.add_row(Text(capability), Text(status))
        console.print(table)
    _items(console, "Findings", view.findings, None if verbose else DEFAULT_MAX_FINDINGS)
    _items(
        console,
        "Manual Review",
        view.manual_review,
        None if verbose else DEFAULT_MAX_MANUAL_REVIEW_ITEMS,
    )
    if view.query_outcomes:
        _section(console, "Query Execution")
        _rows(console, tuple((name, str(count)) for name, count in view.query_outcomes))
    if view.mutations:
        _section(console, "Mutation Execution")
        _rows(console, view.mutations)
    if view.limitations:
        _section(console, "Important Limitations")
        for note in view.limitations if verbose else view.limitations[:DEFAULT_MAX_LIMITATIONS]:
            console.print(Text(note))
        omitted = len(view.limitations) - DEFAULT_MAX_LIMITATIONS
        if not verbose and omitted > 0:
            console.print(f"{omitted} additional limitations; use --verbose.")
    console.print(
        "Review interest is not vulnerability severity. Controls apply only to tested cases.",
        style="gql.secondary",
    )
    if verbose:
        sections = tuple(s for s in technical_sections(report) if s.title != "Scan Overview")
        for group in grouped_technical_sections(sections):
            _render_technical(console, group)
    else:
        console.print("Use --verbose for technical details.", style="gql.secondary")


def _render_technical(console: Console, section: ReportSection) -> None:
    """Reuse report capability projections and the existing bounded response representation."""
    _section(console, section.title)
    for paragraph in section.paragraphs:
        console.print(Text(capability_wording(paragraph)))
    _rows(console, section.rows)
    if section.table_rows:
        table = _table(*section.table_headers)
        for row in section.table_rows:
            table.add_row(*(Text(value) for value in row))
        console.print(table)
    for entry in section.entries:
        console.print()
        console.print(Text(entry.title, style="gql.metadata"))
        _rows(console, entry.details)
        for paragraph in entry.paragraphs:
            console.print(Text(capability_wording(paragraph)))
        for language, value in (*entry.code_blocks, *entry.request_blocks):
            if language == "json":
                console.print("Variables:")
            console.print(Syntax(value, language, word_wrap=True))
        _rows(console, entry.evidence_references)
        if entry.response:
            console.print("Response", style="gql.response")
            _rows(console, entry.response.details)
            body = entry.response.body
            if body:
                if body.notice:
                    console.print(Text(body.notice))
                if body.text:
                    console.print(Syntax(body.text, body.language, word_wrap=True))
            else:
                console.print(
                    "No HTTP response was received; no server response body is available."
                )
    for child in section.children:
        _render_technical(console, child)
