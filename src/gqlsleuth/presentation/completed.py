"""Completed assessment console, composed from pure shared human presentation."""

from dataclasses import replace

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
    PRIORITIZED_REVIEW_NOTICE,
    PRIORITIZED_REVIEW_TITLE,
    AssessmentItem,
    build_assessment,
)
from gqlsleuth.presentation.capabilities import capability_wording
from gqlsleuth.presentation.console import _endpoint_heading, _major_section, _section, _table
from gqlsleuth.presentation.endpoints import endpoint_groups
from gqlsleuth.presentation.limits import MAX_HUMAN_INVENTORY_ITEMS, showing_notice
from gqlsleuth.presentation.priorities import style_priority_terms
from gqlsleuth.presentation.responses import SUCCESS_NOTICE
from gqlsleuth.presentation.statuses import status_text, style_status_terms
from gqlsleuth.reporting.assessment import grouped_technical_sections
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.endpoint_context import group_endpoint_context
from gqlsleuth.reporting.operation_review import operation_review_section
from gqlsleuth.reporting.presentation import (
    ReportSection,
    _mutation_entry,
    technical_sections,
)
from gqlsleuth.reporting.scaling import bound_section


def _rows(
    console: Console, rows: tuple[tuple[str, str], ...], *, status_labels: bool = False
) -> None:
    table = Table.grid(padding=(0, 2), expand=False)
    table.add_column(ratio=1)
    table.add_column(ratio=2, overflow="fold")
    for label, value in rows:
        table.add_row(
            status_text(label) if status_labels else Text(label),
            style_priority_terms(value)
            if label in {"Priority", "Review priority", "Review interest"}
            else style_status_terms(value),
        )
    console.print(table)


def _items(
    console: Console,
    title: str,
    items: tuple[AssessmentItem, ...],
    cap: int | None,
    *,
    inherited_endpoint: str | None = None,
) -> None:
    if not items:
        return
    _major_section(console, title)
    if title == PRIORITIZED_REVIEW_TITLE:
        console.print(PRIORITIZED_REVIEW_NOTICE, style="gql.secondary")
    visible = items if cap is None else items[:cap]
    for endpoint, entries in endpoint_groups(visible, lambda item: item.endpoint):
        if endpoint and endpoint != inherited_endpoint:
            _endpoint_heading(console, endpoint)
        review = title == PRIORITIZED_REVIEW_TITLE
        table = _table(
            *(("Kind", "Operation", "Review focus") if review else ("Finding", "Operation"))
        )
        for item in entries:
            prefix = ""
            if item.state in {"VIOLATION", "UNRESOLVED"}:
                prefix += item.capability + " — "
            if review:
                table.add_row(
                    status_text(item.state),
                    Text(item.operation, style="gql.metadata"),
                    style_priority_terms(prefix + item.label),
                )
            else:
                table.add_row(
                    style_priority_terms(item.label), Text(item.operation, style="gql.metadata")
                )
        console.print(table)
    if cap is not None and len(items) > cap:
        console.print(
            showing_notice(cap, len(items), title.lower() + " items"), style="gql.secondary"
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
    review = operation_review_section(report)
    represented = set(view.endpoints) | {i.endpoint for i in view.manual_review if i.endpoint}
    represented.update(
        value for e in review.entries for key, value in e.details if key == "Endpoint"
    )
    inherited = view.endpoints[0] if len(view.endpoints) == len(represented) == 1 else None
    _section(console, "GQLSleuth Assessment")
    console.print(Text("Target: " + view.target, style="gql.metadata"))
    for endpoint in view.endpoints:
        console.print(Text("GraphQL endpoint: " + endpoint, style="gql.metadata"))
    console.print("Mode: " + view.mode)
    _major_section(console, "GraphQL Overview")
    _rows(console, view.overview)
    _major_section(console, "Security Validation")
    _rows(console, view.validation_rows if verbose else view.compact_validation_rows)
    console.print(view.validation_notice, style="gql.secondary")
    _items(
        console,
        "Findings",
        view.findings,
        MAX_HUMAN_INVENTORY_ITEMS if verbose else DEFAULT_MAX_FINDINGS,
    )
    if view.capabilities:
        _section(console, "Capability Results")
        table = _table("Capability", "Result")
        for capability, status in view.capabilities:
            table.add_row(Text(capability), style_status_terms(status))
        console.print(table)
    _items(
        console,
        PRIORITIZED_REVIEW_TITLE,
        view.manual_review,
        MAX_HUMAN_INVENTORY_ITEMS if verbose else DEFAULT_MAX_MANUAL_REVIEW_ITEMS,
        inherited_endpoint=inherited,
    )
    cap = MAX_HUMAN_INVENTORY_ITEMS if verbose else DEFAULT_MAX_MANUAL_REVIEW_ITEMS
    if review.entries or verbose:
        _render_technical(
            console,
            replace(
                review,
                entries=review.entries[:cap],
                paragraphs=review.paragraphs
                + (
                    (showing_notice(cap, len(review.entries), "operation reviews"),)
                    if len(review.entries) > cap
                    else ()
                ),
            ),
            inherited_endpoint=inherited,
        )
    if view.query_outcomes:
        _major_section(console, "Query Execution")
        _rows(
            console,
            tuple((name, str(count)) for name, count in view.query_outcomes),
            status_labels=True,
        )
    if view.mutations:
        _major_section(console, "Mutation Execution")
        if verbose:
            _rows(console, view.mutations)
        if report.active and not verbose:
            for item in report.active.candidates:
                if item.execution and item.execution.attempted:
                    entry = _mutation_entry(item, report.evidence)
                    _render_technical(
                        console,
                        ReportSection(
                            "",
                            entries=(
                                replace(
                                    entry,
                                    details=(),
                                    paragraphs=(),
                                    request_blocks=(),
                                    execution=False,
                                ),
                            ),
                        ),
                    )
    if view.query_outcomes or view.mutations:
        console.print(SUCCESS_NOTICE, style="gql.secondary")
    if view.limitations:
        _major_section(console, "Important Limitations")
        cap = MAX_HUMAN_INVENTORY_ITEMS if verbose else DEFAULT_MAX_LIMITATIONS
        for note in view.limitations[:cap]:
            console.print(Text(note))
        if len(view.limitations) > cap:
            console.print(
                showing_notice(cap, len(view.limitations), "limitations"), style="gql.secondary"
            )
    console.print(
        "Review interest is not vulnerability severity. Controls apply only to tested cases.",
        style="gql.secondary",
    )
    if verbose:
        sections = tuple(
            s
            for s in technical_sections(report)
            if s.title not in {"Scan Overview", "Operation Review"}
        )
        for group in grouped_technical_sections(sections):
            _render_technical(console, group)
    else:
        console.print("Use --verbose for technical details.", style="gql.secondary")


def _render_technical(
    console: Console,
    section: ReportSection,
    *,
    major: bool = True,
    inherited_endpoint: str | None = None,
) -> None:
    """Reuse report capability projections and the existing bounded response representation."""
    section = group_endpoint_context(bound_section(section))
    if section.title:
        (_major_section if major else _section)(console, section.title)
    for paragraph in section.paragraphs:
        console.print(Text(capability_wording(paragraph)), style="gql.secondary")
    if section.endpoint and section.endpoint != inherited_endpoint:
        _endpoint_heading(console, section.endpoint)
    elif section.paragraphs and (section.rows or section.table_rows):
        console.print()
    _rows(console, section.rows)
    if section.table_rows:
        if section.rows:
            console.print()
        table = _table(*section.table_headers)
        for row in section.table_rows:
            cells = []
            for header, value in zip(section.table_headers, row, strict=True):
                if header in {"Priority", "Review priority", "Review interest"}:
                    cells.append(style_priority_terms(value))
                elif header in {"Status", "Decision", "Observation", "Generation", "Baseline"}:
                    cells.append(style_status_terms(value))
                else:
                    cells.append(Text(value))
            table.add_row(*cells)
        console.print(table)
    for index, entry in enumerate(section.entries):
        if index or not section.endpoint or section.rows or section.table_rows:
            console.print()
        console.print(Text(entry.title, style="gql.operation"))
        if entry.execution:
            console.print("EXECUTION", style="gql.heading")
        _rows(console, entry.details)
        for paragraph in entry.paragraphs:
            console.print(Text(paragraph if entry.references else capability_wording(paragraph)))
        if entry.references:
            console.print(Text("References: " + ", ".join(entry.references), style="gql.metadata"))
        for language, value in entry.code_blocks:
            console.print()
            if language == "json":
                console.print("Variables:", style="gql.response")
            console.print(Syntax(value, language, word_wrap=True))
        if entry.request_blocks:
            console.print()
            console.print("REQUEST", style="gql.heading")
        for block_index, (language, value) in enumerate(entry.request_blocks):
            if block_index:
                console.print()
            console.print(
                "Variables:" if language == "json" else "GraphQL document:", style="gql.response"
            )
            console.print(Syntax(value, language, word_wrap=True))
        _rows(console, entry.evidence_references)
        if entry.response:
            console.print()
            compact = not entry.execution and not entry.request_blocks and not entry.details
            if compact:
                response = entry.response
                line = Text.assemble(
                    "Status: ",
                    status_text(response.classification),
                    " | HTTP: "
                    + (str(response.http_status) if response.http_status is not None else "None"),
                )
                if response.duration_seconds is not None:
                    line.append(f" | Duration: {response.duration_seconds * 1000:.3f} ms")
                console.print(line)
            else:
                console.print("RESPONSE", style="gql.heading")
                console.print("METADATA", style="gql.response")
                _rows(console, entry.response.details)
            body = entry.response.body
            if body:
                console.print()
                console.print("Observed response:" if compact else "BODY", style="gql.response")
                if body.notice and not (
                    compact and body.notice == "Observed response, not generated preview values."
                ):
                    console.print(Text(body.notice))
                if body.text:
                    console.print(Syntax(body.text, body.language, word_wrap=True))
            else:
                console.print(
                    "No HTTP response was received; no server response body is available."
                )
    if not any(
        (section.paragraphs, section.rows, section.table_rows, section.entries, section.children)
    ):
        console.print("None recorded.", style="gql.secondary")
    for child in section.children:
        _render_technical(console, child, major=False, inherited_endpoint=inherited_endpoint)
