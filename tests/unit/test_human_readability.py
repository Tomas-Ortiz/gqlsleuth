"""Readable human hierarchy without modifying canonical facts or request artifacts."""

import json
import re
from copy import deepcopy
from html import unescape
from io import StringIO

import httpx
import pytest
from rich.console import Console
from rich.rule import Rule
from rich.text import Text

from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.domain.analysis import InterestPriority
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.assessment import PRIORITIZED_REVIEW_NOTICE, AssessmentItem
from gqlsleuth.presentation.completed import _items, _render_technical, render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.priorities import PRIORITY_STYLES
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection, _execution_entry
from gqlsleuth.reporting.renderers import render_report

ENDPOINT = "https://example.com/graphql"
OTHER = "https://second.example/graphql"
LONG_ERROR = "Required business input was not provided. " * 8


@pytest.fixture
def readable(phase_ten_scan, monkeypatch):
    safe, _ = phase_ten_scan("""
        type Query { me(id: ID!): User ok: String readAndBurn: String users: [User] }
        type User { id: ID friends: [User] }
    """)

    def handler(request):
        query = json.loads(request.content)["query"]
        return httpx.Response(
            200,
            json={"errors": [{"message": LONG_ERROR}]}
            if "me(" in query
            else {"data": {"value": "BODY_MARKER"}},
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        safe = execute_generated_queries(safe.query_generation, client=client)
    report = build_report(safe)
    entries = tuple(
        _execution_entry(
            next(q for q in report.queries if q.generated.operation_name == name), report.evidence
        )
        for name in ("me", "ok", "readAndBurn")
    )
    section = ReportSection(
        "Safe Query Execution",
        paragraphs=("Execution outcomes are not vulnerability confirmation.",),
        rows=(("GRAPHQL_ERROR", "1"), ("SUCCESS", "2"), ("SKIPPED_SAFETY", "1")),
        entries=entries,
        table_headers=("Operation", "Status", "Endpoint"),
        table_rows=tuple((e.title, dict(e.details)["Status"], ENDPOINT) for e in entries),
    )
    monkeypatch.setattr(HttpClient, "send", lambda *a, **kw: pytest.fail("Rendering sent HTTP"))
    original = deepcopy(report)
    yield safe, report, section
    assert report == original


def capture(renderer, *args, width=100, **kwargs):
    stream = StringIO()
    console = Console(file=stream, width=width, theme=CONSOLE_THEME, color_system=None)
    renderer(console, *args, **kwargs)
    return stream.getvalue()


@pytest.mark.parametrize("width", [45, 100])
def test_endpoint_group_spacing_and_major_rule(width):
    items = tuple(
        AssessmentItem("Schema", name, "REVIEW", "Manual review", endpoint)
        for name, endpoint in (("first", ENDPOINT), ("second", OTHER))
    )
    text = capture(_items, "Prioritized Review", items, None, width=width)
    assert " ".join(PRIORITIZED_REVIEW_NOTICE.split()) in " ".join(text.split())
    assert re.search(r"\n\nEndpoint:.*?\n\n", text, re.S)
    assert text.index("PRIORITIZED REVIEW") < text.index("Endpoint:") < text.index("first")
    assert text.count("Endpoint:") == 2
    rules = [line for line in text.splitlines() if len(line) == width and set(line) <= {"─", "-"}]
    assert len(rules) == 1 and len(rules[0]) <= width
    assert max(map(len, text.splitlines())) <= width
    assert "\n\n\n" not in text


@pytest.mark.parametrize("width", [45, 100])
def test_operation_execution_request_response_boundaries(readable, width):
    _, _, section = readable
    text = capture(_render_technical, section, width=width)
    operation = text.split("\nme\n", 1)[1].split("\nok\n", 1)[0]
    positions = [
        operation.index(label)
        for label in (
            "EXECUTION",
            "GraphQL errors",
            "REQUEST",
            "GraphQL document:",
            "Variables:",
            "RESPONSE",
            "METADATA",
            "BODY",
        )
    ]
    assert positions == sorted(positions)
    assert "\n\nREQUEST\nGraphQL document:" in operation
    assert "\n\nRESPONSE\nMETADATA\n" in operation
    assert "\n\nBODY\n" in operation
    assert LONG_ERROR.strip() in " ".join(operation.split())
    success = text.split("\nok\n", 1)[1].split("\nreadAndBurn\n", 1)[0]
    assert "SUCCESS" in success and "REQUEST" in success and "BODY_MARKER" in success
    skipped = text.split("\nreadAndBurn\n", 1)[1]
    assert "EXECUTION" in skipped and "SKIPPED_SAFETY" in skipped
    assert "REQUEST" not in skipped and "RESPONSE" not in skipped
    assert "\n\n\n" not in text
    assert max(map(len, text.splitlines())) <= width
    assert (
        len([line for line in text.splitlines() if len(line) == width and set(line) <= {"─", "-"}])
        == 1
    )


@pytest.mark.parametrize("verbose", [False, True])
def test_completed_console_separates_major_groups_only(readable, verbose):
    safe, _, _ = readable
    text = capture(render_completed_assessment, safe, verbose=verbose)
    assert "GRAPHQL OVERVIEW" in text and "SECURITY VALIDATION" in text
    assert "\n\n\n" not in text
    assert "REQUEST" in text if verbose else "REQUEST" not in text
    assert "Execution outcomes" not in text  # Synthetic fixture prose is not global help.


@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_human_request_hierarchy_and_canonical_immutability(readable, monkeypatch, format):
    _, report, section = readable
    canonical = render_report(report, ReportFormat.JSON)
    monkeypatch.setattr("gqlsleuth.reporting.renderers.human_sections", lambda r: (section,))
    output = render_report(report, format)
    assert output.count("Endpoint:") == 1
    assert output.index("Execution outcomes") < output.index("Endpoint:")
    assert "Metadata" in output and "Body" in output and "Variables:" in output
    for entry in section.entries:
        for _language, document in entry.request_blocks:
            assert document in unescape(output)
    assert render_report(report, ReportFormat.JSON) == canonical
    assert json.loads(canonical)["report_schema_version"] == 2
    if format is ReportFormat.HTML:
        assert '<h3 class="endpoint">' in output
        assert "<h4>me</h4>" in output
        assert '<h5 class="subsection">Request</h5>' in output
        assert '<details class="response">' in output
        assert '<p class="body-label"><strong>Body</strong></p>' in output
        assert '<p class="help-text">' in output
        assert "default-src 'none'" in output and "<script" not in output
    else:
        assert "### Endpoint:" in output and "#### me\n" in output
        assert "##### Request\n" in output and "##### Response\n" in output
        assert "```graphql\n" in output and "```json\n" in output
        assert not re.search(r"^#{7,} ", output, re.M)


def test_empty_states_and_scaling_notices_are_secondary(readable, monkeypatch):
    _, report, _ = readable
    section = ReportSection("Empty")
    stream = StringIO()
    console = Console(file=stream, theme=CONSOLE_THEME)
    segments = []
    original = console.print

    def observe(*values, **kwargs):
        if values and values[0] == "None recorded.":
            segments.append(kwargs.get("style"))
        original(*values, **kwargs)

    monkeypatch.setattr(console, "print", observe)
    _render_technical(console, section)
    assert segments == ["gql.secondary"]
    monkeypatch.setattr("gqlsleuth.reporting.renderers.human_sections", lambda r: (section,))
    assert '<p class="empty-state">None recorded.</p>' in render_report(report, ReportFormat.HTML)
    assert "*None recorded.*" in render_report(report, ReportFormat.MARKDOWN)
    section = ReportSection(
        "Structural review",
        rows=(("Structural review candidates", "83"),),
        entries=tuple(ReportEntry(str(i)) for i in range(85)),
    )
    text = capture(_render_technical, section)
    assert "Showing 10 of 85 available detail sections." in text
    assert re.search(r"Structural review candidates\s+83", text)


@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_accessible_schema_language_preserves_canonical_terms_and_caveats(readable, format):
    safe, report, _ = readable
    before = render_report(report, ReportFormat.JSON)
    assert "Obvious bounding input:" in before
    assert '"list_bounding_review"' in before
    text = unescape(render_report(report, format)).replace("\\", "")
    assert "Obvious bounding input:" not in text
    assert "Input to limit the number of results: none observed" in text
    assert "Runtime controls may exist outside the schema" in text
    assert "does not prove runtime enforcement" in text
    assert "follow object relationships back to an earlier type" in text
    for term in ("GraphQL", "Query", "Variables", "HTTP", "Introspection"):
        assert term in text
    console = capture(render_completed_assessment, safe, verbose=True, width=120)
    assert "Input to limit the number of results: none observed" in console
    assert "Obvious bounding input:" not in console
    assert render_report(report, ReportFormat.JSON) == before


def test_major_rule_uses_rich_width_aware_rendering(monkeypatch):
    from gqlsleuth.presentation.console import _major_section

    console = Console(file=StringIO(), theme=CONSOLE_THEME)
    objects = []
    monkeypatch.setattr(console, "print", lambda *values, **kwargs: objects.extend(values))
    _major_section(console, "Overview")
    assert sum(isinstance(value, Rule) for value in objects) == 1


def test_execution_heading_peers_and_subordinate_labels(readable, monkeypatch):
    console = Console(file=StringIO(), theme=CONSOLE_THEME)
    labels = {}
    original = console.print

    def observe(*values, **kwargs):
        if values and isinstance(values[0], str):
            labels[values[0]] = kwargs.get("style")
        original(*values, **kwargs)

    monkeypatch.setattr(console, "print", observe)
    _render_technical(console, readable[2])
    assert labels["EXECUTION"] == labels["REQUEST"] == labels["RESPONSE"] == "gql.heading"
    assert {labels[label] for label in ("GraphQL document:", "Variables:", "METADATA", "BODY")} == {
        "gql.response"
    }
    text = console.file.getvalue()
    assert "\nme\nEXECUTION\n" in text and "\nreadAndBurn\nEXECUTION\n" in text
    assert "EXECUTION\n\n" not in text


@pytest.mark.parametrize("priority", list(InterestPriority))
def test_priority_palette_is_shared_by_details_and_tables(priority, monkeypatch):
    label = priority.value.replace("_", " ").upper()
    console = Console(file=StringIO(), theme=CONSOLE_THEME, width=120, force_terminal=True)
    segments = []
    original = console.print

    def observe(*values, **kwargs):
        for value in values:
            if not isinstance(value, str):
                segments.extend(console.render(value))
        original(*values, **kwargs)

    monkeypatch.setattr(console, "print", observe)
    for title in ("Operation Review Candidates", "Generated Queries"):
        section = ReportSection(
            title,
            entries=(ReportEntry("Query mixedCase", details=(("Priority", label),)),),
            table_headers=("Operation", "Priority"),
            table_rows=(("mixedCase", label),),
        )
        _render_technical(console, section)
    matches = [s for s in segments if s.text.strip() == label]
    assert len(matches) == 4
    expected = console.get_style(PRIORITY_STYLES[priority])
    assert all(s.style.color == expected.color and s.style.bold == expected.bold for s in matches)
    text = Text.from_ansi(console.file.getvalue()).plain
    assert "Query mixedCase" in text and "MIXEDCASE" not in text


@pytest.mark.parametrize("terminal", [False, True])
def test_no_color_and_non_tty_keep_priority_and_status_text(terminal, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    stream = StringIO()
    console = Console(file=stream, theme=CONSOLE_THEME, force_terminal=terminal, width=120)
    section = ReportSection(
        "Attack Surface",
        entries=(
            ReportEntry(
                "Mutation createUser",
                details=(("Priority", "HIGH INTEREST"), ("Status", "GRAPHQL_ERROR")),
            ),
        ),
    )
    _render_technical(console, section)
    text = Text.from_ansi(stream.getvalue())
    assert "ATTACK SURFACE" in text.plain and "Mutation createUser" in text.plain
    assert "HIGH INTEREST" in text.plain and "GRAPHQL_ERROR" in text.plain
    assert all(
        Text.get_style_at_offset(text, console, span.start).color is None for span in text.spans
    )
    if not terminal:
        assert "\x1b[" not in stream.getvalue()


def test_skipped_blocks_are_compact_and_context_labels_keep_case():
    names = ("deleteAllPastes", "readAndBurn", "systemUpdate")
    section = ReportSection(
        "Safe Query Execution — Context: CustomerA",
        entries=tuple(
            ReportEntry(
                name,
                execution=True,
                details=(("Status", "SKIPPED_SAFETY"),),
                paragraphs=("Not sent.",),
            )
            for name in names
        ),
    )
    text = capture(_render_technical, section)
    assert "SAFE QUERY EXECUTION — CONTEXT: CustomerA" in text
    for name in names:
        assert f"{name}\nEXECUTION\nStatus" in text
    assert text.count("Not sent.\n\n") == 2
    assert not any(label in text for label in ("REQUEST", "RESPONSE", "METADATA", "BODY"))
