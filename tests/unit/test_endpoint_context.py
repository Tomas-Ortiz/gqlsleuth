"""Endpoint grouping changes human layout only, including multiple-context boundaries."""

import json
from dataclasses import replace
from io import StringIO

import pytest
from rich.console import Console

from gqlsleuth.application.abuse_controls import prepare_abuse_controls
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.sensitive_input import SensitiveInputCandidate, SensitiveInputCategory
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.abuse_controls import render_abuse_controls
from gqlsleuth.presentation.assessment import AssessmentItem
from gqlsleuth.presentation.completed import _items, _render_technical
from gqlsleuth.presentation.console import CONSOLE_THEME, render_mutations
from gqlsleuth.presentation.sensitive_input import render_sensitive_review
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.endpoint_context import group_endpoint_context
from gqlsleuth.reporting.models import ReportFormat, ReportIssue
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection, technical_sections
from gqlsleuth.reporting.renderers import render_report

ENDPOINT = "https://example.com/graphql"
OTHER = "https://other.example/graphql"


@pytest.fixture
def views(phase_ten_scan, monkeypatch):
    safe, requests = phase_ten_scan("""
        type Query { users(id: ID!): User adminUsers: [User] token: String }
        type User { id: ID email: String }
        type Mutation { login(password: String!): String createUser: User deleteUser: Boolean }
    """)
    active = execute_selected_mutations(prepare_active_mutations(safe), confirmed=False)
    abuse = prepare_abuse_controls(active, enabled=True)
    active = replace(active, rate_limiting_abuse_controls=abuse)
    report = build_report(active)
    report = replace(
        report,
        errors_and_limitations=(
            ReportIssue("schema", ENDPOINT, None, "partial", "Coverage is incomplete."),
            ReportIssue("query", ENDPOINT, "users", "graphql_error", "Placeholder rejected."),
        ),
    )
    monkeypatch.setattr(HttpClient, "send", lambda *a, **kw: pytest.fail("Presentation sent HTTP"))
    return active, report, requests


@pytest.mark.parametrize(
    "title",
    [
        "Operation Review Candidates",
        "GraphQL Security Review",
        "Generated Queries",
        "Safe Query Execution",
        "Active Mutation Analysis",
        "Rate Limiting & Abuse Controls",
        "Errors and Limitations",
    ],
)
@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_shared_sections_show_one_endpoint_without_mutating_canonical_records(
    views, monkeypatch, title, format
):
    active, report, requests = views
    before = render_report(report, ReportFormat.JSON)
    evidence = active.evidence
    count = len(requests)
    section = next(s for s in technical_sections(report) if s.title == title)
    assert max(len(section.entries), len(section.table_rows)) >= 2
    monkeypatch.setattr("gqlsleuth.reporting.renderers.human_sections", lambda context: (section,))
    rendered = render_report(report, format).replace("\\.", ".")
    assert rendered.count(ENDPOINT) == 1
    assert "Endpoint:" in rendered
    grouped = group_endpoint_context(section)
    assert grouped.endpoint == ENDPOINT
    assert all(label != "Endpoint" for item in grouped.entries for label, _ in item.details)
    assert [e.title for e in grouped.entries] == [e.title for e in section.entries]
    for old, new in zip(section.entries, grouped.entries, strict=True):
        assert replace(old, details=new.details) == new
    for width in (55, 120):
        output = StringIO()
        _render_technical(Console(file=output, width=width, theme=CONSOLE_THEME), section)
        assert "".join(output.getvalue().split()).count(ENDPOINT) == 1
    assert render_report(report, ReportFormat.JSON) == before
    assert active.evidence == evidence and len(requests) == count
    canonical = json.loads(before)
    assert all(q["generated"]["operation"]["endpoint"] == ENDPOINT for q in canonical["queries"])


@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_multiple_and_exceptional_endpoints_are_grouped_in_stable_order(views, monkeypatch, format):
    _, report, _ = views
    entries = tuple(
        ReportEntry(name, details=(("Endpoint", endpoint), ("Status", "SUCCESS")))
        for name, endpoint in (("first", ENDPOINT), ("exception", OTHER), ("last", ENDPOINT))
    )
    section = ReportSection("Results", entries=entries)
    grouped = group_endpoint_context(section)
    assert [s.endpoint for s in grouped.children] == [ENDPOINT, OTHER]
    assert [[e.title for e in s.entries] for s in grouped.children] == [
        ["first", "last"],
        ["exception"],
    ]
    assert group_endpoint_context(grouped) == grouped
    monkeypatch.setattr("gqlsleuth.reporting.renderers.human_sections", lambda context: (section,))
    rendered = render_report(report, format).replace("\\.", ".")
    assert rendered.count(ENDPOINT) == rendered.count(OTHER) == 1
    assert rendered.index(ENDPOINT) < rendered.index("first") < rendered.index("last")
    assert rendered.index(OTHER) < rendered.index("exception")
    assert rendered.count("SUCCESS") == 3


def test_ambiguous_or_differently_named_endpoint_metadata_is_not_stripped():
    entry = ReportEntry(
        "Cross-endpoint request",
        details=(
            ("Endpoint", ENDPOINT),
            ("Endpoint", OTHER),
            ("WebSocket endpoint", "wss://other.example/ws"),
        ),
    )
    section = ReportSection("Results", endpoint=ENDPOINT, entries=(entry,))
    assert group_endpoint_context(section) == section


def test_unscoped_entries_keep_first_seen_group_order_and_are_not_assigned_an_endpoint():
    section = ReportSection(
        "Results",
        entries=(
            ReportEntry("first", details=(("Endpoint", ENDPOINT),)),
            ReportEntry("unscoped"),
            ReportEntry("other", details=(("Endpoint", OTHER),)),
        ),
    )
    grouped = group_endpoint_context(section)
    assert [s.endpoint for s in grouped.children] == [ENDPOINT, None, OTHER]
    assert [s.entries[0].title for s in grouped.children] == ["first", "unscoped", "other"]
    assert group_endpoint_context(grouped) == grouped


def test_differential_table_keeps_context_labels_inside_each_endpoint_group():
    section = ReportSection(
        "Authorization Differential Review",
        table_headers=("Contexts", "Endpoint", "Observation"),
        table_rows=(
            ("alpha ↔ beta", ENDPOINT, "one"),
            ("beta ↔ gamma", OTHER, "two"),
            ("alpha ↔ gamma", ENDPOINT, "three"),
        ),
    )
    grouped = group_endpoint_context(section)
    assert [s.endpoint for s in grouped.children] == [ENDPOINT, OTHER]
    assert grouped.children[0].table_rows == (("alpha ↔ beta", "one"), ("alpha ↔ gamma", "three"))
    assert grouped.children[1].table_rows == (("beta ↔ gamma", "two"),)


@pytest.mark.parametrize("width", [55, 120])
def test_compact_manual_review_uses_visible_endpoint_groups(width):
    items = tuple(
        AssessmentItem("Schema", name, "REVIEW", "Manual review", endpoint)
        for name, endpoint in (("first", ENDPOINT), ("other", OTHER), ("last", ENDPOINT))
    )
    output = StringIO()
    _items(
        Console(file=output, width=width, theme=CONSOLE_THEME), "Prioritized Review", items, None
    )
    text = " ".join(output.getvalue().split())
    assert text.count(ENDPOINT) == text.count(OTHER) == 1
    assert text.index(ENDPOINT) < text.index("first") < text.index("last") < text.index(OTHER)


def test_active_previews_stay_target_explicit_and_post_execution_abuse_is_grouped(views):
    active, _, _ = views
    for preview in (True, False):
        output = StringIO()
        render_abuse_controls(
            Console(file=output, width=120, theme=CONSOLE_THEME),
            active.rate_limiting_abuse_controls,
            preview=preview,
        )
        text = output.getvalue()
        assert text.count(ENDPOINT) == (
            len(active.rate_limiting_abuse_controls.candidates) if preview else 1
        )
    output = StringIO()
    render_mutations(
        Console(file=output, width=120, theme=CONSOLE_THEME),
        tuple(enumerate(active.preview.candidates, 1)),
        title="Active Mutation candidates",
    )
    assert ENDPOINT in output.getvalue()
    assert output.getvalue().index(ENDPOINT) < output.getvalue().index("login")


@pytest.mark.parametrize("verbose", [False, True])
def test_sensitive_review_groups_endpoints_and_preserves_context(verbose):
    candidates = tuple(
        SensitiveInputCandidate(
            endpoint,
            name,
            "input",
            "role",
            "String",
            SensitiveInputCategory.PRIVILEGE_CONTROL,
            "Review field authorization.",
            (),
        )
        for name, endpoint in (("first", ENDPOINT), ("other", OTHER), ("last", ENDPOINT))
    )
    output = StringIO()
    render_sensitive_review(
        Console(file=output, width=120, theme=CONSOLE_THEME),
        candidates,
        verbose=verbose,
        context="tester-label",
    )
    text = output.getvalue()
    assert text.count(ENDPOINT) == text.count(OTHER) == 1
    assert "Context: tester-label" in text
    assert text.index(ENDPOINT) < text.index("first") < text.index("last") < text.index(OTHER)


def test_grouped_html_endpoint_remains_escaped(views, monkeypatch):
    _, report, _ = views
    endpoint = ENDPOINT + '?value=<script>alert("test")</script>'
    section = ReportSection(
        "Results", entries=(ReportEntry("one", details=(("Endpoint", endpoint),)),)
    )
    monkeypatch.setattr("gqlsleuth.reporting.renderers.human_sections", lambda context: (section,))
    html = render_report(report, ReportFormat.HTML)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
