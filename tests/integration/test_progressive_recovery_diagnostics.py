"""Inventory-first recovery, conservative stops and human-only diagnostic projections."""

import json
from dataclasses import replace
from io import StringIO

import httpx
import pytest
from graphql import graphql_sync
from rich.console import Console

from fixtures.progressive_introspection import mock_recovery
from gqlsleuth.application.introspection import _introspect_endpoint
from gqlsleuth.application.safe_execution import run_safe_execution_scan
from gqlsleuth.graphql.introspection import SchemaRetrievalStatus
from gqlsleuth.graphql.progressive_introspection import ROOT_INVENTORY_QUERY, TYPE_QUERIES
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.assessment import build_assessment
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.recovery import present_recovery
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import technical_sections
from gqlsleuth.reporting.renderers import render_report

TARGET = "http://127.0.0.1:8123/graphql"
SDL = "schema { query: Read } type Read { things: [Thing!]! } type Thing { id: ID! }"
DETAIL, SHALLOW = (q for _, q in TYPE_QUERIES[:2])
INVENTORY = ROOT_INVENTORY_QUERY


@pytest.mark.parametrize(
    "message,label",
    [
        ("Query depth limit exceeded.", "Depth limit"),
        ("Query complexity limit exceeded.", "Complexity limit"),
        ("Query cost limit exceeded.", "Cost limit"),
    ],
)
@pytest.mark.parametrize("status", [200, 400, 413, 422])
def test_root_inventory_survives_eligible_detail_rejections(message, label, status):
    def reject(request, count):
        p = json.loads(request.content)
        if p.get("variables", {}).get("name") == "Read" and p["query"] in {DETAIL, SHALLOW}:
            return httpx.Response(status, json={"errors": [{"message": message}]})
        return None

    handler, seen, _ = mock_recovery(SDL, override=reject)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        endpoint = _introspect_endpoint(TARGET, client)
    recovery = endpoint.progressive
    root = recovery.types[0]
    assert root.name == "Read" and root.field_names == ("things",)
    assert not root.complete and endpoint.selected_schema_source is None
    assert recovery.status is SchemaRetrievalStatus.PARTIAL
    assert recovery.stop_reason == label
    shapes = [a.shape for a in recovery.attempts if a.variables.get("name") == "Read"]
    assert shapes == ["root_inventory", "type_detail", "type_shallow"]
    assert len({(a.shape, a.variables.get("name")) for a in recovery.attempts}) == len(
        recovery.attempts
    )
    assert len(seen) == len(recovery.attempts) + 3 <= 35
    rows = dict(present_recovery(recovery).rows)
    assert rows["Known Queries"] == "1 (partial coverage)"
    assert rows["Known Mutations"] == rows["Known Subs"] == "0"


@pytest.mark.parametrize(
    "status,body,reason",
    [
        (401, {"errors": [{"message": "Query too deep"}]}, "Access denied"),
        (403, {"errors": [{"message": "Query too deep"}]}, "Access denied"),
        (429, {"errors": [{"message": "Query too deep"}]}, "Rate limited"),
        (500, {"errors": [{"message": "Query too deep"}]}, "Server error"),
        (503, {"errors": [{"message": "Query too deep"}]}, "Server error"),
        (413, "<html>too large</html>", "Malformed GraphQL response"),
        (413, "{bad", "Malformed GraphQL response"),
        (
            413,
            {"errors": [{"message": "Query too deep"}, {"message": "Other error"}]},
            "Noneligible response",
        ),
        (200, {"errors": [{"message": "Introspection is disabled"}]}, "Introspection disabled"),
        (
            400,
            {"errors": [{"message": "Unknown argument on introspection field"}]},
            "Noneligible response",
        ),
        (200, {"data": {"__type": None}}, "Malformed or inconsistent schema data"),
    ],
)
def test_ineligible_detail_stops_globally_and_preserves_inventory(status, body, reason):
    def reject(request, count):
        p = json.loads(request.content)
        if p.get("variables", {}).get("name") == "Read" and p["query"] == DETAIL:
            return (
                httpx.Response(status, text=body)
                if isinstance(body, str)
                else httpx.Response(status, json=body)
            )
        return None

    handler, seen, _ = mock_recovery(SDL, override=reject)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        endpoint = _introspect_endpoint(TARGET, client)
    recovery = endpoint.progressive
    assert len(seen) == 6 and len(recovery.attempts) == 3
    assert recovery.stop_reason == reason
    assert recovery.types[0].field_names == ("things",)
    assert endpoint.selected_schema_source is None
    assert [a.shape for a in recovery.attempts] == ["catalogue", "root_inventory", "type_detail"]


def test_type_specific_restrictions_do_not_cancel_other_known_types():
    sdl = "type Query { a: A z: Z } type A { id: ID } type Z { id: ID }"

    def reject(request, count):
        if json.loads(request.content).get("variables", {}).get("name") == "A":
            return httpx.Response(413, json={"errors": [{"message": "Query too deep"}]})
        return None

    handler, _, _ = mock_recovery(sdl, override=reject)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        recovery = _introspect_endpoint(TARGET, client).progressive
    assert "Z" in {t.name for t in recovery.types}
    assert "A" not in {t.name for t in recovery.types}
    assert len([a for a in recovery.attempts if a.variables.get("name") == "A"]) == 3
    assert recovery.assembled is None


@pytest.mark.parametrize("variant", ["empty", "missing", "duplicate", "contradictory"])
def test_root_inventory_integrity_and_unknown_counts(variant):
    def alter(request, count):
        p = json.loads(request.content)
        if p.get("variables", {}).get("name") != "Read":
            return None
        data = graphql_sync(schema, p["query"], variable_values=p["variables"]).data
        if p["query"] == INVENTORY:
            if variant == "missing":
                data["__type"].pop("fields")
            elif variant == "duplicate":
                data["__type"]["fields"] *= 2
            elif variant == "empty":
                data["__type"]["fields"] = []
        elif variant == "empty":
            return httpx.Response(413, json={"errors": [{"message": "Query too deep"}]})
        elif variant == "contradictory":
            data["__type"]["fields"] = []
        return httpx.Response(200, json={"data": data})

    handler, _, schema = mock_recovery(SDL, override=alter)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        recovery = _introspect_endpoint(TARGET, client).progressive
    assert recovery.assembled is None
    rows = dict(present_recovery(recovery).rows)
    assert rows["Known Queries"] == ("0 (partial coverage)" if variant == "empty" else "Unknown")


def test_successful_detail_needs_no_shallow_retry():
    handler, _, _ = mock_recovery(SDL)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        recovery = _introspect_endpoint(TARGET, client).progressive
    assert recovery.assembled is not None
    assert [a.shape for a in recovery.attempts if a.variables.get("name") == "Read"] == [
        "root_inventory",
        "type_detail",
    ]
    assert recovery.stop_reason == "Complete reconstruction"


@pytest.mark.parametrize("depth", [8, 3, 2])
@pytest.mark.parametrize("width,verbose", [(45, False), (60, True), (110, False)])
def test_structured_presentation_and_unchanged_canonical_fields(monkeypatch, depth, width, verbose):
    handler, seen, _ = mock_recovery(SDL, depth=depth)
    monkeypatch.setattr("httpx._client.HTTPTransport", lambda **_: httpx.MockTransport(handler))
    monkeypatch.setenv("NO_COLOR", "1")
    scan = run_safe_execution_scan(TARGET)
    count = len(seen)
    report = build_report(scan)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert canonical["report_schema_version"] == 2
    assert "recovery" not in canonical["endpoints"][0]
    assert (
        canonical["endpoints"][0]["schema_retrieval_summary"]
        == report.endpoints[0].schema_retrieval_summary
    )
    assert "Recovery stop reason:" in " ".join(canonical["evidence"][-1]["notes"]) or any(
        "Recovery stop reason:" in " ".join(e["notes"]) for e in canonical["evidence"]
    )
    output = StringIO()
    render_completed_assessment(
        Console(file=output, theme=CONSOLE_THEME, width=width, color_system=None),
        scan,
        verbose=verbose,
    )
    text = " ".join(output.getvalue().split())
    assert text.count("Recovery method") == 1
    assert "Stop reason" in text and "PROGRESSIVE" in text
    assert "\x1b" not in output.getvalue()
    overview = build_assessment(report).overview
    assert not any("Known Queries" in value for _, value in overview)
    section = next(s for s in technical_sections(report) if s.title == "Introspection")
    rows = dict(section.entries[0].details)
    assert rows["Known Queries"] == (
        "1" if depth == 8 else "1 (partial coverage)" if depth == 3 else "Unknown"
    )
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        human = render_report(report, format)
        assert human.count("Recovery method") == 1 and "Stop reason" in human
        assert human.count("Safety Notice") == 1
        assert human.rfind("Safety Notice") > human.rfind("Introspection")
    assert len(seen) == count


def test_recovery_rows_are_endpoint_scoped_in_mixed_reports(monkeypatch):
    handler, _, _ = mock_recovery(SDL, depth=3)
    monkeypatch.setattr("httpx._client.HTTPTransport", lambda **_: httpx.MockTransport(handler))
    report = build_report(run_safe_execution_scan(TARGET))
    original = report.endpoints[0]
    other = replace(
        original,
        endpoint="http://127.0.0.1:9999/graphql",
        recovery=None,
        schema_retrieval_summary=None,
        schema_retrieval_status="retrieved",
    )
    mixed = replace(report, endpoints=(other, original))
    entries = next(s for s in technical_sections(mixed) if s.title == "Introspection").entries
    assert entries[0].title == other.endpoint and "Recovery method" not in dict(entries[0].details)
    assert (
        entries[1].title == TARGET
        and dict(entries[1].details)["Known Queries"] == "1 (partial coverage)"
    )
