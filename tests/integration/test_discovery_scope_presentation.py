"""Actual mocked discovery drives disclosure without changing requests or canonical facts."""

import json
import re
from html import unescape
from io import StringIO
from urllib.parse import urlsplit

import httpx
import pytest
from graphql import build_schema, introspection_from_schema
from rich.console import Console

from gqlsleuth.application.graphql_detection import discover_and_detect_graphql
from gqlsleuth.application.introspection import introspect_detected_endpoints
from gqlsleuth.application.operation_analysis import analyze_schema_results
from gqlsleuth.application.query_generation import generate_analyzed_queries
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.application.schema_parsing import parse_introspection_schemas
from gqlsleuth.discovery.endpoint_candidates import BUNDLED_ENDPOINT_PATHS
from gqlsleuth.domain.models import ConfidenceLevel, Evidence, EvidenceType, ScanMode, Target
from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_pre_active_context
from gqlsleuth.presentation.discovery_scope import discovery_scope_notes
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import technical_sections
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.rules.loader import load_bundled_rules


def scan(target_url, *, mode=ScanMode.SAFE, retained_path="/graphql", redirect=False):
    requests = []
    schema = introspection_from_schema(build_schema("type Query { health: String }"))

    def handler(request):
        requests.append((request.method, str(request.url)))
        if redirect and request.url.host == "example.com":
            return httpx.Response(302, headers={"Location": "https://other.example.net/graphql"})
        retained_paths = (retained_path,) if isinstance(retained_path, str) else retained_path
        if request.url.path not in retained_paths or request.url.query:
            return httpx.Response(404, json={"message": "Not found"})
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        query = json.loads(request.content)["query"]
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(
                200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
            )
        if query == FULL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": schema})
        return httpx.Response(200, json={"data": {"health": "ok"}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        detection = discover_and_detect_graphql(Target.parse(target_url), mode=mode, client=client)
        if redirect:
            return detection, requests
        schemas = parse_introspection_schemas(
            introspect_detected_endpoints(detection, client=client)
        )
        generation = generate_analyzed_queries(
            analyze_schema_results(schemas, load_bundled_rules())
        )
        return execute_generated_queries(generation, client=client), requests


@pytest.mark.parametrize("mode", [ScanMode.SAFE, ScanMode.ACTIVE])
@pytest.mark.parametrize(
    "target_url,origin,supplied,expanded",
    [
        ("https://example.com/", "https://example.com", None, True),
        ("https://example.com/custom/path", "https://example.com", "/custom/path", True),
        ("https://example.com/graphql", "https://example.com", "/graphql", False),
        ("https://EXAMPLE.com:443/graphql/", "https://example.com", "/graphql", False),
        ("https://example.com:8443/custom", "https://example.com:8443", "/custom", True),
        ("http://example.com:80/custom", "http://example.com", "/custom", True),
        ("https://example.com/graphql/?x=1", "https://example.com", "/graphql?x=1", True),
        ("https://example.com/?x=1", "https://example.com", None, True),
    ],
)
def test_actual_scope_across_console_reports_and_unchanged_scan_facts(
    target_url, origin, supplied, expanded, mode, monkeypatch
):
    result, requests = scan(target_url, mode=mode)
    report = build_report(result)
    before = render_report(report, ReportFormat.JSON)
    evidence_before = result.evidence
    request_before = tuple(requests)
    expected = (
        tuple(
            dict.fromkeys([origin + supplied] + [origin + path for path in BUNDLED_ENDPOINT_PATHS])
        )
        if supplied and expanded
        else (origin + (supplied or "/graphql"),)
    )
    candidates = tuple(
        item.endpoint
        for item in result.evidence
        if item.evidence_type is EvidenceType.ENDPOINT_CANDIDATE
    )
    assert candidates == expected
    confirmations = tuple(
        item for item in result.evidence if item.evidence_type is EvidenceType.GRAPHQL_CONFIRMATION
    )
    assert tuple(item.endpoint for item in confirmations) == expected
    assert sum(item.confidence is ConfidenceLevel.CONFIRMED for item in confirmations) == 1
    # Each non-GraphQL candidate gets GET + detection POST; the retained candidate
    # gets GET + minimal/full introspection + one SAFE Query. Presentation adds none.
    assert len(requests) == 2 * (len(expected) - 1) + 4
    assert requests[0] == ("GET", expected[0])
    assert [url for method, url in requests if method == "POST" and url != origin + "/graphql"] == [
        url for url in expected if url != origin + "/graphql"
    ]
    assert {urlsplit(url).netloc for _, url in requests} == {urlsplit(origin).netloc}
    assert {urlsplit(url).scheme for _, url in requests} == {urlsplit(origin).scheme}

    def unexpected(*args, **kwargs):
        pytest.fail("Presentation attempted HTTP")

    monkeypatch.setattr(HttpClient, "send", unexpected)
    for verbose, width in ((False, 100), (True, 100), (False, 45)):
        output = StringIO()
        render_completed_assessment(
            Console(file=output, width=width, theme=CONSOLE_THEME), result, verbose=verbose
        )
        text = " ".join(output.getvalue().split())
        assert ("Additional same-origin paths checked:" in text) is expanded
        assert "GraphQL endpoint:" in text
        assert origin + "/graphql" in text.replace(" ", "")
        if expanded:
            assert "redirects are followed" in text
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = unescape(render_report(report, format))
        if format is ReportFormat.MARKDOWN:
            text = re.sub(r"\\([^\w\s])", r"\1", text)
        assert ("Additional same-origin paths checked:" in text) is expanded
        if expanded:
            assert "Retained GraphQL endpoints" in text
            assert origin + "/graphql" in text
            assert "scheme, host and effective port" in text
            assert "may lead to another origin" in text
        assert text.rfind("Safety Notice") > text.rfind("GraphQL Discovery and Confirmation")
    scope = discovery_scope_notes(report.target, report.evidence)
    if supplied is None:
        assert "origin root" in scope[0] and "root itself was not probed" in scope[0]
        assert scope[1] == "Additional same-origin paths checked: /graphql."
    if mode is ScanMode.ACTIVE:
        output = StringIO()
        render_pre_active_context(Console(file=output, width=180, theme=CONSOLE_THEME), result)
        assert ("Additional same-origin paths checked:" in output.getvalue()) is expanded
    assert render_report(report, ReportFormat.JSON) == before
    assert json.loads(before)["report_schema_version"] == 2
    assert "discovery_scope" not in before
    assert result.evidence == evidence_before
    assert tuple(requests) == request_before


def test_explicit_graphql_can_expand_when_first_candidate_is_not_detected():
    result, _ = scan("https://example.com/graphql", retained_path="/api/graphql")
    report = build_report(result)
    notes = discovery_scope_notes(report.target, report.evidence)
    assert "beyond the supplied path /graphql" in notes[0]
    assert notes[1].startswith("Additional same-origin paths checked: /api/graphql, /gql,")
    discovery = next(
        s for s in technical_sections(report) if s.title == "GraphQL Discovery and Confirmation"
    )
    assert dict(discovery.rows)["Retained GraphQL endpoints"] == "https://example.com/api/graphql"


def test_cross_origin_redirect_is_not_described_as_same_origin_traffic():
    detection, requests = scan("https://example.com/", redirect=True)
    assert requests == [
        ("GET", "https://example.com/graphql"),
        ("GET", "https://other.example.net/graphql"),
    ]
    assert detection.discovery.probes[0].response.final_url == "https://other.example.net/graphql"
    assert detection.detections[0].candidate_url == "https://example.com/graphql"
    notes = discovery_scope_notes(detection.discovery.target, detection.evidence)
    assert notes[1] == "Additional same-origin paths checked: /graphql."
    assert "candidate URLs; HTTP redirects are followed and may lead to another origin" in notes[2]


@pytest.mark.parametrize("retained_paths", [("/graphql", "/api/graphql"), ()])
def test_retained_endpoints_exclude_not_detected_candidates(retained_paths):
    result, _ = scan("https://example.com/custom", retained_path=retained_paths)
    report = build_report(result)
    discovery = next(
        s for s in technical_sections(report) if s.title == "GraphQL Discovery and Confirmation"
    )
    assert dict(discovery.rows)["Retained GraphQL endpoints"] == (
        ", ".join("https://example.com" + path for path in retained_paths) or "None"
    )
    assert dict(discovery.rows)["Supplied target"] == "https://example.com/custom"


def test_disclosure_uses_recorded_candidates_only_and_bounds_duplicate_free_list():
    target = Target.parse("https://example.com/custom")
    assert discovery_scope_notes(target, ()) == ()
    evidence = tuple(
        Evidence(
            evidence_type=EvidenceType.ENDPOINT_CANDIDATE,
            target=target,
            endpoint=f"https://example.com/path{i}",
            source="fixture",
            summary="Recorded GET attempt.",
        )
        for i in range(12)
    )
    notes = discovery_scope_notes(target, evidence + evidence)
    assert notes[1].count("/path0") == 1
    assert "/path9" in notes[1] and "/path10" not in notes[1]
    assert "Showing 10 of 12 additional discovery candidates" in notes[1]
    # Confirmation evidence alone must never imply an extra discovery GET.
    assert (
        discovery_scope_notes(
            target,
            tuple(
                item.model_copy(update={"evidence_type": EvidenceType.GRAPHQL_CONFIRMATION})
                for item in evidence
            ),
        )
        == ()
    )
