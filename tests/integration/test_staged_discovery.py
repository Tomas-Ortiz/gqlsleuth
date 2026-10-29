"""Offline staged discovery, request accounting, worker bounds and retained reports."""

import json
from io import StringIO
from threading import Barrier, Event, Lock

import httpx
import pytest
from graphql import build_schema, introspection_from_schema
from rich.console import Console

from gqlsleuth.application.graphql_detection import (
    MINIMAL_TYPENAME_QUERY,
    discover_and_detect_graphql,
)
from gqlsleuth.application.introspection import introspect_detected_endpoints
from gqlsleuth.application.operation_analysis import analyze_schema_results
from gqlsleuth.application.query_generation import generate_analyzed_queries
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.application.schema_parsing import parse_introspection_schemas
from gqlsleuth.discovery.endpoint_candidates import (
    BUNDLED_ENDPOINT_PATHS,
    CORE_ENDPOINT_PATHS,
    EXTENDED_ENDPOINT_PATHS,
    generate_endpoint_candidates,
)
from gqlsleuth.domain.models import ConfidenceLevel, EvidenceType, ScanMode, Target
from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.infrastructure.redirect_consent import RedirectConsent
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.discovery_scope import discovery_scope_notes
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.rules.loader import load_bundled_rules


def detect(
    *,
    path=None,
    probable=False,
    post_only=False,
    target="https://example.com/",
    failures=(),
    mode=ScanMode.SAFE,
):
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        if request.method == "GET" and request.url.path in failures:
            raise httpx.ReadTimeout("offline failure")
        if request.method == "POST":
            assert json.loads(request.content) == {"query": MINIMAL_TYPENAME_QUERY}
        if request.url.path == path and (not post_only or request.method == "POST"):
            return httpx.Response(
                200,
                json={"errors": [{"message": "Must provide query string."}]}
                if probable
                else {"data": {"__typename": "Query"}},
            )
        return httpx.Response(200, json={"status": "generic REST"})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_and_detect_graphql(Target.parse(target), mode=mode, client=client)
    return result, seen


@pytest.mark.parametrize("mode", [ScanMode.SAFE, ScanMode.ACTIVE])
@pytest.mark.parametrize(
    "options,gets,posts",
    [
        ({"path": "/graphql"}, 1, 0),
        ({"path": "/api/graphql"}, 10, 9),
        ({"path": "/api/graphql", "probable": True}, 10, 9),
        ({"path": "/v3/api/graphql"}, 27, 26),
        ({}, 27, 27),
        ({"path": "/custom", "target": "https://example.com/custom"}, 1, 0),
        ({"path": "/___graphql"}, 11, 10),
        ({"path": "/___graphql", "probable": True}, 11, 10),
        ({"path": "/v3/api/graphql", "post_only": True}, 27, 27),
        ({"path": "/graphql", "post_only": True}, 1, 1),
        ({"path": "/api/graphql", "post_only": True}, 10, 10),
        ({"path": "/v3/api/graphql", "target": "https://example.com/v3/api/graphql"}, 1, 0),
    ],
)
def test_request_matrix_and_no_unattempted_evidence(options, gets, posts, mode):
    result, seen = detect(**options, mode=mode)
    assert sum(method == "GET" for method, _ in seen) == gets
    assert sum(method == "POST" for method, _ in seen) == posts
    assert len(seen) == len(set(seen))  # No retry or repeated candidate per method.
    candidates = generate_endpoint_candidates(result.discovery.target)
    attempted = tuple(p.candidate_url for p in result.discovery.probes)
    assert attempted == candidates[:gets]
    assert tuple(d.candidate_url for d in result.detections) == attempted
    assert tuple(e.endpoint for e in result.discovery.evidence) == attempted
    assert tuple(e.endpoint for e in result.confirmation_evidence) == attempted
    assert len(result.discovery.evidence) == len(result.confirmation_evidence) == gets
    qualified = [
        d
        for d in result.detections
        if d.confidence in {ConfidenceLevel.CONFIRMED, ConfidenceLevel.PROBABLE}
    ]
    assert len(qualified) == int("path" in options)
    if qualified:
        assert httpx.URL(qualified[0].candidate_url).path == options["path"]
        assert qualified[0].confidence is (
            ConfidenceLevel.PROBABLE if options.get("probable") else ConfidenceLevel.CONFIRMED
        )
    if gets <= 10:
        assert not any(path in EXTENDED_ENDPOINT_PATHS for _, path in seen) or gets == 1
    else:
        first_extended = next(
            i for i, (_, path) in enumerate(seen) if path in EXTENDED_ENDPOINT_PATHS
        )
        assert all(("POST", path) in seen[:first_extended] for path in CORE_ENDPOINT_PATHS)


def test_transport_failures_in_both_stages_are_isolated_without_post_retry():
    failed = ("/graphql", "/___graphql", "/api")
    result, seen = detect(path="/v3/api/graphql", failures=failed)
    assert len(result.detections) == 27
    for path in failed:
        assert ("GET", path) in seen and ("POST", path) not in seen
    assert sum(method == "POST" for method, _ in seen) == 23
    assert sum(d.confidence is ConfidenceLevel.CONFIRMED for d in result.detections) == 1


def test_failed_explicit_extended_candidate_is_not_retried_in_stage_b():
    result, seen = detect(target="https://example.com/v3/api/graphql")
    assert seen[:2] == [("GET", "/v3/api/graphql"), ("POST", "/v3/api/graphql")]
    assert len(seen) == len(set(seen)) == 54
    assert tuple(p.candidate_url for p in result.discovery.probes) == generate_endpoint_candidates(
        result.discovery.target
    )


@pytest.mark.parametrize(
    "payload,confidence",
    [
        ({"status": "ok", "query": "stored"}, ConfidenceLevel.NOT_DETECTED),
        ({"data": {"items": []}}, ConfidenceLevel.POSSIBLE),
        ("<html>GraphQL playground</html>", ConfidenceLevel.NOT_DETECTED),
    ],
)
def test_generic_200_does_not_stop_stages_or_trigger_introspection(payload, confidence):
    seen = []

    def handler(request):
        seen.append(request)
        return (
            httpx.Response(200, text=payload)
            if isinstance(payload, str)
            else httpx.Response(200, json=payload)
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_and_detect_graphql(
            Target.parse("https://example.com"), mode=ScanMode.SAFE, client=client
        )
        assert len(result.detections) == 27
        assert all(d.confidence is confidence for d in result.detections)
        introspection = introspect_detected_endpoints(result, client=client)
    assert len(seen) == 54
    assert not introspection.introspections
    assert not parse_introspection_schemas(introspection).schemas


def test_each_stage_reuses_four_workers_and_retains_order_despite_delays():
    groups = (CORE_ENDPOINT_PATHS[1:5], EXTENDED_ENDPOINT_PATHS[1:5])
    barriers = [Barrier(4, timeout=5) for _ in groups]
    completed = [Event() for _ in groups]
    lock = Lock()
    active = peak = 0
    order = []

    def handler(request):
        nonlocal active, peak
        if request.method == "GET":
            with lock:
                active += 1
                peak = max(peak, active)
            for i, paths in enumerate(groups):
                if request.url.path in paths:
                    barriers[i].wait()
                    if request.url.path == paths[0]:
                        assert completed[i].wait(5)
            with lock:
                order.append(request.url.path)
                active -= 1
            for i, paths in enumerate(groups):
                if request.url.path == paths[-1]:
                    completed[i].set()
        return httpx.Response(404)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_and_detect_graphql(
            Target.parse("https://example.com"), mode=ScanMode.SAFE, client=client
        )
    assert peak == 4 and active == 0
    for paths in groups:
        assert order.index(paths[-1]) < order.index(paths[0])
    assert (
        tuple(httpx.URL(p.candidate_url).path for p in result.discovery.probes)
        == BUNDLED_ENDPOINT_PATHS
    )


@pytest.mark.parametrize("stage", ["core", "extended"])
def test_cancelled_stage_releases_workers_and_sends_no_destination_request(stage):
    seen = []
    redirect_paths = CORE_ENDPOINT_PATHS[1:] if stage == "core" else EXTENDED_ENDPOINT_PATHS[1:]

    def confirm(notice):
        raise KeyboardInterrupt

    def handler(request):
        seen.append((request.method, request.url.host, request.url.path))
        assert request.url.host == "example.com"
        if request.url.path in redirect_paths:
            return httpx.Response(307, headers={"location": "https://other.example/graphql"})
        return httpx.Response(404)

    with (
        HttpClient(
            HttpClientSettings(redirect_consent=RedirectConsent(confirm)),
            transport=httpx.MockTransport(handler),
        ) as client,
        pytest.raises(KeyboardInterrupt),
    ):
        discover_and_detect_graphql(
            Target.parse("https://example.com"), mode=ScanMode.SAFE, client=client
        )
    if stage == "core":
        assert not any(path in EXTENDED_ENDPOINT_PATHS for _, _, path in seen)


@pytest.mark.parametrize("approve", [None, False, True])
def test_extended_redirects_keep_consent_and_context_credentials_isolated(approve):
    seen, notices = [], []
    consent = RedirectConsent(
        (lambda notice: notices.append(notice) or approve) if approve is not None else None
    )

    def handler(request):
        seen.append(request)
        if request.url.host == "other.example":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        if request.url.path == EXTENDED_ENDPOINT_PATHS[0]:
            return httpx.Response(307, headers={"location": "https://other.example/graphql"})
        return httpx.Response(404)

    for secret in ("FAKE_CONTEXT_A", "FAKE_CONTEXT_B"):
        start = len(seen)
        with HttpClient(
            HttpClientSettings(
                custom_headers=(("Authorization", secret),), redirect_consent=consent
            ),
            transport=httpx.MockTransport(handler),
        ) as client:
            result = discover_and_detect_graphql(
                Target.parse("https://example.com"), mode=ScanMode.SAFE, client=client
            )
        redirected = [r for r in seen[start:] if r.url.host == "other.example"]
        assert len(redirected) == (1 if approve else 0)
        assert all(r.headers["authorization"] == secret for r in seen[start:])
        assert all(httpx.URL(d.candidate_url).host == "example.com" for d in result.detections)
        assert len(result.discovery.probes) == (11 if approve else 27)
    assert len(notices) == (0 if approve is None else 1)


def test_extended_endpoint_continues_safe_pipeline_and_reports_actual_bounded_scope(monkeypatch):
    seen = []
    schema = introspection_from_schema(build_schema("type Query { ping: String }"))

    def handler(request):
        seen.append(request)
        if request.url.path != "/v3/api/graphql":
            return httpx.Response(404)
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        query = json.loads(request.content)["query"]
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(
                200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
            )
        if query == FULL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": schema})
        assert query == "query {\n  ping\n}"
        return httpx.Response(200, json={"data": {"ping": "ok"}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        detection = discover_and_detect_graphql(
            Target.parse("https://example.com/"), mode=ScanMode.SAFE, client=client
        )
        parsed = parse_introspection_schemas(
            introspect_detected_endpoints(detection, client=client)
        )
        generated = generate_analyzed_queries(analyze_schema_results(parsed, load_bundled_rules()))
        result = execute_generated_queries(generated, client=client)
    assert len(seen) == 56  # 27 GET + 26 confirmation POST + 2 introspection + 1 SAFE Query.
    assert len(result.executions) == 1 and result.executions[0].status.value == "success"
    report = build_report(result)
    canonical = render_report(report, ReportFormat.JSON)
    data = json.loads(canonical)
    assert data["report_schema_version"] == 2
    candidates = [e for e in data["evidence"] if e["evidence_type"] == "endpoint_candidate"]
    assert len(candidates) == 27
    assert tuple(e["endpoint"] for e in candidates) == generate_endpoint_candidates(report.target)
    assert not any(e.evidence_type is EvidenceType.MUTATION_EXECUTION for e in report.evidence)
    notes = discovery_scope_notes(report.target, report.evidence)
    assert "Showing 10 of 27 additional discovery candidates" in notes[1]
    assert "/v3/api/graphql" not in notes[1]  # Bounded list; full evidence remains in JSON.

    def unexpected(*args, **kwargs):
        pytest.fail("Presentation must not make requests")

    monkeypatch.setattr(HttpClient, "send", unexpected)
    for width in (45, 100):
        output = StringIO()
        render_completed_assessment(
            Console(file=output, width=width, color_system=None, theme=CONSOLE_THEME), result
        )
        text = " ".join(output.getvalue().split())
        assert "Showing 10 of 27 additional discovery candidates" in text
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "Showing 10 of 27 additional discovery candidates" in text
        assert text.rfind("Safety Notice") > text.rfind("GraphQL Discovery and Confirmation")
        assert "\x1b[" not in text
    assert render_report(report, ReportFormat.JSON) == canonical
