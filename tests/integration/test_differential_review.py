"""Real SAFE pipelines over the controlled local fixture via offline MockTransport."""

import json
import re
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from html import unescape
from io import BytesIO, StringIO, TextIOWrapper

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

import gqlsleuth.application.differential_review as differential
import gqlsleuth.cli as cli
from fixtures.phase15_target import response_for
from gqlsleuth.application.scan_configuration import map_auth_context_inputs
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.differential import DifferenceKind, NamedAuthContext
from gqlsleuth.domain.exceptions import HttpConfigurationError, RuleConfigurationError
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_differential
from gqlsleuth.presentation.differential import present_differential
from gqlsleuth.reporting.differential import build_differential_report, differential_sections
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report

TARGET = "https://example.com/graphql"
CANARIES = ("PHASE15_CONTEXT_A_SECRET", "PHASE15_CONTEXT_B_SECRET")
ENTRIES = [
    "public",
    "empleado=X-Test-Context: empleado",
    "empleado=Authorization: Bearer " + CANARIES[0],
    "empleado=X-Tenant-ID: " + CANARIES[0],
    "soporte=X-Test-Context: soporte",
    "soporte=Cookie: session=" + CANARIES[1],
    "soporte=X-API-Key: " + CANARIES[1],
]


@pytest.fixture
def controlled(monkeypatch, tmp_path):
    requests = []
    settings = []
    clients = []
    original_scan = differential.run_safe_execution_scan

    def handler(request):
        requests.append(request)
        payload = json.loads(request.content) if request.method == "POST" else None
        status, body = response_for(request.method, request.url.path, request.headers, payload)
        return (
            httpx.Response(status, json=body)
            if isinstance(body, dict)
            else httpx.Response(status, text=body)
        )

    def transport(**configuration):
        assert configuration["trust_env"] is False

        def send(request):
            clients.append(configuration)
            return handler(request)

        return httpx.MockTransport(send)

    def scan(*args, **kwargs):
        settings.append(kwargs["http_settings"])
        return original_scan(*args, **kwargs)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    monkeypatch.setattr(differential, "run_safe_execution_scan", scan)
    monkeypatch.setattr(
        OllamaClient, "interpret", lambda *args: pytest.fail("Differential AI call")
    )
    monkeypatch.chdir(tmp_path)
    return requests, settings, clients


def run(entries=ENTRIES, **kwargs):
    return differential.run_differential_scan(
        TARGET, contexts=map_auth_context_inputs(entries), **kwargs
    )


def test_three_contexts_full_safe_pipeline_pairs_and_evidence(controlled, monkeypatch):
    result = run()
    assert [context.name for context in result.contexts] == ["public", "empleado", "soporte"]
    assert [(pair.context_a, pair.context_b) for pair in result.pairs] == [
        ("public", "empleado"),
        ("public", "soporte"),
        ("empleado", "soporte"),
    ]
    assert result.pairs[0].candidates[0].kind is DifferenceKind.INTROSPECTION_DIFFERENCE
    assert result.pairs[0].limitations and not any(
        item.kind is DifferenceKind.OPERATION_VISIBILITY_DIFFERENCE
        for item in result.pairs[0].candidates
    )
    pair = result.pairs[-1]
    visibility = [
        item
        for item in pair.candidates
        if item.kind is DifferenceKind.OPERATION_VISIBILITY_DIFFERENCE
    ]
    assert [(item.operation_kind, item.operation_name) for item in visibility] == [
        (OperationKind.QUERY, "internalUsers"),
        (OperationKind.MUTATION, "updatePaste"),
    ]
    assert all(item.left.state == "absent" and item.right.state == "visible" for item in visibility)
    outcomes = {
        item.operation_name: item
        for item in pair.candidates
        if item.kind is DifferenceKind.EXECUTION_OUTCOME_DIFFERENCE
    }
    assert outcomes["profile"].left.state == "http_error"
    assert outcomes["profile"].left.http_status == 403
    assert outcomes["profile"].right.state == "success"
    assert outcomes["account"].left.state == "graphql_error"
    assert outcomes["account"].right.state == "success"
    assert all(item.left.evidence_ids and item.right.evidence_ids for item in pair.candidates)
    for context in result.contexts:
        assert context.scan is not None
        ids = {item.evidence_id for item in context.scan.evidence}
        for compared in result.pairs:
            for candidate in compared.candidates:
                if compared.context_a == context.name:
                    assert set(candidate.left.evidence_ids) <= ids
                if compared.context_b == context.name:
                    assert set(candidate.right.evidence_ids) <= ids
        assert not any(
            item.evidence_type is EvidenceType.MUTATION_EXECUTION for item in context.scan.evidence
        )
    assert len(result.evidence) == sum(len(context.scan.evidence) for context in result.contexts)
    assert len(controlled[1]) == len({id(item) for item in controlled[1]}) == 3
    before = deepcopy(result)
    count = len(controlled[0])
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Comparison requested HTTP"))
    assert differential.compare_context_scans(result.target, result.contexts) == result
    assert len(controlled[0]) == count and result == before


@pytest.mark.parametrize("verbose", [False, True])
def test_cli_reports_secret_isolation_transport_and_no_ai(controlled, tmp_path, verbose):
    options = [value for entry in ENTRIES for value in ("--auth-context", entry)]
    output = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            *options,
            "--timeout",
            "4.5",
            "--no-verify-tls",
            "--proxy",
            "http://localhost:8080",
            "-f",
            "json,markdown,html",
            "-o",
            "reports",
            *(["-v"] if verbose else []),
        ],
    )
    assert output.exit_code == 0, output.exception
    assert "Authorization Differential Review" in output.stdout
    assert "Pairs compared: 3" in output.stdout and "Zero differential Mutations" in output.stdout
    assert "Select Mutations" not in output.stdout and "AI-Assisted" not in output.stdout
    for request in controlled[0]:
        name = request.headers.get("x-test-context", "public")
        headers = str(request.headers)
        if name == "public":
            assert all(
                key not in request.headers
                for key in ("authorization", "cookie", "x-api-key", "x-tenant-id")
            )
        elif name == "empleado":
            assert CANARIES[0] in headers and CANARIES[1] not in headers
            assert request.headers["authorization"] == "Bearer " + CANARIES[0]
            assert "cookie" not in request.headers
        else:
            assert CANARIES[1] in headers and CANARIES[0] not in headers
            assert request.headers["cookie"] == "session=" + CANARIES[1]
            assert "authorization" not in request.headers
        assert set(request.extensions["timeout"].values()) == {4.5}
        assert not request.content or not json.loads(request.content)["query"].startswith(
            "mutation"
        )
    assert all(
        not configuration["verify"] and configuration["proxy"] for configuration in controlled[2]
    )
    files = tuple((tmp_path / "reports").iterdir())
    assert len(files) == 3
    for text in (output.output, *(path.read_text(encoding="utf-8") for path in files)):
        assert all(secret not in text for secret in CANARIES)
        assert "Broken Access Control" not in text and "IDOR" not in text
    canonical = json.loads(next(path for path in files if path.suffix == ".json").read_text())
    assert canonical["mode"] == "safe" and len(canonical["contexts"]) == 3
    assert "headers" not in canonical["contexts"][0]
    assert "ai_interpretation" not in canonical


def test_arbitrary_labels_and_endpoint_access_difference(controlled):
    result = run(["tenant-37=X-Test-Context: closed", "support.Y=X-Test-Context: soporte"])
    assert [(item.context_a, item.context_b) for item in result.pairs] == [
        ("tenant-37", "support.Y")
    ]
    endpoint = result.pairs[0].candidates[0]
    assert endpoint.kind is DifferenceKind.ENDPOINT_ACCESS_DIFFERENCE
    assert endpoint.left.state == "not_detected" and endpoint.right.state == "confirmed"
    assert result.pairs[0].limitations


def test_context_failures_do_not_cancel_later_scans_or_leak_errors(controlled, monkeypatch):
    original = differential.run_safe_execution_scan

    def scan(*args, **kwargs):
        if dict(kwargs["http_settings"].custom_headers).get("X-Test-Context") == "empleado":
            raise RuleConfigurationError(CANARIES[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(differential, "run_safe_execution_scan", scan)
    result = run()
    assert result.contexts[1].scan is None
    assert result.contexts[1].error_code == "RuleConfigurationError"
    assert result.contexts[2].scan is not None
    assert all(pair.limitations for pair in result.pairs)
    assert CANARIES[0] not in repr(result)


@pytest.mark.parametrize(
    "mode,base",
    [
        (ScanMode.ACTIVE, HttpClientSettings()),
        (ScanMode.SAFE, HttpClientSettings(custom_headers=(("X-Key", CANARIES[0]),))),
    ],
)
def test_application_gate_cannot_be_bypassed(controlled, mode, base):
    with pytest.raises(HttpConfigurationError):
        run(mode=mode, http_settings=base)
    assert not controlled[0]


def test_programmatic_headers_validated_before_first_context(controlled):
    with pytest.raises(HttpConfigurationError):
        differential.run_differential_scan(
            TARGET,
            contexts=(
                NamedAuthContext("a"),
                NamedAuthContext("b", (("X-Key", CANARIES[0] + "\r\n"),)),
            ),
        )
    assert not controlled[0]


def test_report_order_and_rendering_are_local_and_leave_evidence_unchanged(controlled, monkeypatch):
    result = run()
    before = deepcopy(result)
    report = build_differential_report(result, generated_at=datetime(2026, 9, 14, tzinfo=UTC))
    assert differential_sections(report)[-1].title == "Safety Notice"
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Report requested HTTP"))
    canonical = render_report(report, ReportFormat.JSON)
    assert canonical == render_report(report, ReportFormat.JSON)
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format)
        assert rendered.count("Safety Notice") == 1
        assert "Authorization Differential Review" in rendered
        tail = rendered.split("Safety Notice", 1)[1]
        assert "Operation" not in tail and "Context:" not in tail
        assert "GRAPHQL_ERROR" in rendered or "GRAPHQL\\_ERROR" in rendered
        assert "not proof of an authorization weakness" in rendered
    assert result == before


def test_missing_execution_and_non_equivalent_generated_requests_are_limitations(controlled):
    result = run(ENTRIES[1:])
    first, second = result.contexts
    changed = tuple(
        replace(item, generated_query=replace(item.generated_query, variables={"id": "different"}))
        for item in second.scan.executions
    )
    second = replace(second, scan=replace(second.scan, executions=changed[:-1]))
    compared = differential.compare_context_scans(result.target, (first, second))
    assert any("equivalent" in item.reason for item in compared.pairs[0].limitations)
    assert any("unavailable" in item.reason for item in compared.pairs[0].limitations)


def test_compact_and_narrow_console(controlled):
    result = run()
    stream = StringIO()
    render_differential(Console(file=stream, width=45, theme=CONSOLE_THEME), result)
    assert max(map(len, stream.getvalue().splitlines())) <= 45
    assert len(stream.getvalue().splitlines()) < 100


@pytest.mark.parametrize("multiple_endpoints", [False, True])
def test_candidate_summary_shared_by_console_and_human_reports(controlled, multiple_endpoints):
    result = run()
    other_endpoint = "https://example.com/other/graphql"
    if multiple_endpoints:
        pair = result.pairs[-1]
        pair = replace(
            pair,
            candidates=(replace(pair.candidates[0], endpoint=other_endpoint), *pair.candidates[1:]),
        )
        result = replace(result, pairs=(*result.pairs[:-1], pair))
    before = deepcopy(result)
    request_count = len(controlled[0])
    table = present_differential(result.pairs)
    assert len(table.rows) == 6
    assert ("Endpoint" in table.headers) is multiple_endpoints
    assert all("https://" not in row[2] and "Endpoint:" not in row[2] for row in table.rows)
    assert table.rows[0][:2] == ("public <-> empleado", "Introspection")
    assert any(
        row[2] == "query profile: HTTP_ERROR <-> SUCCESS (HTTP 403 <-> 200)" for row in table.rows
    )
    if multiple_endpoints:
        assert table.endpoints == (TARGET, other_endpoint)
        assert [row[3] for row in table.rows] == [
            candidate.endpoint for pair in result.pairs for candidate in pair.candidates
        ]
    for verbose in (False, True):
        stream = StringIO()
        render_differential(
            Console(file=stream, width=240, theme=CONSOLE_THEME), result, verbose=verbose
        )
        output = stream.getvalue()
        for row in table.rows:
            assert row[2] in output
        if multiple_endpoints:
            assert "Endpoint" in output and other_endpoint in output
        else:
            assert f"Target endpoint: {TARGET}" in output
            assert output.count(TARGET) == 1
    report = build_differential_report(result)
    section = differential_sections(report)[1]
    assert section.table_headers == table.headers and section.table_rows == table.rows
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format)
        if format is ReportFormat.HTML:
            summary = rendered.split("<h2>Authorization Differential Review</h2>")[1]
            summary = summary.split("</section>")[0]
            candidate_table = re.findall(r"<table>.*?</table>", summary, re.S)[-1]
            rows = re.findall(r"<tr>(.*?)</tr>", candidate_table, re.S)[1:]
            cells = tuple(
                tuple(unescape(value) for value in re.findall(r"<td>(.*?)</td>", row))
                for row in rows
            )
            assert cells == table.rows
            assert "<h2>Context: empleado</h2>" in rendered
            assert "<h2>empleado ↔ soporte</h2>" in rendered
        else:
            summary = rendered.split("## Authorization Differential Review\n")[1]
            summary = summary.split("\n## ")[0]
            assert "| Contexts | Difference | Operation / observed states |" in summary
            for row in table.rows:
                assert "| " + " | ".join(row) + " |" in unescape(summary).replace("\\", "")
            assert "## Context: empleado" in rendered
            assert "## empleado ↔ soporte" in rendered
            assert all(line == line.rstrip() for line in summary.splitlines())
        if not multiple_endpoints:
            assert unescape(summary).replace("\\", "").count(TARGET) == 1
    assert result == before and len(controlled[0]) == request_count


def test_human_evidence_references_are_secondary_and_json_keeps_exact_ids(controlled):
    result = run()
    report = build_differential_report(result)
    canonical = render_report(report, ReportFormat.JSON)
    pairs = json.loads(canonical)["pairs"]
    html = render_report(report, ReportFormat.HTML)
    markdown = render_report(report, ReportFormat.MARKDOWN)
    collapsed = re.findall(
        r"<details>\s*<summary>Evidence references</summary>(.*?)</details>", html, re.S
    )
    assert len(collapsed) == sum(len(pair.candidates) for pair in result.pairs)
    visible_html = re.sub(r"<details>.*?</details>", "", html, flags=re.S)
    for pair, serialized_pair in zip(result.pairs, pairs, strict=True):
        for candidate, serialized in zip(
            pair.candidates, serialized_pair["candidates"], strict=True
        ):
            for side in ("left", "right"):
                ids = [str(value) for value in getattr(candidate, side).evidence_ids]
                assert serialized[side]["evidence_ids"] == ids
                for value in ids:
                    assert any(value in block for block in collapsed)
                    assert value not in visible_html and value not in markdown
    assert render_report(report, ReportFormat.JSON) == canonical
    assert re.findall(r"<h2>(.*?)</h2>", html)[-1] == "Safety Notice"
    assert re.findall(r"^## (.+)$", markdown, re.M)[-1] == "Safety Notice"
    assert html.count("Safety Notice") == markdown.count("Safety Notice") == 1


def test_legacy_windows_console_can_render_differential_pairs(controlled):
    result = run()
    buffer = BytesIO()
    with TextIOWrapper(buffer, encoding="cp1252") as stream:
        render_differential(
            Console(file=stream, width=80, theme=CONSOLE_THEME), result, verbose=True
        )
        stream.flush()
        assert "empleado <-> soporte" in buffer.getvalue().decode("cp1252")


def test_normalized_network_failure_remains_partial_result_and_other_context_runs(monkeypatch):
    def handler(request):
        if request.headers.get("x-test-context") == "empleado":
            raise httpx.ConnectError(CANARIES[0], request=request)
        payload = json.loads(request.content) if request.method == "POST" else None
        status, body = response_for(request.method, request.url.path, request.headers, payload)
        return (
            httpx.Response(status, json=body)
            if isinstance(body, dict)
            else httpx.Response(status, text=body)
        )

    monkeypatch.setattr(
        "httpx._client.HTTPTransport", lambda **kwargs: httpx.MockTransport(handler)
    )
    result = run(ENTRIES[1:])
    assert all(context.scan is not None for context in result.contexts)
    assert not result.contexts[0].scan.executions
    assert result.contexts[1].scan.executions
    assert result.pairs[0].candidates[0].left.state == "HttpTransportError"
    assert CANARIES[0] not in repr(result)


def test_cookie_jars_never_cross_context_boundaries(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        name = request.headers.get("x-test-context", "public")
        payload = json.loads(request.content) if request.method == "POST" else None
        status, body = response_for(request.method, request.url.path, request.headers, payload)
        headers = {"Set-Cookie": "server_session=" + CANARIES[0]} if name == "empleado" else {}
        return (
            httpx.Response(status, headers=headers, json=body)
            if isinstance(body, dict)
            else httpx.Response(status, headers=headers, text=body)
        )

    monkeypatch.setattr(
        "httpx._client.HTTPTransport", lambda **kwargs: httpx.MockTransport(handler)
    )
    run(
        [
            "arbitrary-a=X-Test-Context: empleado",
            "no-headers",
            "arbitrary-b=X-Test-Context: soporte",
        ]
    )
    for request in seen:
        if request.headers.get("x-test-context") != "empleado":
            assert "cookie" not in request.headers
    assert any("cookie" in request.headers for request in seen)


def test_context_redirects_keep_same_origin_and_strip_cross_origin(controlled):
    from gqlsleuth.infrastructure.http import HttpRequest

    seen = []
    for context in map_auth_context_inputs(ENTRIES):
        current = []

        def handler(request, current=current):
            current.append(request)
            destinations = {
                "https://example.com/start": "https://example.com/next",
                "https://example.com/next": "https://other.example.com/end",
                "https://other.example.com/end": "https://example.com/back",
            }
            if str(request.url) in destinations:
                return httpx.Response(302, headers={"Location": destinations[str(request.url)]})
            return httpx.Response(200)

        with HttpClient(
            HttpClientSettings(custom_headers=context.headers),
            transport=httpx.MockTransport(handler),
        ) as client:
            client.send(HttpRequest(method="GET", url="https://example.com/start"))
        for request in current[:2]:
            for name, value in context.headers:
                assert request.headers[name] == value
        for request in current[2:]:
            assert all(name not in request.headers for name, _ in context.headers)
            assert "authorization" not in request.headers and "cookie" not in request.headers
        seen.extend(current)
    assert len(seen) == 12


def test_raw_body_changes_do_not_create_differences_and_human_views_omit_echoes(controlled):
    result = run(ENTRIES[1:])
    original = result.contexts[0]
    echoed = tuple(
        replace(
            item,
            response=item.response.model_copy(
                update={
                    "body": json.dumps({"data": CANARIES[0]}).encode(),
                    "headers": {"x-echo": CANARIES[0]},
                }
            )
            if item.response
            else None,
        )
        for item in original.scan.executions
    )
    second = replace(original, name="other-label", scan=replace(original.scan, executions=echoed))
    result = differential.compare_context_scans(result.target, (original, second))
    assert not result.pairs[0].candidates
    report = build_differential_report(result)
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        assert CANARIES[0] not in render_report(report, format)
    for verbose in (False, True):
        stream = StringIO()
        render_differential(Console(file=stream, theme=CONSOLE_THEME), result, verbose=verbose)
        assert CANARIES[0] not in stream.getvalue()
    # Existing retained facts remain untouched, rather than redacted to meet display requirements.
    assert CANARIES[0].encode() in second.scan.executions[0].response.body


def test_safe_requests_match_single_context_pipeline_exactly(controlled):
    result = run(ENTRIES[1:])
    requests = controlled[0]
    for context in map_auth_context_inputs(ENTRIES[1:]):
        key = dict(context.headers)["X-Test-Context"]
        before = [
            (request.method, str(request.url), request.content)
            for request in requests
            if request.headers.get("x-test-context") == key
        ]
        start = len(requests)
        single = differential.run_safe_execution_scan(
            TARGET, http_settings=HttpClientSettings(custom_headers=context.headers)
        )
        assert before == [
            (request.method, str(request.url), request.content) for request in requests[start:]
        ]
        retained = next(item.scan for item in result.contexts if item.name == context.name)
        assert [(item.status, item.attempted) for item in single.executions] == [
            (item.status, item.attempted) for item in retained.executions
        ]
