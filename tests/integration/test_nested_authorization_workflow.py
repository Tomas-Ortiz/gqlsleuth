"""Full SAFE pipelines and nested probes over an offline controlled target."""

import base64
import json
from dataclasses import replace
from io import StringIO

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from fixtures.phase19_target import is_nested, response_for
from gqlsleuth import cli
from gqlsleuth.application.differential_review import run_differential_scan
from gqlsleuth.application.nested_authorization import (
    compare_nested_outcomes,
    execute_nested_authorization,
    prepare_nested_authorization,
)
from gqlsleuth.application.scan_configuration import map_auth_context_inputs
from gqlsleuth.domain.differential import NamedAuthContext
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.nested_authorization import NestedDifference, NestedOutcome
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.nested_authorization import render_nested_authorization
from gqlsleuth.reporting.differential import build_differential_report, differential_sections
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report

TARGET = "https://example.com/graphql"
CANARIES = ("PHASE19_CONTEXT_A_SECRET", "PHASE19_CONTEXT_B_SECRET", "PHASE19_CONTEXT_C_SECRET")
ENTRIES = [
    "cliente=X-Test-Context: alpha",
    "cliente=Authorization: Bearer " + CANARIES[0],
    "soporte=X-Test-Context: beta",
    "soporte=Cookie: session=" + CANARIES[1],
    "arbitrary=X-Test-Context: gamma",
    "arbitrary=X-API-Key: " + CANARIES[2],
]


@pytest.fixture
def controlled(monkeypatch):
    requests, sessions = [], []

    def transport(**configuration):
        assert configuration["trust_env"] is False
        session = []
        sessions.append(session)

        def handle(request):
            payload = json.loads(request.content) if request.method == "POST" else None
            requests.append((request, payload))
            session.append((request, payload))
            status, body = response_for(request.method, request.url.path, request.headers, payload)
            return httpx.Response(
                status, json=body, headers={"Set-Cookie": "SERVER_COOKIE=test-only; Path=/"}
            )

        return httpx.MockTransport(handle)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    monkeypatch.setattr(OllamaClient, "interpret", lambda *args: pytest.fail("Differential AI"))
    return requests, sessions


def run(enabled=False, entries=ENTRIES, **kwargs):
    return run_differential_scan(
        TARGET, contexts=map_auth_context_inputs(entries), nested_auth_review=enabled, **kwargs
    )


def test_exact_baseline_sequence_budgets_secrets_and_fresh_sessions(controlled):
    requests, sessions = controlled
    ordinary = run()
    before = [(request.method, str(request.url), payload) for request, payload in requests]
    assert ordinary.nested_authorization_review is None
    requests.clear()
    sessions.clear()
    result = run(True, http_settings=HttpClientSettings(timeout_seconds=3))
    nested = result.nested_authorization_review
    assert [(r.method, str(r.url), p) for r, p in requests[: len(before)]] == before
    probes = [(r, p) for r, p in requests if is_nested(p)]
    assert len(probes) == nested.request_count == len(nested.evidence) == 9
    assert len(nested.candidates) == 3 and len(nested.pairs) == 3
    for offset in range(0, 9, 3):
        group = probes[offset : offset + 3]
        assert group[0][1] == group[1][1] == group[2][1]
        assert [r.headers["x-test-context"] for r, _ in group] == ["alpha", "beta", "gamma"]
        assert group[0][1]["variables"] == {"id": "1"}
        assert set(group[0][1]) == {"query", "variables"}
    for index, (request, _) in enumerate(probes):
        values = str(dict(request.headers))
        assert CANARIES[index % 3] in values
        assert not any(secret in values for j, secret in enumerate(CANARIES) if j != index % 3)
        assert "SERVER_COOKIE" not in request.headers.get("cookie", "")
        assert request.extensions["timeout"]["read"] == 3
    probe_sessions = [session for session in sessions if any(is_nested(p) for _, p in session)]
    assert len(probe_sessions) == 9 and all(len(session) == 1 for session in probe_sessions)
    assert all(pair.context_a == "cliente" and pair.context_b == "soporte" for pair in nested.pairs)
    assert all(pair.kind is NestedDifference.NESTED_ACCESS_DIFFERENCE for pair in nested.pairs)
    assert len(result.evidence) == sum(len(c.scan.evidence) for c in result.contexts) + 9
    assert not any(
        item.evidence_type is EvidenceType.MUTATION_EXECUTION for item in result.evidence
    )
    assert all(secret not in repr(nested) for secret in CANARIES)


@pytest.mark.parametrize("verbose", [False, True])
def test_console_reports_no_business_values_and_exact_json(controlled, tmp_path, verbose):
    result = run(True)
    nested = result.nested_authorization_review
    report = build_differential_report(result)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    projected = canonical["nested_authorization_review"]
    assert len(projected["executions"]) == 9
    for actual, encoded in zip(nested.executions, projected["executions"], strict=True):
        assert encoded["evidence"]["evidence_type"] == "nested_authorization_probe"
        assert encoded["evidence"]["execution_mode"] == "safe"
        assert (
            base64.b64decode(encoded["evidence"]["response_body"]["data"])
            == actual.evidence.response_body
        )
    assert differential_sections(report)[-1].title == "Safety Notice"
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "Nested Authorization Review" in text and text.count("Safety Notice") == 1
        assert text.index("Nested Authorization Review") < text.index("Safety Notice")
        assert "PHASE19_RETURNED_BUSINESS_VALUE" not in text
        assert all(secret not in text for secret in CANARIES)
    output = StringIO()
    render_nested_authorization(
        Console(file=output, theme=CONSOLE_THEME, width=55), nested, verbose=verbose
    )
    assert "RETURNED" in output.getvalue() and "EXPLICIT_DENIAL" in output.getvalue()
    assert "PHASE19_RETURNED_BUSINESS_VALUE" not in output.getvalue()
    assert all(secret not in output.getvalue() for secret in CANARIES)
    options = [arg for entry in ENTRIES for arg in ("--auth-context", entry)]
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            *options,
            "--nested-auth-review",
            "-f",
            "json,markdown,html",
            "-o",
            str(tmp_path),
            *(["-v"] if verbose else []),
        ],
    )
    assert result.exit_code == 0, result.exception
    assert "Nested Authorization Review" in result.output
    assert "Confirm" not in result.output and "Select" not in result.output
    assert len(list(tmp_path.iterdir())) == 3
    assert all(secret not in result.output for secret in CANARIES)


@pytest.mark.parametrize(
    "options",
    [
        [],
        ["--auth-context", "only"],
        ["--auth-context", "a", "--auth-context", "b", "--mode", "active"],
        ["--auth-context", "a", "--auth-context", "b", "--ai"],
        ["--auth-context", "a", "--auth-context", "b", "-H", "Authorization: PHASE19_ERROR_SECRET"],
        [
            "--auth-context",
            "a",
            "--auth-context",
            "b",
            "--auth-context",
            "c",
            "--auth-context",
            "d",
        ],
    ],
)
def test_invalid_combinations_before_network(controlled, options):
    result = CliRunner().invoke(cli.app, ["scan", TARGET, "--nested-auth-review", *options])
    assert result.exit_code == 2 and not controlled[0]
    assert "PHASE19_ERROR_SECRET" not in result.output and "Traceback" not in result.output


def test_flag_absent_reports_unchanged(controlled):
    result = run()
    report = build_differential_report(result)
    assert "nested_authorization_review" not in json.loads(render_report(report, ReportFormat.JSON))
    assert "Nested Authorization Review" not in render_report(report, ReportFormat.MARKDOWN)
    assert not any(is_nested(payload) for _, payload in controlled[0])


def test_failures_do_not_stop_later_contexts_and_comparison_is_local(controlled, monkeypatch):
    safe = run()
    contexts = map_auth_context_inputs(ENTRIES)
    requests = []

    def transport(**kwargs):
        def handle(request):
            payload = json.loads(request.content)
            requests.append(payload)
            if len(requests) == 1:
                raise httpx.ConnectError("PHASE19_ERROR_SECRET", request=request)
            status, body = response_for("POST", request.url.path, request.headers, payload)
            return httpx.Response(status, json=body)

        return httpx.MockTransport(handle)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    nested = execute_nested_authorization(safe, contexts=contexts, enabled=True)
    assert len(requests) == nested.request_count == 9
    assert nested.executions[0].outcome is NestedOutcome.NETWORK_FAILURE
    assert nested.executions[1].outcome is NestedOutcome.EXPLICIT_DENIAL
    assert "PHASE19_ERROR_SECRET" not in repr(nested)
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Comparison HTTP"))
    assert compare_nested_outcomes(nested.executions) == nested.pairs
    assert len(nested.pairs) == 2


def test_value_differences_and_nulls_do_not_create_strong_pairs(controlled):
    entries = [
        "one=X-Test-Context: alpha",
        "two=X-Test-Context: alpha",
        "three=X-Test-Context: gamma",
    ]
    result = run(True, entries=entries)
    assert not result.nested_authorization_review.pairs
    assert result.nested_authorization_review.request_count == 9


def test_different_values_and_list_lengths_are_ignored(controlled, monkeypatch):
    safe = run()

    def transport(**kwargs):
        def handle(request):
            context = request.headers["x-test-context"]
            length = {"alpha": 1, "beta": 2, "gamma": 4}[context]
            return httpx.Response(
                200,
                json={
                    "data": {
                        "project": {
                            "owner": {"email": context},
                            "settings": {"secret": context},
                            "members": [{"email": str(index)} for index in range(length)],
                        }
                    }
                },
            )

        return httpx.MockTransport(handle)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    result = execute_nested_authorization(
        safe, contexts=map_auth_context_inputs(ENTRIES), enabled=True
    )
    assert all(item.outcome is NestedOutcome.RETURNED for item in result.executions)
    assert not result.pairs


def test_duplicate_or_excess_candidates_cannot_expand_budget(controlled):
    safe = run()
    preview = prepare_nested_authorization(safe)
    result = execute_nested_authorization(
        safe,
        contexts=map_auth_context_inputs(ENTRIES),
        enabled=True,
        preview=replace(preview, candidates=preview.candidates * 2),
    )
    assert result.request_count == 9
    assert all(not item.attempted for item in result.executions[9:])


def test_visibility_executes_only_common_paths(controlled):
    result = run(True, entries=["visible=X-Test-Context: alpha", "hidden=X-Test-Context: hidden"])
    nested = result.nested_authorization_review
    assert nested.request_count == 2
    assert len(nested.pairs) == 2
    assert all(
        pair.kind is NestedDifference.NESTED_FIELD_VISIBILITY_DIFFERENCE for pair in nested.pairs
    )
    assert sum(item.attempted for item in nested.executions) == 2


@pytest.mark.parametrize("cross_origin", [False, True])
def test_phase14_redirect_scope_preserved(controlled, monkeypatch, cross_origin):
    safe = run(entries=ENTRIES[:4])
    sent = []

    def transport(**kwargs):
        def handle(request):
            sent.append(request)
            if request.url.path == "/graphql":
                return httpx.Response(
                    307,
                    headers={"Location": "https://other.example/next" if cross_origin else "/next"},
                )
            return httpx.Response(403, json={"errors": [{"message": "Forbidden"}]})

        return httpx.MockTransport(handle)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    nested = execute_nested_authorization(
        safe, contexts=map_auth_context_inputs(ENTRIES[:4]), enabled=True
    )
    assert nested.request_count == 6 and len(sent) == 12
    for i in range(0, 12, 2):
        header = "authorization" if i % 4 == 0 else "cookie"
        assert header in sent[i].headers
        assert (header in sent[i + 1].headers) is not cross_origin


def test_programmatic_active_and_context_count_rejected(controlled):
    result = run()
    context = result.contexts[0]
    scan = context.scan
    generated = scan.query_generation
    analysis = generated.operation_analysis
    schema = analysis.schema_scan
    intro = schema.introspection
    detection = intro.detection
    active = replace(
        scan,
        query_generation=replace(
            generated,
            operation_analysis=replace(
                analysis,
                schema_scan=replace(
                    schema,
                    introspection=replace(
                        intro,
                        detection=replace(
                            detection, discovery=replace(detection.discovery, mode=ScanMode.ACTIVE)
                        ),
                    ),
                ),
            ),
        ),
    )
    with pytest.raises(HttpConfigurationError):
        prepare_nested_authorization(
            replace(result, contexts=(replace(context, scan=active), *result.contexts[1:]))
        )
    with pytest.raises(HttpConfigurationError):
        execute_nested_authorization(result, contexts=(NamedAuthContext("one"),), enabled=True)
