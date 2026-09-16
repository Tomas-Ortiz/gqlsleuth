"""Bounded object probes, owner gates, privacy and additive report/CLI integration."""

import io
import json
from dataclasses import replace

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from fixtures.phase20_target import SDL, response_for
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application import object_authorization as application
from gqlsleuth.application.differential_review import ContextScanResult, compare_context_scans
from gqlsleuth.application.scan_configuration import map_auth_context_inputs
from gqlsleuth.domain.differential import NamedAuthContext
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.domain.object_authorization import (
    ObjectAccessKind,
    ObjectOutcome,
    parse_object_cases,
)
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.object_authorization import render_object_authorization
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.differential import build_differential_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report

CONTEXTS = (
    NamedAuthContext(
        "clienteA", (("X-Test-Context", "clienteA"), ("Authorization", "PHASE20_A_SECRET"))
    ),
    NamedAuthContext(
        "clienteB", (("X-Test-Context", "clienteB"), ("Cookie", "session=PHASE20_B_SECRET"))
    ),
    NamedAuthContext("foo"),
)


@pytest.fixture
def retained(phase_ten_scan):
    safe = phase_ten_scan(SDL, mode=ScanMode.SAFE)[0]
    result = compare_context_scans(
        Target.parse("https://example.com/graphql"),
        tuple(ContextScanResult(item.name, safe) for item in CONTEXTS),
    )
    return safe, result


@pytest.fixture
def transport(monkeypatch):
    requests = []
    clients = []
    failure = {}

    def handler(request):
        payload = json.loads(request.content)
        context = request.headers.get("x-test-context", "public")
        requests.append((context, payload, dict(request.headers)))
        assert "learned" not in request.headers.get("cookie", "")
        if context in failure:
            if failure[context] == "network":
                raise httpx.ConnectError("PHASE20_TRANSPORT_SECRET", request=request)
            return httpx.Response(failure[context], json={})
        status, document = response_for(request.method, request.headers, payload)
        return httpx.Response(status, json=document, headers={"set-cookie": "learned=isolated"})

    def factory(settings):
        client = HttpClient(settings, transport=httpx.MockTransport(handler))
        clients.append((settings, client))
        return client

    monkeypatch.setattr(application, "HttpClient", factory)
    return requests, clients, failure


def test_owner_first_exact_inputs_isolation_and_no_enumeration(retained, transport):
    _, scan = retained
    requests, clients, _ = transport
    cases = parse_object_cases(
        ["clienteA:order:id=123", "clienteB:order:id=456", "clienteA:order:id=999"],
        tuple(item.name for item in CONTEXTS),
    )
    result = application.execute_object_authorization(
        scan, cases=cases, contexts=CONTEXTS, enabled=True
    )
    assert (
        result.attempted_request_count == len(requests) == len(clients) == len(result.evidence) == 7
    )
    assert [item[0] for item in requests] == [
        "clienteA",
        "clienteB",
        "public",
        "clienteB",
        "clienteA",
        "public",
        "clienteA",
    ]
    assert requests[0][1] == requests[1][1] == requests[2][1]
    assert [item[1]["variables"]["id"] for item in requests] == ["123"] * 3 + ["456"] * 3 + ["999"]
    assert all(set(item[1]) == {"query", "variables"} for item in requests)
    for context, _, headers in requests:
        assert ("PHASE20_A_SECRET" in str(headers)) == (context == "clienteA")
        assert ("PHASE20_B_SECRET" in str(headers)) == (context == "clienteB")
    assert {item.kind for item in result.candidates} == {
        ObjectAccessKind.CROSS_CONTEXT_OBJECT_ACCESS,
        ObjectAccessKind.UNAUTHENTICATED_OBJECT_ACCESS,
    }
    assert all(item.source_evidence_ids for item in result.candidates)
    assert [item.outcome for item in result.executions[3:6]] == [
        ObjectOutcome.TARGET_RETURNED,
        ObjectOutcome.EXPLICIT_DENIAL,
        ObjectOutcome.EXPLICIT_DENIAL,
    ]
    assert all(not item.attempted and item.evidence is None for item in result.executions[-2:])
    assert "operator-declared authorized context" in result.limitations[-1]
    for evidence in result.evidence:
        assert evidence.execution_mode is ScanMode.SAFE
        assert evidence.response_body and evidence.request_method == "POST"
        assert evidence.query == result.probes[evidence.identifier == "456"].query
        assert evidence.variables == {"id": evidence.identifier}


@pytest.mark.parametrize("failure", [401, 403, 404, 500, "network"])
def test_owner_failure_short_circuit(retained, transport, failure):
    _, scan = retained
    requests, _, failures = transport
    failures["clienteB"] = failure
    cases = parse_object_cases(["clienteB:order:id=123"], tuple(item.name for item in CONTEXTS))
    result = application.execute_object_authorization(
        scan, cases=cases, contexts=CONTEXTS, enabled=True
    )
    assert len(requests) == result.attempted_request_count == 1
    assert not result.candidates and result.limitations
    assert len(result.executions) == 3
    assert "PHASE20_TRANSPORT_SECRET" not in repr(result)


def test_nonowner_failure_continues_and_hard_budget(retained, transport):
    _, scan = retained
    requests, _, failures = transport
    failures["clienteB"] = "network"
    cases = parse_object_cases(
        [f"clienteA:order:id={value}" for value in (123, 100, 777)],
        tuple(item.name for item in CONTEXTS),
    )
    result = application.execute_object_authorization(
        scan, cases=cases, contexts=CONTEXTS, enabled=True
    )
    assert len(requests) == result.attempted_request_count == 9
    assert len(result.evidence) == 9
    assert len(result.candidates) == 3
    assert all(
        item.kind is ObjectAccessKind.UNAUTHENTICATED_OBJECT_ACCESS for item in result.candidates
    )
    with pytest.raises(HttpConfigurationError):
        application.execute_object_authorization(
            scan,
            cases=cases + (replace(cases[0], identifier="888", index=4),),
            contexts=CONTEXTS,
            enabled=True,
        )
    assert len(requests) == 9


@pytest.mark.parametrize("change", ["query", "variables", "context", "case", "duplicate", "root"])
def test_tampered_previews_never_execute(retained, transport, change):
    safe, _ = retained
    cases = parse_object_cases(["order:id=123"])
    preview = application.prepare_object_authorization(safe, cases=cases)
    probe = preview.probes[0]
    if change == "query":
        probe = replace(probe, query=probe.query + " query { __typename }")
    elif change == "variables":
        probe = replace(probe, variables={"id": "124"})
    elif change == "context":
        probe = replace(
            probe, contexts=(replace(probe.contexts[0], has_supplied_context_headers=True),)
        )
    elif change == "case":
        probe = replace(probe, case=replace(probe.case, identifier="124"))
    elif change == "root":
        probe = replace(probe, response_id_path=("other", "id"))
    preview = replace(preview, probes=(probe, probe) if change == "duplicate" else (probe,))
    result = application.execute_object_authorization(
        safe, cases=cases, enabled=True, preview=preview
    )
    assert len(transport[0]) == (1 if change == "duplicate" else 0)
    assert result.attempted_request_count == len(transport[0])


def test_anonymous_modes_enabled_gate_and_ai_exclusion(retained, transport):
    safe, _ = retained
    cases = parse_object_cases(["order:id=100", "order:id=456", "order:id=mismatch"])
    disabled = application.execute_object_authorization(safe, cases=cases)
    assert not disabled.evidence and not transport[0]
    result = application.execute_object_authorization(safe, cases=cases, enabled=True)
    assert result.attempted_request_count == 3 and len(result.candidates) == 1
    assert build_ai_context(safe) == build_ai_context(
        replace(safe, object_authorization_review=result)
    )
    named = application.execute_object_authorization(
        safe, cases=(cases[0],), contexts=(NamedAuthContext("foo"),), enabled=True
    )
    assert named.executions[0].context.name == "foo"
    assert named.candidates[0].kind is ObjectAccessKind.UNAUTHENTICATED_OBJECT_ACCESS
    with pytest.raises(HttpConfigurationError):
        application.execute_object_authorization(
            safe, cases=(cases[0],), contexts=(CONTEXTS[0],), enabled=True
        )
    with pytest.raises(HttpConfigurationError):
        application.execute_object_authorization(
            safe,
            cases=cases,
            enabled=True,
            http_settings=HttpClientSettings(custom_headers=(("X-Custom", "secret"),)),
        )


def test_reports_console_privacy_evidence_and_final_safety(retained, transport):
    safe, scan = retained
    cases = parse_object_cases(["clienteA:order:id=123"], tuple(item.name for item in CONTEXTS))
    result = application.execute_object_authorization(
        scan, cases=cases, contexts=CONTEXTS, enabled=True
    )
    for verbose in (False, True):
        stream = io.StringIO()
        render_object_authorization(
            Console(file=stream, width=70, theme=cli.CONSOLE_THEME), result, verbose=verbose
        )
        assert "TARGET_RETURNED" in stream.getvalue()
        assert "PHASE20_A_SECRET" not in stream.getvalue()
        assert "PHASE20_B_SECRET" not in stream.getvalue()
    completed = replace(scan, object_authorization_review=result)
    assert completed.evidence[: len(scan.evidence)] == scan.evidence
    context = build_differential_report(completed)
    data = json.loads(render_report(context, ReportFormat.JSON))
    assert data["object_authorization_review"]["attempted_request_count"] == 3
    assert data["object_authorization_review"]["probes"][0]["variables"] == {"id": "123"}
    for format in ReportFormat:
        output = render_report(context, format)
        assert "PHASE20_A_SECRET" not in output and "PHASE20_B_SECRET" not in output
        if format is not ReportFormat.JSON:
            assert "Controlled Object Authorization Validation" in output
            assert output.count("Safety Notice") == 1
            assert output.index("Controlled Object Authorization Validation") < output.index(
                "Safety Notice"
            )
            assert "PHASE20_BUSINESS_VALUE" not in output
    assert "object_authorization_review" not in render_report(build_report(safe), ReportFormat.JSON)
    anonymous = application.execute_object_authorization(
        safe, cases=parse_object_cases(["order:id=100"]), enabled=True
    )
    assert "UNAUTHENTICATED_OBJECT_ACCESS" in render_report(
        build_report(replace(safe, object_authorization_review=anonymous)), ReportFormat.MARKDOWN
    ).replace("\\", "")


@pytest.mark.parametrize(
    "options",
    [
        ["--object-auth-case", "order:id=SECRET"],
        ["--object-auth-review"],
        ["--object-auth-review", "--object-auth-case", "order:id=SECRET", "-H", "X-Key: SECRET"],
        ["--object-auth-review", "--object-auth-case", "order:id=SECRET", "--mode", "active"],
        [
            "--object-auth-review",
            "--object-auth-case",
            "order:id=SECRET",
            "--auth-context",
            "foo=X-Key: SECRET",
        ],
        ["--auth-context", "foo"],
        [
            "--object-auth-review",
            "--object-auth-case",
            "order:id=SECRET",
            "--auth-context",
            "a",
            "--auth-context",
            "b",
        ],
        [
            "--object-auth-review",
            "--object-auth-case",
            "a:order:id=SECRET",
            "--auth-context",
            "a",
            "--auth-context",
            "b",
            "--ai",
        ],
        [
            "--object-auth-review",
            "--object-auth-case",
            "order:id=SECRET",
            "--nested-auth-review",
            "--auth-context",
            "foo",
        ],
    ],
)
def test_cli_rejects_before_network(monkeypatch, options):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid CLI performed HTTP"))
    run = CliRunner().invoke(cli.app, ["scan", "https://example.com/graphql", *options])
    assert run.exit_code == 2 and "SECRET" not in run.output
    assert not isinstance(run.exception, AssertionError)


def test_single_bare_exception_does_not_weaken_normal_contexts():
    assert map_auth_context_inputs(["foo"], object_review=True) == (NamedAuthContext("foo"),)
    with pytest.raises(HttpConfigurationError):
        map_auth_context_inputs(["foo"])
    with pytest.raises(HttpConfigurationError):
        map_auth_context_inputs(["foo=X-Key: SECRET"], object_review=True)


@pytest.mark.parametrize("cross_origin", [False, True])
def test_redirect_scope_and_target_settings_unchanged(retained, monkeypatch, cross_origin):
    _, scan = retained
    sent = []
    configured = []

    def handler(request):
        sent.append(request)
        if request.url.path == "/graphql":
            return httpx.Response(
                307, headers={"Location": "https://other.example/next" if cross_origin else "/next"}
            )
        return httpx.Response(200, json={"data": {"order": {"id": "123"}}})

    def factory(settings):
        configured.append(settings)
        return HttpClient(settings, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(application, "HttpClient", factory)
    result = application.execute_object_authorization(
        scan,
        cases=parse_object_cases(["clienteA:order:id=123"], tuple(item.name for item in CONTEXTS)),
        contexts=CONTEXTS,
        enabled=True,
        http_settings=HttpClientSettings(timeout_seconds=3, verify_tls=False),
    )
    assert result.attempted_request_count == 3 and len(sent) == 6
    assert all(item.timeout_seconds == 3 and item.verify_tls is False for item in configured)
    assert len({id(item) for item in configured}) == 3
    for index, header in ((0, "authorization"), (2, "cookie")):
        assert header in sent[index].headers
        assert (header in sent[index + 1].headers) is not cross_origin
    assert all(
        "authorization" not in item.headers and "cookie" not in item.headers for item in sent[4:]
    )


@pytest.mark.parametrize("problem", ["missing", "default", "return_type", "active"])
def test_incompatible_context_data_cannot_execute(phase_ten_scan, monkeypatch, problem):
    sdl = "type Query { order(id: ID!, hint: Int = 1): Order } type Order { id: ID! }"
    first = phase_ten_scan(sdl, mode=ScanMode.SAFE)[0]
    second = phase_ten_scan(
        sdl.replace("Int = 1", "Int = 2")
        if problem == "default"
        else sdl.replace("id: ID! }", "id: ID }")
        if problem == "return_type"
        else sdl,
        mode=ScanMode.ACTIVE if problem == "active" else ScanMode.SAFE,
    )[0]
    result = replace(
        compare_context_scans(
            Target.parse("https://example.com/graphql"),
            (ContextScanResult("a", first), ContextScanResult("b", first)),
        ),
        contexts=(
            ContextScanResult("a", first),
            ContextScanResult("b", None if problem == "missing" else second),
        ),
    )
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Ineligible probe HTTP"))
    kwargs = {
        "cases": parse_object_cases(["a:order:id=123"], ("a", "b")),
        "contexts": (NamedAuthContext("a"), NamedAuthContext("b")),
        "enabled": True,
    }
    if problem == "active":
        with pytest.raises(HttpConfigurationError):
            application.execute_object_authorization(result, **kwargs)
    else:
        review = application.execute_object_authorization(result, **kwargs)
        assert not review.probes and review.limitations and not review.evidence


def test_combined_workflow_disabled_sequence_and_separate_budgets(monkeypatch):
    requests = []

    def transport(**kwargs):
        def handler(request):
            payload = json.loads(request.content) if request.method == "POST" else None
            requests.append((request.headers.get("x-test-context"), payload))
            status, document = response_for(request.method, request.headers, payload)
            return httpx.Response(status, json=document)

        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    options = [
        "--auth-context",
        "a=X-Test-Context: clienteA",
        "--auth-context",
        "b=X-Test-Context: clienteB",
    ]
    baseline = CliRunner().invoke(
        cli.app, ["scan", "https://example.com/graphql", *options, "--nested-auth-review"]
    )
    assert baseline.exit_code == 0, baseline.exception
    original = list(requests)
    requests.clear()
    result = application.run_object_authorization_scan(
        "https://example.com/graphql",
        contexts=map_auth_context_inputs(
            ["a=X-Test-Context: clienteA", "b=X-Test-Context: clienteB"]
        ),
        cases=parse_object_cases(["a:order:id=123"], ("a", "b")),
        nested_auth_review=True,
    )
    assert requests[: len(original)] == original
    assert len(requests) == len(original) + 2
    assert result.nested_authorization_review.request_count == 2
    assert result.object_authorization_review.attempted_request_count == 2
    assert all(payload["variables"] == {"id": "123"} for _, payload in requests[-2:])
    report = render_report(build_differential_report(result), ReportFormat.HTML)
    assert (
        report.index("Nested Authorization Review")
        < report.index("Controlled Object Authorization Validation")
        < report.index("Safety Notice")
    )
