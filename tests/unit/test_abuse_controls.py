"""Ordinary baseline provenance, bounded exact replay and defensive consent invariants."""

import json
from dataclasses import replace
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.phase27_target import SDL, response_for
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.application import abuse_controls as application
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.abuse_controls import AbuseControlOutcome
from gqlsleuth.domain.active import MutationDecision
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.execution import QueryExecutionStatus as Status
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.abuse_controls import render_abuse_controls
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections, technical_sections
from gqlsleuth.reporting.renderers import render_report

SECRET = "PHASE27_AUTH_CANARY"
COOKIE = "PHASE27_COOKIE_CANARY"
API_KEY = "PHASE27_API_CANARY"
PROXY = "PHASE27_PROXY_CANARY"


def settings():
    return HttpClientSettings(
        custom_headers=(
            ("Authorization", "Bearer " + SECRET),
            ("Cookie", "session=" + COOKIE),
            ("X-API-Key", API_KEY),
            ("X-Forwarded-For", "192.0.2.1"),
            ("User-Agent", "fixed-fixture-agent"),
        ),
        timeout_seconds=3,
        verify_tls=False,
        proxy="http://fake:" + PROXY + "@proxy.example:8888",
    )


@pytest.fixture
def active(phase_ten_scan):
    safe = phase_ten_scan(SDL)[0]
    preview = prepare_active_mutations(safe)
    index = next(
        i
        for i, item in enumerate(preview.candidates, 1)
        if item.generated_mutation.operation_name == "login"
    )

    def handler(request):
        status, body = response_for(request.method, json.loads(request.content))
        return httpx.Response(status, json=body)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        return execute_selected_mutations(
            preview, selected_indices=(index,), confirmed=True, client=client
        )


@pytest.fixture
def wire(monkeypatch):
    requests, configurations = [], []
    control = {"scenario": "none", "network": None, "override": {}, "redirect": None}

    def handler(request):
        requests.append(request)
        assert "learned" not in request.headers.get("cookie", "")
        attempt = len(requests)
        if attempt == control["network"]:
            raise httpx.ConnectError(SECRET, request=request)
        redirect = control["redirect"]
        if redirect and request.url.path == "/graphql":
            return httpx.Response(307, headers={"Location": redirect})
        if redirect and request.url.host == "other.example":
            assert all(
                name not in request.headers
                for name in ("authorization", "cookie", "x-api-key", "x-forwarded-for")
            )
        payload = json.loads(request.content)
        status, body = control["override"].get(
            attempt,
            response_for(request.method, payload, scenario=control["scenario"], attempt=attempt),
        )
        return httpx.Response(
            status,
            json=body,
            headers={"Set-Cookie": "learned=private", "Retry-After": "60", "X-Secret": SECRET},
        )

    def client(config):
        configurations.append(config)
        # Mock proxy mounts too: HTTPX otherwise gives proxy mounts precedence over transport.
        return HttpClient(
            config.model_copy(update={"proxy": None}), transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(application, "HttpClient", client)
    return requests, control, configurations


def session(active, kind="query", **kwargs):
    preview = application.prepare_abuse_controls(active, enabled=True)
    index = next(item.index for item in preview.candidates if item.operation.kind.value == kind)
    return application.AbuseControlSession(
        active, http_settings=settings(), enabled=True, selected_index=index, **kwargs
    )


@pytest.mark.parametrize(
    "kind,scenario,count,policy,signal",
    [
        ("query", "http429", 3, "satisfied", "rate_limit"),
        ("query", "none", 5, "violated", None),
        ("mutation", "rate", 3, "satisfied", "rate_limit"),
        ("mutation", "none", 3, "violated", None),
        ("mutation", "lockout", 3, "satisfied", "lockout"),
        ("mutation", "challenge", 2, "satisfied", "challenge"),
        ("query", "server-error", 2, "unresolved", None),
    ],
)
def test_bounded_exact_replay_early_stop_and_policy(
    active, wire, kind, scenario, count, policy, signal
):
    requests, control, configurations = wire
    control["scenario"] = scenario
    workflow = session(active, kind)
    preview = workflow.preview
    assert not requests
    result = workflow.execute(preview=preview, confirmed=True)
    assert result.attempted_request_count == len(requests) == count
    assert result.policy_result.value == policy
    assert result.first_signal_attempt == (count if signal else None)
    assert bool(result.findings) is (policy == "violated")
    assert [e.attempt_index for e in result.attempts] == list(range(1, count + 1))
    for req, config, evidence in zip(requests, configurations, result.attempts, strict=True):
        assert config == settings()
        assert json.loads(req.content) == {
            "query": preview.selected.query,
            "variables": preview.selected.variables,
        }
        for name, value in settings().custom_headers:
            assert req.headers[name] == value
        assert (
            evidence.query == preview.selected.query
            and evidence.variables == preview.selected.variables
        )
        assert evidence.baseline_evidence_id == preview.selected.baseline_evidence_id
        assert evidence.policy_id == result.policy_id
        assert evidence.request_method == "POST" and evidence.duration_seconds >= 0
        assert evidence.evidence_type is EvidenceType.ABUSE_CONTROL_PROBE
        assert evidence.execution_mode is ScanMode.ACTIVE
        assert (
            "set-cookie" not in evidence.response_headers
            and "x-secret" not in evidence.response_headers
        )
        assert evidence.response_body and evidence.response_status_code
    if signal:
        assert result.attempts[-1].signal.kind.value == signal
    if result.findings:
        finding = result.findings[0]
        assert finding.actual_attempts == finding.planned_attempts == count
        assert finding.attempt_evidence_ids == tuple(e.evidence_id for e in result.attempts)
        assert finding.baseline_evidence_id == preview.selected.baseline_evidence_id
        assert finding.provenance.value == "operator_supplied"
        assert (
            "higher threshold" in finding.limitation
            and "different time window" in finding.limitation
        )
        assert not any(hasattr(finding, name) for name in ("severity", "cvss", "cwe"))
    assert workflow.execute(preview=preview, confirmed=True) == result and len(requests) == count


def test_candidate_provenance_priority_and_no_baseline_body(active, wire):
    result = application.prepare_abuse_controls(active, enabled=True)
    assert [c.operation.name for c in result.candidates] == ["login", "search"]
    assert result.candidates[0].baseline_status is Status.GRAPHQL_ERROR
    assert result.candidates[1].baseline_status is Status.SUCCESS
    assert [c.baseline_source for c in result.candidates] == [
        EvidenceType.MUTATION_EXECUTION,
        EvidenceType.QUERY_EXECUTION,
    ]
    assert [c.planned_attempts for c in result.candidates] == [3, 5]
    assert result.candidates == application.prepare_abuse_controls(active, enabled=True).candidates
    assert not any(hasattr(c, "response_body") for c in result.candidates)
    assert not wire[0]


@pytest.mark.parametrize("consent", [False, None, "y", 1])
def test_strict_confirmation_and_finished_session(active, wire, consent):
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=consent)
    assert not result.attempts and not result.findings
    assert workflow.execute(preview=workflow.preview, confirmed=True) == result
    assert not wire[0]


@pytest.mark.parametrize("mode,enabled", [(ScanMode.SAFE, True), (ScanMode.ACTIVE, False)])
def test_mode_and_flag_independently_required(phase_ten_scan, wire, mode, enabled):
    safe = phase_ten_scan(SDL, mode)[0]
    workflow = application.AbuseControlSession(
        safe, enabled=enabled, selected_index=1, http_settings=settings()
    )
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert not result.attempts and not result.candidates and not wire[0]


def test_empty_selection(active, wire):
    workflow = application.AbuseControlSession(active, enabled=True, http_settings=settings())
    assert not workflow.execute(preview=workflow.preview, confirmed=True).attempts
    assert not wire[0]


@pytest.mark.parametrize("index", [True, 0, -1, 3, "1", (1, 2)])
def test_selection_cannot_expand_to_multiple_or_unknown(active, wire, index):
    with pytest.raises(HttpConfigurationError):
        application.prepare_abuse_controls(active, enabled=True, selected_index=index)
    assert not wire[0]


@pytest.mark.parametrize("failed", [1, 2, 5])
def test_network_failure_stops_without_replacement(active, wire, failed):
    wire[1]["network"] = failed
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert len(wire[0]) == result.attempted_request_count == failed
    assert result.attempts[-1].outcome is AbuseControlOutcome.NETWORK_FAILURE
    assert result.policy_result.value == "unresolved" and not result.findings
    assert SECRET not in repr(result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("query", 'mutation { deleteUser(id: "1") }'),
        ("variables", {"term": True}),
        ("planned_attempts", 50),
        ("index", True),
        ("baseline_source", EvidenceType.AUTHENTICATION_SECURITY_PROBE),
    ],
)
def test_forged_plan_cannot_change_payload_or_budget(active, wire, field, value):
    workflow = session(active)
    forged = replace(
        workflow.preview, selected=replace(workflow.preview.selected, **{field: value})
    )
    assert not workflow.execute(preview=forged, confirmed=True).attempts
    assert not wire[0]


@pytest.mark.parametrize("during", [False, True])
def test_before_each_attempt_rechecks_original_variables(active, wire, monkeypatch, during):
    workflow = session(active)
    original = application._request
    if during:

        def request(*args):
            evidence = original(*args)
            active.safe_execution.executions[0].generated_query.variables["term"] = "different"
            return evidence

        monkeypatch.setattr(application, "_request", request)
    else:
        active.safe_execution.executions[0].generated_query.variables["term"] = "different"
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert result.attempted_request_count == len(wire[0]) == int(during)
    assert not result.findings


def test_http_context_change_stops_sequence(active, wire, monkeypatch):
    workflow = session(active)
    original = application._request

    def request(*args):
        evidence = original(*args)
        workflow._settings = workflow._settings.model_copy(update={"timeout_seconds": 4})
        return evidence

    monkeypatch.setattr(application, "_request", request)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert len(wire[0]) == 1 and not result.findings and result.policy_result.value == "unresolved"


@pytest.mark.parametrize(
    "status",
    [Status.SKIPPED_SAFETY, Status.SKIPPED_LIMIT, Status.NETWORK_FAILURE, Status.INVALID_RESPONSE],
)
def test_unusable_query_statuses_excluded(active, status):
    safe = active.safe_execution
    altered = replace(safe, executions=(replace(safe.executions[0], status=status),))
    assert not application.prepare_abuse_controls(altered, enabled=True).candidates


@pytest.mark.parametrize(
    "kind",
    [
        EvidenceType.GRAPHQL_BEHAVIOR_PROBE,
        EvidenceType.NESTED_AUTHORIZATION_PROBE,
        EvidenceType.OBJECT_AUTHORIZATION_PROBE,
        EvidenceType.SEQUENTIAL_OBJECT_PROBE,
        EvidenceType.MUTATION_AUTHORIZATION_PROBE,
        EvidenceType.SENSITIVE_INPUT_PROBE,
        EvidenceType.IDOR_BOLA_PROBE,
        EvidenceType.AUTHENTICATION_SECURITY_PROBE,
        EvidenceType.ABUSE_CONTROL_PROBE,
    ],
)
def test_security_probe_evidence_cannot_become_baseline(active, kind):
    safe = active.safe_execution
    altered = replace(
        safe,
        execution_evidence=tuple(
            e.model_copy(update={"evidence_type": kind}) for e in safe.execution_evidence
        ),
    )
    assert not application.prepare_abuse_controls(altered, enabled=True).candidates


def test_mutation_unexecuted_or_missing_evidence_is_ineligible(active):
    for altered in (
        replace(active, executions=()),
        replace(active, execution_evidence=()),
        replace(active, confirmed=False),
        replace(active, selected_indices=()),
    ):
        assert all(
            c.operation.kind is OperationKind.QUERY
            for c in application.prepare_abuse_controls(altered, enabled=True).candidates
        )


def test_destructive_mutation_is_rechecked_even_with_forged_execution(active):
    dangerous = next(
        c for c in active.preview.candidates if c.generated_mutation.operation_name == "deleteUser"
    )
    execution = next(e for e in active.executions if e.attempted)
    index = active.preview.candidates.index(dangerous) + 1
    altered = replace(
        active,
        selected_indices=(index,),
        executions=(
            replace(
                execution, preview=dangerous, selected=True, decision=MutationDecision.EXECUTED
            ),
        ),
    )
    assert all(
        c.operation.name != "deleteUser"
        for c in application.prepare_abuse_controls(altered, enabled=True).candidates
    )


@pytest.mark.parametrize("target", ["https://example.com/next", "https://other.example/next"])
def test_redirect_headers_and_cookie_isolation(active, wire, target):
    wire[1]["redirect"] = target
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    expected = 1 if "other.example" in target else 5
    assert result.attempted_request_count == expected
    assert len(wire[0]) == 2 * expected  # Central transport redirects, not planned repeats.
    if "other.example" not in target:
        assert all(req.headers["authorization"] == "Bearer " + SECRET for req in wire[0])


@pytest.mark.parametrize("secret", [SECRET, COOKIE, API_KEY, PROXY])
def test_echoed_credentials_withheld_from_new_evidence(active, wire, secret):
    wire[1]["override"][1] = (200, {"data": {"search": secret}})
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert (
        result.attempts[0].response_material_withheld and result.attempts[0].response_body is None
    )
    assert secret not in repr(result)


def test_reporting_console_ai_and_evidence_are_additive_and_local(active, wire, caplog):
    workflow = session(active, "mutation")
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    combined = replace(active, rate_limiting_abuse_controls=result)
    assert combined.evidence == (*active.evidence, *result.attempts)
    assert build_ai_context(combined).operations == build_ai_context(active).operations
    report = build_report(combined)
    sections = human_sections(report)
    assert sections[-1].title == "Safety Notice"
    assert [s.title for s in sections].count("Safety Notice") == 1
    assert "Rate Limiting / Abuse-Control Findings" in [s.title for s in technical_sections(report)]
    texts = [repr(result), serialize_context(build_ai_context(combined)), caplog.text]
    for width in (48, 100):
        for verbose in (False, True):
            output = StringIO()
            render_abuse_controls(
                Console(file=output, width=width, theme=CONSOLE_THEME), result, verbose=verbose
            )
            texts.append(output.getvalue())
    for format in ReportFormat:
        rendered = render_report(report, format)
        texts.append(rendered)
        if format is ReportFormat.JSON:
            data = json.loads(rendered)["rate_limiting_abuse_controls"]
            assert data["attempted_request_count"] == 3 and data["policy_result"] == "violated"
            assert data["selected"]["query"] == result.selected.query
            assert data["findings"][0]["attempt_evidence_ids"] == [
                str(e.evidence_id) for e in result.attempts
            ]
        else:
            assert rendered.count("Safety Notice") == 1
            assert "rollback or deduplication" in rendered
    assert all(secret not in text for secret in (SECRET, COOKIE, API_KEY, PROXY) for text in texts)
    assert len(wire[0]) == 3
    assert "rate_limiting_abuse_controls" not in json.loads(
        render_report(build_report(active), ReportFormat.JSON)
    )
