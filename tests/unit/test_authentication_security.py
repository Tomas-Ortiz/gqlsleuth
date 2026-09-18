"""Exact retained baseline, independent consent, scoped findings and privacy boundaries."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.phase26_target import CLAIM_CANARY, SDL, fake_token, response_for
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.application import authentication as application
from gqlsleuth.application.active_execution import (
    ActiveExecutionScanResult,
    ActiveMutationPreviewResult,
)
from gqlsleuth.domain.authentication import AuthenticationProbe as Probe
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.nested_authorization import NestedOutcome
from gqlsleuth.graphql.authentication import classify_authentication_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.authentication import render_authentication
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.rules.token_security import token_variant

TOKEN = fake_token()
COOKIE = "PHASE26_COOKIE_CANARY"
PROXY = "PHASE26_PROXY_CANARY"
BOTH = (Probe.JWT_SIGNATURE_TAMPERED, Probe.JWT_ALG_NONE)


@pytest.fixture
def active(phase_ten_scan):
    safe = phase_ten_scan(SDL)[0]
    # Retain a successful non-null fixture response and matching evidence, no new request.
    body = b'{"data":{"currentUser":{"id":"1"}}}'
    execution = safe.executions[0]
    return replace(
        safe,
        executions=(
            replace(execution, response=execution.response.model_copy(update={"body": body})),
        ),
        execution_evidence=tuple(
            item.model_copy(update={"response_body": body}) for item in safe.execution_evidence
        ),
    )


@pytest.fixture
def wire(monkeypatch):
    requests, configurations = [], []
    controls = {
        "scenario": "protected",
        "original": TOKEN,
        "network": set(),
        "override": {},
        "redirect": False,
    }

    def handler(request):
        requests.append(request)
        number = len(requests)
        payload = json.loads(request.content)
        assert "learned" not in request.headers.get("cookie", "")
        if number in controls["network"]:
            raise httpx.ConnectError(TOKEN, request=request)
        if controls["redirect"] and request.url.host == "example.com" and number > 1:
            return httpx.Response(307, headers={"location": "https://other.example/graphql"})
        if request.url.host == "other.example":
            assert "authorization" not in request.headers
            assert "cookie" not in request.headers
            assert "x-tenant" not in request.headers
            return httpx.Response(200, json={"data": {"currentUser": {"id": "1"}}})
        if number in controls["override"]:
            status, body = controls["override"][number]
        else:
            status, body = response_for(
                request.method,
                payload,
                request.headers.get("authorization", ""),
                original=controls["original"],
                scenario=controls["scenario"],
            )
        return httpx.Response(
            status, json=body, headers={"set-cookie": "learned=secret", "x-secret": COOKIE}
        )

    def client(settings):
        configurations.append(settings)
        # HTTPX proxy mounts otherwise take precedence over a supplied mock transport.
        return HttpClient(
            settings.model_copy(update={"proxy": None}), transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(application, "HttpClient", client)
    return requests, controls, configurations


def settings(token=TOKEN):
    return HttpClientSettings(
        custom_headers=(
            ("aUtHoRiZaTiOn", "Bearer " + token),
            ("Cookie", "session=" + COOKIE),
            ("X-Tenant", "PHASE26_TENANT"),
            ("User-Agent", "phase26-test"),
        ),
        timeout_seconds=3,
        verify_tls=False,
        proxy="http://fake:" + PROXY + "@proxy.example:8888",
    )


def session(active, probes=BOTH, token=TOKEN, **kwargs):
    return application.AuthenticationSecuritySession(
        active,
        http_settings=settings(token),
        selected_index=1,
        selected_probes=probes,
        enabled=True,
        **kwargs,
    )


@pytest.mark.parametrize(
    "scenario,probes,count,kinds",
    [
        ("protected", (), 1, []),
        ("open", BOTH, 1, ["authentication_enforcement_failure"]),
        ("ambiguous", BOTH, 1, []),
        ("protected", BOTH, 3, []),
        ("signature-accepted", BOTH, 3, ["jwt_signature_validation_failure"]),
        ("none-accepted", BOTH, 3, ["jwt_none_algorithm_accepted"]),
    ],
)
def test_control_gating_exact_requests_and_findings(active, wire, scenario, probes, count, kinds):
    requests, controls, configurations = wire
    controls["scenario"] = scenario
    workflow = session(active, probes)
    preview = workflow.preview
    assert not requests
    result = workflow.execute(preview=preview, confirmed=True)
    assert result.attempted_request_count == len(requests) == count
    assert [item.finding_type.value for item in result.findings] == kinds
    assert "authorization" not in requests[0].headers
    for request, config in zip(requests, configurations, strict=True):
        assert json.loads(request.content) == {
            "query": preview.selected_query.query,
            "variables": preview.selected_query.variables,
        }
        assert request.headers["cookie"] == "session=" + COOKIE
        assert request.headers["x-tenant"] == "PHASE26_TENANT"
        assert request.headers["user-agent"] == "phase26-test"
        assert config.timeout_seconds == 3 and config.verify_tls is False
        assert config.proxy == settings().proxy
    for i, request in enumerate(requests[1:]):
        assert request.headers["authorization"] == "Bearer " + token_variant(TOKEN, probes[i])
    for evidence in result.evidence:
        assert evidence.evidence_type is EvidenceType.AUTHENTICATION_SECURITY_PROBE
        assert evidence.execution_mode is ScanMode.ACTIVE
        assert evidence.baseline_evidence_id == preview.selected_query.baseline_evidence_id
        assert evidence.request_method == "POST" and evidence.duration_seconds >= 0
        assert evidence.response_body and evidence.response_status_code
        assert (
            "set-cookie" not in evidence.response_headers
            and "x-secret" not in evidence.response_headers
        )
    for finding in result.findings:
        assert finding.provenance.value == "operator_supplied"
        assert finding.control_evidence_id == result.evidence[0].evidence_id
        assert finding.probe_evidence_id in {e.evidence_id for e in result.evidence}
        assert not any(hasattr(finding, name) for name in ("severity", "cvss", "cwe"))
    assert workflow.execute(preview=preview, confirmed=True) == result
    assert len(requests) == count


@pytest.mark.parametrize("confirmed", [False, None, 1, "yes"])
def test_confirmation_is_strict_default_no(active, wire, confirmed):
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=confirmed)
    assert not wire[0] and not result.evidence and not result.findings and not result.confirmed


@pytest.mark.parametrize("mode,enabled", [(ScanMode.SAFE, True), (ScanMode.ACTIVE, False)])
def test_mode_and_enablement_gate(phase_ten_scan, wire, mode, enabled):
    safe = phase_ten_scan(SDL, mode)[0]
    workflow = application.AuthenticationSecuritySession(
        safe, http_settings=settings(), enabled=enabled, selected_index=1, selected_probes=BOTH
    )
    assert workflow.preview.candidates == ()
    assert not workflow.execute(preview=workflow.preview, confirmed=True).evidence
    assert not wire[0]


def test_empty_selection(active, wire):
    workflow = application.AuthenticationSecuritySession(
        active, http_settings=settings(), enabled=True
    )
    assert not workflow.execute(preview=workflow.preview, confirmed=True).evidence
    assert not wire[0]


@pytest.mark.parametrize("index", [True, 0, 2, -1, "1"])
def test_invalid_selection(active, wire, index):
    with pytest.raises(HttpConfigurationError):
        application.prepare_authentication_security(
            active, http_settings=settings(), enabled=True, selected_index=index
        )
    assert not wire[0]


@pytest.mark.parametrize(
    "probes",
    [(Probe.JWT_ALG_NONE, Probe.JWT_ALG_NONE), (Probe.AUTHORIZATION_REMOVED,), ("jwt_alg_none",)],
)
def test_no_arbitrary_or_duplicate_probe_types(active, wire, probes):
    with pytest.raises(HttpConfigurationError):
        session(active, probes)
    assert not wire[0]


@pytest.mark.parametrize(
    "field,value",
    [
        ("query", "mutation { deleteUser }"),
        ("variables", {"id": "2"}),
        ("endpoint", "https://other.example/graphql"),
        ("operation", "other"),
    ],
)
def test_forged_preview_never_executes(active, wire, field, value):
    workflow = session(active)
    preview = replace(
        workflow.preview, selected_query=replace(workflow.preview.selected_query, **{field: value})
    )
    assert not workflow.execute(preview=preview, confirmed=True).evidence
    assert not wire[0]


@pytest.mark.parametrize(
    "document",
    [
        "mutation { currentUser }",
        "subscription { currentUser }",
        'query { currentUser(id: "1") { id } } query { currentUser(id: "1") { id } }',
        "query { other }",
        'query { alias: currentUser(id: "1") { id } }',
    ],
)
def test_inconsistent_retained_documents_rejected(active, wire, document):
    artifact = replace(active.executions[0].generated_query, query_text=document)
    safe = replace(
        active,
        query_generation=replace(active.query_generation, queries=(artifact,)),
        executions=(replace(active.executions[0], generated_query=artifact),),
    )
    assert not application.prepare_authentication_security(
        safe, http_settings=settings(), enabled=True
    ).candidates
    assert not wire[0]


@pytest.mark.parametrize(
    "status", [s for s in QueryExecutionStatus if s is not QueryExecutionStatus.SUCCESS]
)
def test_only_successful_attempts_are_candidates(active, status):
    safe = replace(active, executions=(replace(active.executions[0], status=status),))
    assert not application.prepare_authentication_security(
        safe, http_settings=settings(), enabled=True
    ).candidates


@pytest.mark.parametrize("failed,count", [(1, 1), (2, 3), (3, 3)])
def test_network_failure_consumes_attempt_and_independent_later_probe(active, wire, failed, count):
    wire[1]["network"] = {failed}
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert len(wire[0]) == result.attempted_request_count == count
    assert result.evidence[failed - 1].outcome is NestedOutcome.NETWORK_FAILURE
    assert result.evidence[failed - 1].policy_result.value == "unresolved"
    assert TOKEN not in repr(result) and not result.findings


@pytest.mark.parametrize(
    "status,body,outcome",
    [
        (200, {"data": {"currentUser": {"id": "1"}}}, "returned"),
        (200, {"data": None}, "indeterminate"),
        (200, {"data": {"currentUser": None}}, "indeterminate"),
        (200, {"data": {"other": 1}}, "indeterminate"),
        (200, {"errors": [{"message": "Invalid input"}]}, "indeterminate"),
        (200, {"errors": [{"message": "Forbidden", "path": ["other"]}]}, "indeterminate"),
        (
            200,
            {"errors": [{"extensions": {"code": "FORBIDDEN"}, "path": ["currentUser"]}]},
            "explicit_denial",
        ),
        (200, {"errors": [{"message": "Unauthorized"}]}, "explicit_denial"),
        (
            200,
            {"errors": [{"message": "Unauthorized"}, {"message": "Business error"}]},
            "indeterminate",
        ),
        (401, {}, "explicit_denial"),
        (403, {}, "explicit_denial"),
        (404, {}, "indeterminate"),
        (500, {}, "indeterminate"),
        (200, [], "indeterminate"),
        (200, "not GraphQL", "indeterminate"),
    ],
)
def test_conservative_response_classification(status, body, outcome):
    assert (
        classify_authentication_response(status, json.dumps(body).encode(), "currentUser").value
        == outcome
    )


@pytest.mark.parametrize(
    "claim,offset,kind",
    [
        ("exp", -3600, "expired_jwt_accepted"),
        ("nbf", 3600, "not_yet_valid_jwt_accepted"),
        ("iat", 3600, None),
        ("exp", -30, None),
    ],
)
def test_temporal_findings_use_original_baseline_not_inspection_time(
    active, wire, claim, offset, kind
):
    baseline = datetime(2025, 1, 1, tzinfo=UTC)
    safe = replace(
        active,
        execution_evidence=tuple(
            e.model_copy(update={"timestamp": baseline, "duration_seconds": 1})
            for e in active.execution_evidence
        ),
    )
    token = fake_token({claim: baseline.timestamp() + offset})
    wire[1]["original"] = token
    workflow = session(safe, (), token)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert len(wire[0]) == 1
    assert [f.finding_type.value for f in result.findings] == ([kind] if kind else [])


def test_supplied_unsigned_no_duplicate_probe_and_opaque_control(active, wire):
    for token, kinds in (
        (fake_token(header={"alg": "none"}), ["jwt_none_algorithm_accepted"]),
        ("PHASE26_OPAQUE_CANARY", []),
    ):
        wire[0].clear()
        wire[1]["original"] = token
        workflow = session(active, (), token)
        assert not workflow.preview.available_probes
        result = workflow.execute(preview=workflow.preview, confirmed=True)
        assert len(wire[0]) == 1
        assert [f.finding_type.value for f in result.findings] == kinds


def test_cross_origin_strips_generated_tokens_and_never_attributes_access(active, wire):
    wire[1]["redirect"] = True
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert result.attempted_request_count == 3 and len(wire[0]) == 5
    assert all(e.outcome is NestedOutcome.INDETERMINATE for e in result.evidence[1:])
    assert not result.findings


@pytest.mark.parametrize(
    "material", [TOKEN, token_variant(TOKEN, BOTH[0]), token_variant(TOKEN, BOTH[1]), COOKIE, PROXY]
)
def test_echoed_request_material_is_not_retained(active, wire, material):
    wire[1]["override"][1] = (200, {"data": {"currentUser": {"echo": material}}})
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert result.evidence[0].response_body is None
    assert result.evidence[0].response_material_withheld
    assert material not in repr(result)


def test_reports_console_ai_and_evidence_composition(active, wire, caplog):
    wire[1]["scenario"] = "signature-accepted"
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    base = ActiveExecutionScanResult(ActiveMutationPreviewResult(active, ()), (), False, (), ())
    scan = replace(base, authentication_token_security=result)
    assert scan.evidence == (*active.evidence, *result.evidence)
    assert build_ai_context(base) == build_ai_context(scan)
    report = build_report(scan)
    assert human_sections(report)[-1].title == "Safety Notice"
    texts = [repr(result), serialize_context(build_ai_context(scan)), caplog.text]
    for width in (48, 100):
        for verbose in (False, True):
            stream = StringIO()
            render_authentication(
                Console(file=stream, width=width, theme=CONSOLE_THEME), result, verbose=verbose
            )
            texts.append(stream.getvalue())
    for format in ReportFormat:
        rendered = render_report(report, format)
        texts.append(rendered)
        if format is ReportFormat.JSON:
            data = json.loads(rendered)["authentication_token_security"]
            assert data["attempted_request_count"] == 3
            assert data["selected_query"]["query"] == result.selected_query.query
            assert data["findings"][0]["baseline_evidence_id"] == str(
                result.selected_query.baseline_evidence_id
            )
        else:
            assert "Authentication &amp; Token" in rendered or "Authentication & Token" in rendered
            assert rendered.count("Safety Notice") == 1
    for material in (TOKEN, *(token_variant(TOKEN, p) for p in BOTH), COOKIE, PROXY, CLAIM_CANARY):
        assert all(material not in text for text in texts)
    assert len(wire[0]) == 3  # Presentation/reporting/AI context construction are local only.
    assert "authentication_token_security" not in json.loads(
        render_report(build_report(base), ReportFormat.JSON)
    )


def test_null_baseline_missing_evidence_and_unattempted_are_ineligible(active, phase_ten_scan):
    for safe in (
        phase_ten_scan(SDL)[0],
        replace(active, execution_evidence=()),
        replace(active, executions=(replace(active.executions[0], attempted=False),)),
    ):
        assert not application.prepare_authentication_security(
            safe, http_settings=settings(), enabled=True
        ).candidates


@pytest.mark.parametrize("during_control", [False, True])
def test_retained_artifact_changes_are_revalidated_before_each_request(
    active, wire, monkeypatch, during_control
):
    workflow = session(active)
    preview = workflow.preview
    if during_control:
        original = application._request

        def request(*args):
            evidence = original(*args)
            active.executions[0].generated_query.variables["id"] = "2"
            return evidence

        monkeypatch.setattr(application, "_request", request)
    else:
        active.executions[0].generated_query.variables["id"] = "2"
    result = workflow.execute(preview=preview, confirmed=True)
    assert result.attempted_request_count == len(wire[0]) == int(during_control)
    assert not result.findings
    assert all(item.evidence is None for item in result.executions[int(during_control) :])


@pytest.mark.parametrize(
    "headers",
    [
        (),
        (("Authorization", "Bearer"),),
        (("Authorization", "Basic PHASE26_SECRET"),),
        (("Authorization", "Bearer PHASE26_SECRET extra"),),
        (("Authorization", "Bearer PHASE26_SECRET"), ("authorization", "Bearer OTHER_SECRET")),
    ],
)
def test_carrier_errors_do_not_echo(headers):
    with pytest.raises(HttpConfigurationError) as error:
        application.bearer_token(HttpClientSettings(custom_headers=headers))
    assert "SECRET" not in str(error.value)
