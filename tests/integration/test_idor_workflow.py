"""CLI consent, single-context isolation, reports and AI regression using mock transports."""

import io
import json
from dataclasses import replace

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from fixtures.phase22_target import SDL
from fixtures.phase25_target import response_for
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application import idor as application
from gqlsleuth.application.active_execution import (
    ActiveExecutionScanResult,
    ActiveMutationPreviewResult,
)
from gqlsleuth.application.scan_configuration import map_auth_context_inputs
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.sequential_discovery import parse_discovery_seeds
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.idor import render_idor
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report

TARGET = "https://example.com/graphql"
OPTIONS = ["--mode", "active", "--idor-review", "--idor-seed", "order:id=123"]
SECRET = "PHASE25_CONTEXT_A_SECRET"


@pytest.fixture
def controlled(monkeypatch):
    requests = []

    def factory(**kwargs):
        def handler(request):
            requests.append(request)
            payload = json.loads(request.content) if request.method == "POST" else None
            return httpx.Response(
                200,
                json=response_for(
                    request.method,
                    payload,
                    authenticated=bool(request.headers.get("authorization")),
                ),
            )

        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", factory)
    return requests


@pytest.mark.parametrize(
    "extra",
    [
        ["--idor-review", "--idor-seed", "order:id=123"],
        ["--mode", "active", "--idor-review"],
        OPTIONS + ["--idor-discovery"],
        OPTIONS + ["--auth-context", "a=Cookie: fake", "--auth-context", "b=X-Key: fake"],
        OPTIONS + ["--auth-context", "bare"],
        OPTIONS + ["--auth-context", "a=Authorization: " + SECRET, "-H", "Cookie: fake"],
        OPTIONS + ["--auth-context", "a=Authorization: " + SECRET, "--sensitive-input-review"],
        OPTIONS + ["--auth-context", "a=Authorization: " + SECRET, "--mutation-auth-review"],
        OPTIONS + ["--auth-context", "a=Authorization: " + SECRET, "--nested-auth-review"],
        OPTIONS + ["--auth-context", "a=Authorization: " + SECRET, "--ai"],
        ["--auth-context", "a=Authorization: " + SECRET],
        ["--mode", "active", "--auth-context", "a=Authorization: " + SECRET],
    ],
)
def test_invalid_combinations_before_http(monkeypatch, extra):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid CLI sent HTTP"))
    result = CliRunner().invoke(cli.app, ["scan", TARGET, *extra])
    assert result.exit_code == 2
    assert SECRET not in result.output and "Traceback" not in result.output


@pytest.mark.parametrize("named", [False, True])
@pytest.mark.parametrize(
    "interactive,consent,count", [(False, "", 0), (True, "n", 0), (True, "", 0), (True, "y", 3)]
)
def test_cli_consent_reports_isolated_named_path(
    controlled, monkeypatch, tmp_path, named, interactive, consent, count
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    options = ["scan", TARGET, *OPTIONS, "-f", "json,markdown,html", "-o", str(tmp_path)]
    if named:
        options += [
            "--auth-context",
            "usuario=Authorization: Bearer " + SECRET,
            "--auth-context",
            "usuario=X-Tenant-ID: PHASE25_TENANT_SECRET",
        ]
        for name in (
            "run_differential_scan",
            "_run_multiplicity_stage",
            "_run_depth_stage",
            "_run_active_stage",
        ):
            monkeypatch.setattr(
                cli, name, lambda *args, **kwargs: pytest.fail("Unrelated named ACTIVE stage")
            )
    input_text = consent + "\n" if named else "\n" + consent + "\n\n"
    result = CliRunner().invoke(cli.app, options, input=input_text)
    assert result.exit_code == 0, (result.exception, result.output)
    probes = [
        req
        for req in controlled
        if req.method == "POST"
        and json.loads(req.content).get("variables", {}).get("id") in {"123", "122", "124"}
    ]
    assert len(probes) == count
    assert result.output.count("Execute IDOR / BOLA detection?") == int(interactive)
    assert SECRET not in result.output and "PHASE25_TENANT_SECRET" not in result.output
    assert all(
        (req.headers.get("authorization") == "Bearer " + SECRET) is named for req in controlled
    )
    report = json.loads(next(tmp_path.glob("*.json")).read_text())
    detection = report["idor_bola_detection"]
    assert detection["attempted_request_count"] == count
    assert len(detection["findings"]) == (1 if named else 2) * bool(count)
    assert detection["context_type"] == ("authenticated" if named else "anonymous")
    assert "contexts" not in report
    evidence = [item for item in report["evidence"] if item["evidence_type"] == "idor_bola_probe"]
    assert len(evidence) == count
    assert all(item["request_method"] == "POST" for item in evidence)
    for suffix in ("md", "html"):
        human = next(tmp_path.glob("*." + suffix)).read_text(encoding="utf-8")
        assert human.count("Safety Notice") == 1
        assert human.index("IDOR / BOLA Detection") < human.index("Safety Notice")
        assert ("IDOR / BOLA Findings" in human) is bool(count)
        assert SECRET not in human and "PHASE25_TENANT_SECRET" not in human
        assert "operator" in human and "DENY" in human


def test_disabled_requests_identical_and_header_compatibility(controlled, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    common = ["scan", TARGET, "--mode", "active", "-H", "X-API-Key: " + SECRET, "-f", "json"]
    off = CliRunner().invoke(cli.app, [*common, "-o", str(tmp_path / "off")])
    assert off.exit_code == 0
    before = [(item.method, str(item.url), item.content, dict(item.headers)) for item in controlled]
    assert "idor_bola_detection" not in json.loads(
        next((tmp_path / "off").glob("*.json")).read_text()
    )
    controlled.clear()
    on = CliRunner().invoke(cli.app, [*common, *OPTIONS[2:], "-o", str(tmp_path / "on")])
    assert on.exit_code == 0
    assert before == [
        (item.method, str(item.url), item.content, dict(item.headers)) for item in controlled
    ]
    assert (
        json.loads(next((tmp_path / "on").glob("*.json")).read_text())["idor_bola_detection"][
            "context_type"
        ]
        == "authenticated"
    )


def test_normal_phase15_cardinality_and_shared_header_parser():
    with pytest.raises(HttpConfigurationError):
        map_auth_context_inputs(["label=Cookie: fake"])
    assert len(map_auth_context_inputs(["a", "b"])) == 2
    result = map_auth_context_inputs(
        ["usuario=Cookie: fake", "usuario=X-API-Key: fake"],
        mode=ScanMode.ACTIVE,
        idor_review=True,
    )
    assert result[0].headers == (("Cookie", "fake"), ("X-API-Key", "fake"))
    with pytest.raises(HttpConfigurationError):
        map_auth_context_inputs(
            ["usuario=Cookie: fake\r\nX-Key: fake"], mode=ScanMode.ACTIVE, idor_review=True
        )


def test_reports_ai_and_console_do_not_send_or_leak(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL)[0]
    requests = []

    def handler(request):
        requests.append(request)
        payload = json.loads(request.content)
        return httpx.Response(200, json=response_for("POST", payload))

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    workflow = application.IdorSession(
        safe,
        seeds=parse_discovery_seeds(["order:id=123"]),
        enabled=True,
        http_settings=HttpClientSettings(custom_headers=(("Cookie", SECRET),)),
        context_label="arbitrary",
    )
    detection = workflow.execute(preview=workflow.preview, confirmed=True)
    original = ActiveExecutionScanResult(ActiveMutationPreviewResult(safe, ()), (), False, (), ())
    active = replace(original, idor_bola_detection=detection)
    assert build_ai_context(active).operations == build_ai_context(original).operations
    assert active.evidence[: len(safe.evidence)] == safe.evidence
    report = build_report(active)
    assert human_sections(report)[-1].title == "Safety Notice"
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert canonical["idor_bola_detection"]["findings"][0]["evidence_id"] == str(
        detection.findings[0].evidence_id
    )
    for format in ReportFormat:
        rendered = render_report(report, format)
        assert SECRET not in rendered
    for width in (54, 100):
        for verbose in (False, True):
            stream = io.StringIO()
            render_idor(
                Console(file=stream, width=width, theme=CONSOLE_THEME), detection, verbose=verbose
            )
            assert "IDOR / BOLA" in stream.getvalue() and SECRET not in stream.getvalue()
            assert "victim" not in stream.getvalue() and "another user's" not in stream.getvalue()
    assert len(requests) == 3


def test_redirect_credential_scope_and_cookie_isolation(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL)[0]
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.host == "example.com":
            assert request.headers["cookie"] == SECRET
            return httpx.Response(
                307,
                headers={
                    "location": "https://other.example/graphql",
                    "set-cookie": "learned=private",
                },
            )
        assert (
            "cookie" not in request.headers
            and "authorization" not in request.headers
            and "x-tenant-id" not in request.headers
        )
        payload = json.loads(request.content)
        return httpx.Response(200, json={"data": {"order": {"id": payload["variables"]["id"]}}})

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    workflow = application.IdorSession(
        safe,
        seeds=parse_discovery_seeds(["order:id=123"]),
        enabled=True,
        http_settings=HttpClientSettings(
            custom_headers=(("Cookie", SECRET), ("Authorization", SECRET), ("X-Tenant-ID", SECRET))
        ),
    )
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert result.attempted_request_count == 3
    assert len(requests) == 6  # existing redirect behavior, no probe retries
