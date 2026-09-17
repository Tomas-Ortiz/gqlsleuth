"""Independent ACTIVE consent, unchanged prior requests, reports, AI and header boundaries."""

import base64
import io
import json
from dataclasses import replace

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from fixtures.phase22_target import SDL, response_for
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application import sequential_discovery as application
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.models import EvidenceType
from gqlsleuth.domain.sequential_discovery import parse_discovery_seeds
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.sequential_discovery import render_sequential_discovery
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report

TARGET = "https://example.com/graphql"
OPTIONS = ["--mode", "active", "--idor-discovery", "--idor-seed", "order:id=123"]
SECRET = "PHASE22_HEADER_SECRET"


@pytest.fixture
def controlled(monkeypatch):
    requests = []

    def transport(**kwargs):
        def handler(request):
            requests.append(
                (
                    request.method,
                    str(request.url),
                    tuple(request.headers.multi_items()),
                    request.content,
                )
            )
            payload = json.loads(request.content) if request.method == "POST" else None
            if payload and payload["query"].startswith("mutation"):
                return httpx.Response(200, json={"data": {"updateOrder": {"id": "1"}}})
            return httpx.Response(200, json=response_for(request.method, payload))

        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    return requests


@pytest.mark.parametrize(
    "options",
    [
        ["--idor-discovery", "--idor-seed", "order:id=123"],
        ["--mode", "active", "--idor-seed", "order:id=123"],
        ["--mode", "active", "--idor-discovery"],
        OPTIONS + ["--idor-seed", "order:id=1", "--idor-seed", "order:id=2"],
        OPTIONS + ["--auth-context", "a", "--auth-context", "b"],
        OPTIONS + ["--expect-deny", "1"],
        OPTIONS + ["--object-auth-review", "--object-auth-case", "order:id=123"],
        ["--mode", "active", "--idor-discovery", "--idor-seed", "order:id=PHASE22_BAD_SECRET"],
    ],
)
def test_invalid_cli_precedes_network(monkeypatch, options):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid CLI sent HTTP"))
    result = CliRunner().invoke(cli.app, ["scan", TARGET, *options])
    assert result.exit_code == 2
    assert "PHASE22_BAD_SECRET" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "interactive,input_text,count",
    [
        (False, "", 0),
        (True, "\nn\n\n", 0),
        (True, "\n\n\n", 0),
        (True, "\ny\n\n", 3),
    ],
)
def test_cli_confirmation_reports_and_prior_request_invariance(
    controlled, monkeypatch, tmp_path, interactive, input_text, count
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    common = [
        "scan",
        TARGET,
        "--mode",
        "active",
        "-H",
        f"Authorization: {SECRET}",
        "-f",
        "json,markdown,html",
    ]
    before = CliRunner().invoke(cli.app, [*common, "-o", str(tmp_path / "off")], input="\n\n")
    assert before.exit_code == 0, before.exception
    original = list(controlled)
    baseline = json.loads(next((tmp_path / "off").glob("*.json")).read_text())
    assert "sequential_object_discovery" not in baseline
    controlled.clear()
    after = CliRunner().invoke(
        cli.app, [*common, *OPTIONS[2:], "-v", "-o", str(tmp_path / "on")], input=input_text
    )
    assert after.exit_code == 0, (after.exception, after.output)
    assert controlled[: len(original)] == original
    requests = controlled[len(original) :]
    assert len(requests) == count
    assert [json.loads(item[3])["variables"]["id"] for item in requests] == (
        ["123", "122", "124"] if count else []
    )
    assert all(dict(item[2])["authorization"] == SECRET for item in controlled)
    assert SECRET not in after.output
    assert "Active Mutation candidates" in after.output
    assert after.output.count("Execute bounded sequential object discovery?") == int(interactive)
    assert "Execute these" not in after.output
    report = json.loads(next((tmp_path / "on").glob("*.json")).read_text())
    review = report["sequential_object_discovery"]
    assert review["attempted_request_count"] == count
    assert review["offsets"] == [-1, 1]
    assert len(review["candidates"]) == int(count > 0)
    assert [item["requested_identifier"] for item in review["probes"]] == ["123", "122", "124"]
    evidence = [
        item for item in report["evidence"] if item["evidence_type"] == "sequential_object_probe"
    ]
    assert len(evidence) == count
    for item in evidence:
        assert item["execution_mode"] == "active"
        body = base64.b64decode(item["response_body"]["data"])
        assert isinstance(json.loads(body), dict)
        assert item["variables"] == {"id": item["requested_identifier"]}
    for extension in ("md", "html"):
        human = next((tmp_path / "on").glob(f"*.{extension}")).read_text(encoding="utf-8")
        assert human.count("Safety Notice") == 1
        assert human.index("Bounded Sequential Object Discovery") < human.index("Safety Notice")
        assert "Operator-supplied seed" in human.replace("\\-", "-")
        assert "generated adjacent identifier" in human
        assert SECRET not in human
    assert not report["active"]["confirmed"]


def test_decline_does_not_cancel_mutation_and_confirmation_is_separate(controlled, monkeypatch):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    result = CliRunner().invoke(cli.app, ["scan", TARGET, *OPTIONS], input="\nn\n1\ny\n")
    assert result.exit_code == 0, (result.exception, result.output)
    payloads = [json.loads(item[3]) for item in controlled if item[0] == "POST"]
    assert sum(item["query"].startswith("mutation") for item in payloads) == 1
    assert not any(
        item.get("variables", {}).get("id") in {"123", "122", "124"} for item in payloads
    )
    assert result.output.count("Execute bounded sequential object discovery?") == 1
    assert result.output.count("Execute these 1 selected Mutations?") == 1


def test_safe_never_enters_sequential_stage(controlled, monkeypatch):
    monkeypatch.setattr(
        cli, "prepare_sequential_discovery", lambda *args, **kwargs: pytest.fail("SAFE preparation")
    )
    result = CliRunner().invoke(cli.app, ["scan", TARGET])
    assert result.exit_code == 0
    assert "Bounded Sequential Object Discovery" not in result.output


@pytest.mark.parametrize("supplied", [False, True])
def test_direct_reports_console_and_ai_exclusion(phase_ten_scan, monkeypatch, supplied):
    safe = phase_ten_scan(SDL)[0]
    requests = []
    raw = b'{"data":{"order":{"id":"123","email":"PHASE22_BUSINESS_SECRET"}}}'

    def handler(request):
        requests.append(request)
        return httpx.Response(200, content=raw)

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    settings = HttpClientSettings(custom_headers=(("X-API-Key", SECRET),) if supplied else ())
    result = application.execute_sequential_discovery(
        safe,
        seeds=parse_discovery_seeds(["order:id=123"]),
        enabled=True,
        confirmed=True,
        http_settings=settings,
    )
    assert len(requests) == 3
    assert all((request.headers.get("x-api-key") == SECRET) is supplied for request in requests)
    active = execute_selected_mutations(prepare_active_mutations(safe))
    enhanced = replace(active, sequential_object_discovery=result)
    assert build_ai_context(active) == build_ai_context(enhanced)
    assert enhanced.evidence[: len(safe.evidence)] == safe.evidence
    report = build_report(enhanced)
    assert human_sections(report)[-1].title == "Safety Notice"
    for verbose in (False, True):
        stream = io.StringIO()
        render_sequential_discovery(
            Console(file=stream, width=60, theme=CONSOLE_THEME), result, verbose=verbose
        )
        assert SECRET not in stream.getvalue()
        assert "PHASE22_BUSINESS_SECRET" not in stream.getvalue()
    for format in ReportFormat:
        rendered = render_report(report, format)
        assert SECRET not in rendered
        if format is not ReportFormat.JSON:
            assert "PHASE22_BUSINESS_SECRET" not in rendered
        else:
            parsed = json.loads(rendered)
            assert parsed["evidence_counts"][EvidenceType.SEQUENTIAL_OBJECT_PROBE.value] == 3
            for evidence in parsed["sequential_object_discovery"]["executions"]:
                assert base64.b64decode(evidence["evidence"]["response_body"]["data"]) == raw


def test_redirect_header_scope_and_fresh_cookies(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL)[0]
    requests = []

    def handler(request):
        requests.append(request)
        assert "learned" not in request.headers.get("cookie", "")
        if request.url.host == "example.com":
            if request.url.path == "/graphql":
                assert request.headers["authorization"] == SECRET
                return httpx.Response(307, headers={"location": "/same"})
            assert request.headers["cookie"] == "session=" + SECRET
            return httpx.Response(307, headers={"location": "https://other.example/graphql"})
        assert "authorization" not in request.headers and "cookie" not in request.headers
        assert "x-api-key" not in request.headers
        identifier = json.loads(request.content)["variables"]["id"]
        return httpx.Response(
            200,
            json={"data": {"order": {"id": identifier}}},
            headers={"set-cookie": "learned=secret"},
        )

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    result = application.execute_sequential_discovery(
        safe,
        seeds=parse_discovery_seeds(["order:id=123"]),
        enabled=True,
        confirmed=True,
        http_settings=HttpClientSettings(
            custom_headers=(
                ("Authorization", SECRET),
                ("Cookie", "session=" + SECRET),
                ("X-API-Key", SECRET),
            )
        ),
    )
    assert result.attempted_request_count == 3
    assert len(requests) == 9  # Each existing-client send follows two controlled redirects.
    assert {json.loads(item.content)["variables"]["id"] for item in requests} == {
        "123",
        "122",
        "124",
    }


def test_cli_ai_call_count_unchanged(controlled, monkeypatch):
    calls = []

    def interpret(result):
        calls.append(build_ai_context(result))
        return None

    monkeypatch.setattr(cli, "interpret_completed_scan", interpret)
    monkeypatch.setattr(cli, "render_ai", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    before = CliRunner().invoke(cli.app, ["scan", TARGET, "--mode", "active", "--ai"], input="\n\n")
    after = CliRunner().invoke(cli.app, ["scan", TARGET, *OPTIONS, "--ai"], input="\ny\n\n")
    assert before.exit_code == after.exit_code == 0, (before.exception, after.exception)
    assert len(calls) == 2 and calls[0] == calls[1]
