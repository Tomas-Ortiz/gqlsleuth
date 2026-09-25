"""Offline CLI, independent consent, exact target requests, reports and privacy boundaries."""

import io
import json
from dataclasses import replace

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from fixtures.phase23_target import SDL, response_for
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application import mutation_authorization as application
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.mutation_authorization import parse_mutation_cases
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.mutation_authorization import render_mutation_authorization
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report

TARGET = "https://example.com/graphql"
OPTIONS = [
    "--mode",
    "active",
    "--mutation-auth-review",
    "--mutation-auth-case",
    "updateOrder:id=123",
]
SECRET = "PHASE23_AUTH_HEADER_SECRET"


@pytest.fixture
def controlled(monkeypatch):
    requests = []

    def transport(**kwargs):
        def handler(request):
            payload = json.loads(request.content) if request.method == "POST" else None
            requests.append((request.method, str(request.url), dict(request.headers), payload))
            return httpx.Response(200, json=response_for(request.method, payload))

        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    return requests


@pytest.mark.parametrize(
    "options",
    [
        ["--mutation-auth-review", "--mutation-auth-case", "updateOrder:id=123"],
        ["--mode", "active", "--mutation-auth-case", "updateOrder:id=123"],
        ["--mode", "active", "--mutation-auth-review"],
        OPTIONS + ["--mutation-auth-case", "updateOrder:id=123"],
        OPTIONS + ["--auth-context", "a", "--auth-context", "b"],
        OPTIONS + ["--expect-deny", "1"],
        OPTIONS[:-1] + ["bad-name:id=PHASE23_INVALID_SECRET"],
        OPTIONS[:-1] + ["updateOrder:id=PHASE23_INVALID_SECRET\n"],
    ],
)
def test_cli_errors_precede_network_without_secret_echo(monkeypatch, options):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid CLI sent HTTP"))
    result = CliRunner().invoke(
        cli.app, ["scan", TARGET, *options, "-H", f"Authorization: {SECRET}"]
    )
    assert result.exit_code == 2
    assert SECRET not in result.output and "PHASE23_INVALID_SECRET" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("interactive,confirmed", [(False, True), (True, False), (True, True)])
def test_cli_preview_confirmation_reports_and_disabled_invariance(
    controlled, monkeypatch, tmp_path, interactive, confirmed
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    monkeypatch.setattr(cli.typer, "prompt", lambda *args, **kwargs: "")
    confirmations = []

    def confirm(text, *, default):
        confirmations.append(text)
        assert default is False
        assert text == "Execute mutation authorization validation?"
        return confirmed

    monkeypatch.setattr(cli.typer, "confirm", confirm)
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
    before = CliRunner().invoke(cli.app, [*common, "-o", str(tmp_path / "off")])
    assert before.exit_code == 0, (before.exception, before.output)
    original = list(controlled)
    disabled = json.loads(next((tmp_path / "off").glob("*.json")).read_text())
    assert "mutation_authorization" not in disabled
    controlled.clear()
    result = CliRunner().invoke(cli.app, [*common, *OPTIONS[2:], "-o", str(tmp_path / "on")])
    assert result.exit_code == 0, (result.exception, result.output)
    count = int(interactive and confirmed)
    assert controlled[: len(original)] == original
    assert len(controlled) == len(original) + count
    assert len(confirmations) == int(interactive)
    assert "Active Mutation candidates" in result.output
    for text in (
        "Mutation Authorization Validation",
        "Target identifier",
        "123",
        "DENY",
        "Maximum requests: 1",
        "Variables:",
        "Test User",
        "test@example.com",
        "may modify server-side state",
    ):
        assert text in result.output
    assert SECRET not in result.output
    assert all(item[2]["authorization"] == SECRET for item in controlled)
    report = json.loads(next((tmp_path / "on").glob("*.json")).read_text())
    review = report["mutation_authorization"]
    assert review["attempted_request_count"] == count
    assert review["evaluation"]["status"] == ("violated" if count else "unresolved")
    assert not report["active"]["confirmed"]
    evidence = [
        item
        for item in report["evidence"]
        if item["evidence_type"] == "mutation_authorization_probe"
    ]
    assert len(evidence) == count
    if count:
        assert controlled[-1][3] == {
            "query": review["probe"]["query"],
            "variables": review["probe"]["variables"],
        }
    for extension in ("md", "html"):
        human = next((tmp_path / "on").glob(f"*.{extension}")).read_text(encoding="utf-8")
        assert human.count("Safety Notice") == 1
        assert human.index("Mutation Authorization Validation") < human.index("Safety Notice")
        assert SECRET not in human and "Phase 23" not in human


def test_three_active_consents_and_budgets_are_independent(controlled, monkeypatch, phase_ten_scan):
    safe = phase_ten_scan(SDL)[0]
    candidates = prepare_active_mutations(safe).candidates
    index = next(
        i
        for i, item in enumerate(candidates, 1)
        if item.generated_mutation.operation_name == "updateOrder"
    )
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    monkeypatch.setattr(
        cli.typer,
        "prompt",
        lambda text, **kwargs: str(index) if text.startswith("Select Mutations") else "",
    )
    calls = []

    def confirm(text, *, default):
        calls.append(text)
        assert default is False
        return text.startswith("Execute these")

    monkeypatch.setattr(cli.typer, "confirm", confirm)
    result = CliRunner().invoke(
        cli.app, ["scan", TARGET, *OPTIONS, "--idor-discovery", "--idor-seed", "order:id=999"]
    )
    assert result.exit_code == 0, (result.exception, result.output)
    assert calls == [
        "Execute bounded sequential object discovery?",
        "Execute mutation authorization validation?",
        "Execute these 1 selected Mutations?",
    ]
    mutations = [
        item[3] for item in controlled if item[3] and item[3]["query"].startswith("mutation")
    ]
    assert len(mutations) == 1 and mutations[0]["variables"]["id"] == "1"


def test_safe_and_disabled_do_not_prepare_or_consume_other_results(controlled, monkeypatch):
    monkeypatch.setattr(
        cli,
        "MutationAuthorizationSession",
        lambda *args, **kwargs: pytest.fail("Implicit Mutation authorization"),
    )
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    for options in (
        [],
        ["--mode", "active"],
        ["--mode", "active", "--idor-discovery", "--idor-seed", "order:id=123"],
    ):
        result = CliRunner().invoke(cli.app, ["scan", TARGET, *options])
        assert result.exit_code == 0, result.exception
        assert "Mutation Authorization Validation" not in result.output
    assert not any(item[3] and item[3]["query"].startswith("mutation") for item in controlled)


@pytest.mark.parametrize("width", [45, 100])
def test_reports_exact_preview_ai_exclusion_and_privacy(phase_ten_scan, monkeypatch, width):
    safe, baseline = phase_ten_scan(SDL)
    active = execute_selected_mutations(prepare_active_mutations(safe))
    ai = build_ai_context(active)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200, json={"data": {"updateOrder": {"id": "123", "name": "UNRELATED_BUSINESS_SECRET"}}}
        )

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    session = application.MutationAuthorizationSession(
        safe,
        cases=parse_mutation_cases(["updateOrder:id=123"]),
        enabled=True,
        http_settings=HttpClientSettings(custom_headers=(("Cookie", SECRET),)),
    )
    preview = session.preview
    result = session.execute(preview=preview, confirmed=True)
    composed = replace(active, mutation_authorization=result)
    assert build_ai_context(composed).operations == ai.operations
    assert composed.evidence[:-1] == active.evidence
    assert composed.evidence[-1] == result.evidence[0]
    assert SECRET not in repr(result)
    console_output = io.StringIO()
    console = Console(file=console_output, width=width, theme=CONSOLE_THEME)
    render_mutation_authorization(console, preview, preview=True)
    render_mutation_authorization(console, result)
    assert SECRET not in console_output.getvalue()
    assert "UNRELATED_BUSINESS_SECRET" not in console_output.getvalue()
    report = build_report(composed)
    sections = human_sections(report)
    assert sections[-1].title == "Safety Notice"
    assert sum(item.title == "Safety Notice" for item in sections) == 1
    human_section = next(
        item for item in sections if item.title == "Mutation Authorization Validation"
    )
    assert dict(human_section.entries[0].code_blocks)["graphql"] == preview.probe.query
    assert json.loads(dict(human_section.entries[0].code_blocks)["json"]) == preview.probe.variables
    for format in ReportFormat:
        rendered = render_report(report, format)
        assert SECRET not in rendered
        if format is not ReportFormat.JSON:
            assert "UNRELATED_BUSINESS_SECRET" not in rendered
            for word in (
                "victim",
                "attacker",
                "another user's object",
                "IDOR confirmed",
                "BOLA confirmed",
            ):
                assert word not in rendered
    assert len(requests) == 1 and requests[0].headers["cookie"] == SECRET


def test_help_exposes_capability_names():
    result = CliRunner().invoke(cli.app, ["scan", "--help"], env={"COLUMNS": "160"})
    assert result.exit_code == 0
    assert "--mutation-auth-review" in result.output and "--mutation-auth-case" in result.output
    assert "Phase 23" not in result.output
