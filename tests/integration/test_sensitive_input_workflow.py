"""Offline end-to-end consent, exact requests/evidence, reports and unchanged prior capabilities."""

import io
import json
from dataclasses import replace

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from fixtures.phase24_target import SDL, response_for
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application import sensitive_input as application
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.models import EvidenceType
from gqlsleuth.domain.sensitive_input import parse_sensitive_case
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.sensitive_input import (
    render_sensitive_review,
    render_sensitive_validation,
)
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report

TARGET = "https://example.com/graphql"
OPTIONS = [
    "--mode",
    "active",
    "--sensitive-input-review",
    "--sensitive-input-case",
    "updateUser:input.isStaff=true",
    "--sensitive-input-target",
    "id=123",
]
SECRET = "PHASE24_HEADER_SECRET"


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
        OPTIONS[2:],
        OPTIONS[:2] + OPTIONS[3:],
        ["--mode", "active", "--sensitive-input-review"],
        OPTIONS + ["--sensitive-input-case", "updateUser:input.role=ADMIN"],
        OPTIONS + ["--auth-context", "a", "--auth-context", "b"],
        OPTIONS[:4] + ["bad-name:input.role=SECRET\n"],
        ["--sensitive-input-target", "id=SECRET"],
    ],
)
def test_invalid_cli_precedes_network(monkeypatch, options):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid CLI sent HTTP"))
    result = CliRunner().invoke(
        cli.app, ["scan", TARGET, *options, "-H", "Authorization: " + SECRET]
    )
    assert result.exit_code == 2
    assert (
        SECRET not in result.output
        and "SECRET\n" not in result.output
        and "Traceback" not in result.output
    )


@pytest.mark.parametrize("interactive,confirmed", [(False, True), (True, False), (True, True)])
def test_cli_complete_preview_requests_and_reports(
    controlled, monkeypatch, tmp_path, interactive, confirmed
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    monkeypatch.setattr(cli.typer, "prompt", lambda *args, **kwargs: "")
    confirmations = []

    def confirm(text, *, default):
        confirmations.append(text)
        assert default is False and text == "Execute sensitive input validation?"
        return confirmed

    monkeypatch.setattr(cli.typer, "confirm", confirm)
    common = [
        "scan",
        TARGET,
        "--mode",
        "active",
        "-H",
        "Authorization: " + SECRET,
        "-f",
        "json,markdown,html",
    ]
    before = CliRunner().invoke(cli.app, [*common, "-o", str(tmp_path / "off")])
    assert before.exit_code == 0, (before.exception, before.output)
    original = list(controlled)
    disabled = json.loads(next((tmp_path / "off").glob("*.json")).read_text())
    assert "sensitive_input_validation" not in disabled
    assert disabled["sensitive_input_review"]
    controlled.clear()
    after = CliRunner().invoke(cli.app, [*common, *OPTIONS[2:], "-o", str(tmp_path / "on")])
    assert after.exit_code == 0, (after.exception, after.output)
    count = int(interactive and confirmed)
    assert controlled[: len(original)] == original
    assert len(controlled) == len(original) + count
    assert len(confirmations) == int(interactive)
    assert SECRET not in after.output
    for text in (
        "Sensitive Input Validation",
        "isStaff",
        "true",
        "DENY",
        "123",
        "Variables:",
        "Test User",
        "Maximum requests: 1",
        "may change server-side state",
        "does not prove persistence",
    ):
        assert text in after.output
    report = json.loads(next((tmp_path / "on").glob("*.json")).read_text())
    validation = report["sensitive_input_validation"]
    assert validation["attempted_request_count"] == count
    assert validation["evaluation"]["status"] == ("violated" if count else "unresolved")
    assert not report["active"]["confirmed"]
    evidence = [
        item for item in report["evidence"] if item["evidence_type"] == "sensitive_input_probe"
    ]
    assert len(evidence) == count
    if count:
        assert controlled[-1][3] == {
            "query": validation["probe"]["query"],
            "variables": {"id": "123", "input": {"displayName": "Test User", "isStaff": True}},
        }
        assert evidence[0]["value_matches"] is True and evidence[0]["target_id_matches"] is True
    assert all(item[2]["authorization"] == SECRET for item in controlled)
    for ext in ("md", "html"):
        text = next((tmp_path / "on").glob(f"*.{ext}")).read_text(encoding="utf-8")
        assert "Sensitive Input Review" in text and "Sensitive Input Validation" in text
        assert text.count("Safety Notice") == 1
        assert text.index("Sensitive Input Validation") < text.index("Safety Notice")
        assert SECRET not in text and "Phase 24" not in text


def test_active_consents_are_independent(controlled, monkeypatch, phase_ten_scan):
    safe = phase_ten_scan(SDL)[0]
    candidates = prepare_active_mutations(safe).candidates
    index = next(
        i
        for i, c in enumerate(candidates, 1)
        if c.generated_mutation.operation_name == "updateUser"
    )
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    monkeypatch.setattr(
        cli.typer,
        "prompt",
        lambda text, **kwargs: str(index) if text.startswith("Select Mutations") else "",
    )
    calls = []

    def confirm(text, *, default):
        assert default is False
        calls.append(text)
        return text.startswith("Execute these")

    monkeypatch.setattr(cli.typer, "confirm", confirm)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            *OPTIONS,
            "--mutation-auth-review",
            "--mutation-auth-case",
            "updateUser:id=456",
        ],
    )
    assert result.exit_code == 0, (result.exception, result.output)
    assert calls == [
        "Execute mutation authorization validation?",
        "Execute sensitive input validation?",
        "Execute these 1 selected Mutations?",
    ]
    requests = [r[3] for r in controlled if r[3] and r[3]["query"].startswith("mutation")]
    assert len(requests) == 1 and requests[0]["variables"] == {
        "id": "1",
        "input": {"displayName": "Test User"},
    }


@pytest.mark.parametrize(
    "entry,target,outcome,policy",
    [
        ("updateUser:input.isStaff=true", "id=123", "target_value_returned", "violated"),
        ("updateUser:input.isStaff=true", "id=deny", "explicit_denial", "satisfied"),
        ("updateUser:input.isStaff=true", "id=business", "indeterminate", "unresolved"),
        ("updateUser:input.isStaff=true", "id=wrong-value", "indeterminate", "unresolved"),
        ("updateUser:input.isStaff=true", "id=wrong-id", "indeterminate", "unresolved"),
        ("updateUser:input.role=ADMIN", "id=123", "target_value_returned", "violated"),
        ("updateProfile:input.isStaff=true", None, "target_value_returned", "violated"),
    ],
)
def test_exactly_one_value_no_read_after_write_and_evidence(
    phase_ten_scan, monkeypatch, entry, target, outcome, policy
):
    safe = phase_ten_scan(SDL)[0]
    requests = []
    responses = []

    def handler(request):
        payload = json.loads(request.content)
        requests.append((request.method, payload))
        raw = json.dumps(response_for(request.method, payload)).encode()
        responses.append(raw)
        return httpx.Response(200, content=raw, headers={"X-Test": "retained"})

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    session = application.SensitiveInputSession(
        safe, case=parse_sensitive_case([entry], target), enabled=True
    )
    preview = session.preview
    result = session.execute(preview=preview, confirmed=True)
    assert session.execute(preview=preview, confirmed=True) == result
    assert requests == [
        ("POST", {"query": preview.probe.query, "variables": preview.probe.variables})
    ]
    assert result.attempted_request_count == 1
    assert result.execution.outcome.value == outcome and result.evaluation.status.value == policy
    assert bool(result.violation) == (policy == "violated")
    evidence = result.evidence[0]
    assert evidence.evidence_type is EvidenceType.SENSITIVE_INPUT_PROBE
    assert evidence.query == preview.probe.query and evidence.variables == preview.probe.variables
    assert (
        evidence.supplied_value == preview.probe.typed_value and evidence.expected.value == "deny"
    )
    assert (
        evidence.response_body == responses[0] and evidence.response_headers["x-test"] == "retained"
    )
    assert result.evaluation.source_evidence_ids == (evidence.evidence_id,)


def test_local_and_active_reports_ai_and_secret_boundaries(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL)[0]
    active = execute_selected_mutations(prepare_active_mutations(safe))
    stripped = replace(
        safe, query_generation=replace(safe.query_generation, sensitive_input_review=())
    )
    assert build_ai_context(safe).operations == build_ai_context(stripped).operations
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "data": {"updateUser": {"id": "123", "isStaff": True, "other": "BUSINESS_SECRET"}}
            },
        )

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    session = application.SensitiveInputSession(
        safe,
        case=parse_sensitive_case(["updateUser:input.isStaff=true"], "id=123"),
        enabled=True,
        http_settings=HttpClientSettings(custom_headers=(("Cookie", SECRET),)),
    )
    result = session.execute(preview=session.preview, confirmed=True)
    composed = replace(active, sensitive_input_validation=result)
    assert build_ai_context(composed).operations == build_ai_context(active).operations
    assert composed.evidence == active.evidence + result.evidence
    for width in (45, 100):
        output = io.StringIO()
        console = Console(file=output, theme=CONSOLE_THEME, width=width)
        render_sensitive_review(console, safe.query_generation.sensitive_input_review, verbose=True)
        render_sensitive_validation(console, session.preview, preview=True)
        render_sensitive_validation(console, result)
        assert SECRET not in output.getvalue() and "BUSINESS_SECRET" not in output.getvalue()
        assert "<VALUE>" in output.getvalue() and "<ID>" in output.getvalue()
    report = build_report(composed)
    sections = human_sections(report)
    assert sections[-1].title == "Safety Notice"
    for format in ReportFormat:
        text = render_report(report, format)
        assert SECRET not in text
        if format is not ReportFormat.JSON:
            assert "BUSINESS_SECRET" not in text
            assert text.count("Safety Notice") == 1 and "Phase 24" not in text
            assert "Persistence and broader business impact" in text
    assert len(requests) == 1 and requests[0].headers["cookie"] == SECRET


def test_safe_named_review_and_disabled_no_chaining(controlled, monkeypatch, tmp_path):
    monkeypatch.setattr(
        cli,
        "SensitiveInputSession",
        lambda *args, **kwargs: pytest.fail("Implicit ACTIVE validation"),
    )
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    for options in (
        [],
        ["--mode", "active"],
        ["--mode", "active", "--mutation-auth-review", "--mutation-auth-case", "updateUser:id=123"],
        ["--auth-context", "one", "--auth-context", "two"],
    ):
        result = CliRunner().invoke(
            cli.app, ["scan", TARGET, *options, "-f", "markdown,html", "-o", str(tmp_path)]
        )
        assert result.exit_code == 0, (result.exception, result.output)
        assert "Sensitive Input Review" in result.output
        assert "Sensitive Input Validation" not in result.output
    for file in tmp_path.iterdir():
        text = file.read_text(encoding="utf-8")
        assert "Sensitive Input Review" in text and text.count("Safety Notice") == 1
    assert not any(r[3] and r[3]["query"].startswith("mutation") for r in controlled)
