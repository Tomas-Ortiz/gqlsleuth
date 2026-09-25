"""Full CLI with mock HTTP and one real loopback WebSocket; never public targets."""

import json

import httpx
import pytest
from typer.testing import CliRunner

from fixtures.phase30_target import LocalSubscriptionTarget, http_response
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application.safe_execution import run_safe_execution_scan
from gqlsleuth.application.subscriptions import SubscriptionSecuritySession
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings


@pytest.fixture
def controlled(monkeypatch):
    requests = []

    def respond(request):
        requests.append(request)
        return http_response(request)

    monkeypatch.setattr(
        "httpx._client.HTTPTransport", lambda **kwargs: httpx.MockTransport(respond)
    )
    monkeypatch.setattr(cli, "_run_multiplicity_stage", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_run_depth_stage", lambda *args, **kwargs: None)
    return requests


@pytest.mark.parametrize(
    "options",
    [
        ["--subscription-review"],
        ["--subscription-expect-deny"],
        ["--subscription-variables", "{}"],
        ["--subscription-init-payload", "{}"],
        ["--subscription-ws-url", "ws://127.0.0.1/graphql"],
        ["--mode", "active", "--subscription-review", "--auth-context", "label"],
        ["--mode", "active", "--subscription-review", "--subscription-variables", "[]"],
        ["--mode", "active", "--subscription-review", "--subscription-init-payload", "CANARY"],
        [
            "--mode",
            "active",
            "--subscription-review",
            "--subscription-init-payload",
            "{}",
            "--subscription-init-payload",
            "{}",
        ],
    ],
)
def test_invalid_flags_before_http(monkeypatch, options):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Unexpected HTTP"))
    result = CliRunner().invoke(cli.app, ["scan", "http://127.0.0.1/graphql", *options])
    assert result.exit_code == 2
    assert "Traceback" not in result.output and "CANARY" not in result.output


@pytest.mark.parametrize(
    "interactive,inputs,count,confirmations",
    [
        (False, "", 0, 0),
        (True, "\n", 0, 0),
        (True, "2\n\n", 0, 1),
        (True, "2\nn\n", 0, 1),
        (True, "2\ny\n", 1, 1),
        (True, "all\n*\n1,2\n1-2\n0\n3\n2\ny\n", 1, 1),
    ],
)
def test_selection_confirmation_reports(
    controlled, monkeypatch, tmp_path, interactive, inputs, count, confirmations
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    with LocalSubscriptionTarget("init-required") as target:
        result = CliRunner().invoke(
            cli.app,
            [
                "scan",
                target.target,
                "--mode",
                "active",
                "--subscription-review",
                "--subscription-expect-deny",
                "--subscription-init-payload",
                '{"Authorization":"Bearer PHASE30_INIT_SECRET"}',
                "-H",
                "Authorization: Bearer PHASE30_HEADER_SECRET",
                "-f",
                "json,markdown,html",
                "-o",
                str(tmp_path),
            ],
            input=inputs,
        )
        assert result.exit_code == 0, (result.exception, result.output)
        assert target.connections == target.subscriptions == count
        if count:
            assert target.headers[0]["authorization"] == "Bearer PHASE30_HEADER_SECRET"
            assert target.messages[0]["payload"]["Authorization"] == "Bearer PHASE30_INIT_SECRET"
    report = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    stage = report["subscription_security"]
    assert len(stage["attempts"]) == len(stage["findings"]) == count
    assert (
        sum(e["evidence_type"] == "subscription_security_probe" for e in report["evidence"])
        == count
    )
    assert (
        result.output.count("Execute subscription / WebSocket security validation?")
        == confirmations
    )
    for content in [result.output, *(p.read_text(encoding="utf-8") for p in tmp_path.iterdir())]:
        assert "PHASE30_HEADER_SECRET" not in content and "PHASE30_INIT_SECRET" not in content
    for extension in ("md", "html"):
        text = next(tmp_path.glob(f"*.{extension}")).read_text(encoding="utf-8")
        assert text.count("Safety Notice") == 1
        assert text.rfind("Subscriptions &") < text.rfind("Safety Notice")


@pytest.mark.parametrize(
    "scenario,protocol,outcome,sent,events",
    [
        ("event", "graphql-ws", "event_returned", 1, 1),
        ("401", "graphql-transport-ws", "explicit_denial", 0, 0),
        ("403", "graphql-transport-ws", "explicit_denial", 0, 0),
        ("4401", "graphql-transport-ws", "explicit_denial", 0, 0),
        ("4403", "graphql-ws", "indeterminate", 0, 0),
        ("redirect", "graphql-transport-ws", "indeterminate", 0, 0),
        ("timeout", "graphql-transport-ws", "no_event_before_timeout", 1, 0),
        ("event", None, "indeterminate", 0, 0),
        ("disconnect", "graphql-transport-ws", "network_failure", 0, 0),
        ("control-budget", "graphql-transport-ws", "indeterminate", 0, 0),
        ("oversized", "graphql-transport-ws", "indeterminate", 1, 0),
    ],
)
def test_real_protocol_termination(controlled, scenario, protocol, outcome, sent, events):
    with LocalSubscriptionTarget(scenario, protocol) as target:
        safe = run_safe_execution_scan(target.target, mode=ScanMode.ACTIVE)
        before = len(controlled)
        session = SubscriptionSecuritySession(
            safe, enabled=True, deny=True, http_settings=HttpClientSettings(timeout_seconds=0.3)
        )
        result = session.execute(preview=session.select(2), confirmed=True)
        assert target.connections == len(result.attempts) == 1
        attempt = result.attempts[0]
        assert attempt.outcome.value == outcome
        assert target.subscriptions == sent == int(attempt.subscription_sent)
        assert attempt.application_event_count == events
        assert len(result.findings) == int(outcome == "event_returned")
        assert session.execute(preview=session.preview, confirmed=True) == result
        assert target.connections == 1 and len(controlled) == before


def test_disabled_noninteractive_identical_http_and_ai(controlled, monkeypatch):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    contexts = []
    monkeypatch.setattr(
        cli, "interpret_completed_scan", lambda result: contexts.append(build_ai_context(result))
    )
    monkeypatch.setattr(cli, "render_ai", lambda *args, **kwargs: None)
    with LocalSubscriptionTarget() as target:
        args = ["scan", target.target, "--mode", "active", "--ai"]
        off = CliRunner().invoke(cli.app, args)
        assert off.exit_code == 0, off.output
        baseline = [(r.method, str(r.url), r.content, dict(r.headers)) for r in controlled]
        controlled.clear()
        on = CliRunner().invoke(cli.app, [*args, "--subscription-review"])
        assert on.exit_code == 0, (on.exception, on.output)
        assert baseline == [(r.method, str(r.url), r.content, dict(r.headers)) for r in controlled]
        assert (
            target.connections == 0
            and len(contexts) == 2
            and contexts[0].operations == contexts[1].operations
        )
