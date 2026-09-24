"""Full CLI federation workflow over MockTransport only."""

import json

import httpx
import pytest
from typer.testing import CliRunner

from fixtures.phase29_target import response_for
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.infrastructure.http import HttpClient

TARGET = "https://example.com/graphql"
CASE = ["--federation-entity-case", '{"__typename":"User","id":"123"}']


@pytest.fixture
def controlled(monkeypatch):
    requests = []

    def factory(**kwargs):
        def handler(request):
            requests.append(request)
            assert request.headers["authorization"] == "Bearer PHASE29_CLI_CANARY"
            status, body = response_for(request.method, request.content)
            return httpx.Response(status, json=body)

        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", factory)
    monkeypatch.setattr(cli, "_run_multiplicity_stage", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_run_depth_stage", lambda *args, **kwargs: None)
    return requests


@pytest.mark.parametrize(
    "options",
    [
        ["--federation-review"],
        ["--federation-sdl-expect-deny"],
        CASE,
        ["--mode", "active", "--federation-review", "--auth-context", "one"],
        [
            "--mode",
            "active",
            "--federation-review",
            "--auth-context",
            "one",
            "--auth-context",
            "two",
        ],
        ["--mode", "active", "--federation-review", *CASE, *CASE],
        ["--mode", "active", "--federation-review", "--federation-entity-case", "PHASE29_SECRET"],
    ],
)
def test_invalid_options_before_network(monkeypatch, options):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid flags sent HTTP"))
    result = CliRunner().invoke(cli.app, ["scan", TARGET, *options])
    assert result.exit_code == 2
    assert "Traceback" not in result.output and "PHASE29_SECRET" not in result.output


@pytest.mark.parametrize(
    "interactive,inputs,count,findings,confirmations",
    [
        (False, "", 0, 0, 0),
        (True, "\n", 0, 0, 0),
        (True, "1\n\n", 0, 0, 0),
        (True, "1\n1,2\nn\n", 0, 0, 1),
        (True, "1\n1,2\n\n", 0, 0, 1),
        (True, "1\n1\ny\n", 1, 1, 1),
        (True, "1\n2\ny\n", 1, 1, 1),
        (True, "1\n2,1\ny\n", 2, 2, 1),
        (True, "all\n*\n1,2\n1\nall\n*\n1-2\n3\n1,1\n2,1\ny\n", 2, 2, 1),
    ],
)
def test_explicit_endpoint_probes_confirmation_reports(
    controlled, monkeypatch, tmp_path, interactive, inputs, count, findings, confirmations
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            "--mode",
            "active",
            "--federation-review",
            "--federation-sdl-expect-deny",
            *CASE,
            "-H",
            "Authorization: Bearer PHASE29_CLI_CANARY",
            "-f",
            "json,markdown,html",
            "-o",
            str(tmp_path),
        ],
        input=inputs,
    )
    assert result.exit_code == 0, (result.exception, result.output)
    report = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    federation = report["federation_security"]
    assert len(federation["attempts"]) == count
    assert len(federation["findings"]) == findings
    assert result.output.count("Execute federation security validation?") == confirmations
    assert "PHASE29_CLI_CANARY" not in result.output
    assert (
        sum(e["evidence_type"] == "federation_security_probe" for e in report["evidence"]) == count
    )
    for path in tmp_path.iterdir():
        text = path.read_text(encoding="utf-8")
        assert "PHASE29_CLI_CANARY" not in text
        if path.suffix != ".json":
            assert text.count("Safety Notice") == 1
            assert text.rfind("Federation Security") < text.rfind("Safety Notice")


def test_disabled_noninteractive_baseline_requests_ai_unchanged(controlled, monkeypatch):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    contexts = []
    monkeypatch.setattr(
        cli, "interpret_completed_scan", lambda result: contexts.append(build_ai_context(result))
    )
    monkeypatch.setattr(cli, "render_ai", lambda *args, **kwargs: None)
    options = [
        "scan",
        TARGET,
        "--mode",
        "active",
        "-H",
        "Authorization: Bearer PHASE29_CLI_CANARY",
        "--ai",
    ]
    off = CliRunner().invoke(cli.app, options)
    assert off.exit_code == 0, off.output
    original = [(r.method, str(r.url), r.content, dict(r.headers)) for r in controlled]
    controlled.clear()
    on = CliRunner().invoke(cli.app, [*options, "--federation-review", *CASE])
    assert on.exit_code == 0, (on.exception, on.output)
    assert original == [(r.method, str(r.url), r.content, dict(r.headers)) for r in controlled]
    assert len(contexts) == 2 and contexts[0] == contexts[1]
    assert "PHASE29_CLI_CANARY" not in str(contexts)


def test_single_service_no_entity_case(controlled, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            "--mode",
            "active",
            "--federation-review",
            "-H",
            "Authorization: Bearer PHASE29_CLI_CANARY",
            "-f",
            "json",
            "-o",
            str(tmp_path),
        ],
        input="1\n2\n1\ny\n",
    )
    assert result.exit_code == 0, (result.exception, result.output)
    report = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    result = report["federation_security"]
    assert len(result["attempts"]) == 1 and not result["findings"]
    assert result["attempts"][0]["expected"] == "observe"
