"""Whole SAFE pipeline and independent authentication interaction over a mocked target."""

import json

import httpx
import pytest
from typer.testing import CliRunner

from fixtures.phase26_target import fake_token, response_for
from gqlsleuth import cli
from gqlsleuth.infrastructure.http import HttpClient

TOKEN = fake_token()
TARGET = "https://example.com/graphql"
OPTIONS = ["--mode", "active", "--auth-security-review", "-H", "Authorization: Bearer " + TOKEN]


@pytest.fixture
def controlled(monkeypatch):
    requests = []

    def factory(**kwargs):
        def handler(request):
            requests.append(request)
            payload = json.loads(request.content) if request.method == "POST" else {}
            status, body = response_for(
                request.method,
                payload,
                request.headers.get("authorization", ""),
                original=TOKEN,
                scenario="signature-accepted",
            )
            return httpx.Response(status, json=body)

        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", factory)
    # Existing independently consented stages are tested in their own suites.
    monkeypatch.setattr(cli, "_run_multiplicity_stage", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_run_depth_stage", lambda *args, **kwargs: None)
    return requests


@pytest.mark.parametrize(
    "options",
    [
        ["--auth-security-review"],
        ["--auth-security-review", "--mode", "active"],
        ["--auth-security-review", "--mode", "active", "-H", "Authorization: Bearer"],
        ["--auth-security-review", "--mode", "active", "-H", "Authorization: Basic PHASE26_SECRET"],
        [*OPTIONS, "-H", "authorization: Bearer PHASE26_OTHER_SECRET"],
        [*OPTIONS, "--auth-context", "label=Cookie: PHASE26_SECRET"],
    ],
)
def test_invalid_inputs_fail_before_scan_without_echo(monkeypatch, options):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid input sent HTTP"))
    result = CliRunner().invoke(cli.app, ["scan", TARGET, *options])
    assert result.exit_code == 2
    assert TOKEN not in result.output and "PHASE26_SECRET" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "interactive,inputs,count,confirmations",
    [
        (False, "", 0, 0),
        (True, "\n", 0, 0),
        (True, "1\n\nn\n", 0, 1),
        (True, "1\n\n\n", 0, 1),
        (True, "1\n\ny\n", 1, 1),
        (True, "1\n1,2\ny\n", 3, 1),
        (True, "all\n1,2\n*\n1\nall\n*\n1-2\n3\n1,1\n2,1\ny\n", 3, 1),
    ],
)
def test_independent_selection_confirmation_and_reports(
    controlled, monkeypatch, tmp_path, interactive, inputs, count, confirmations
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    result = CliRunner().invoke(
        cli.app,
        ["scan", TARGET, *OPTIONS, "-f", "json,markdown,html", "-o", str(tmp_path)],
        input=inputs,
    )
    assert result.exit_code == 0, (result.exception, result.output)
    probes = [
        req
        for req in controlled
        if req.method == "POST"
        and json.loads(req.content).get("variables") == {"id": "1"}
        and req.headers.get("authorization") != "Bearer " + TOKEN
    ]
    assert len(probes) == count
    assert result.output.count("Execute authentication and token security probes?") == confirmations
    assert TOKEN not in result.output
    report = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    security = report["authentication_token_security"]
    assert security["attempted_request_count"] == count
    assert len(security["findings"]) == int(count == 3)
    assert (
        sum(e["evidence_type"] == "authentication_security_probe" for e in report["evidence"])
        == count
    )
    for suffix in ("md", "html"):
        text = next(tmp_path.glob("*." + suffix)).read_text(encoding="utf-8")
        assert text.count("Safety Notice") == 1
        assert "Authentication" in text[: text.index("Safety Notice")]
        assert TOKEN not in text


def test_disabled_and_noninteractive_request_sequences_identical(controlled, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    common = [
        "scan",
        TARGET,
        "--mode",
        "active",
        "-H",
        "Authorization: Bearer " + TOKEN,
        "-f",
        "json",
    ]
    off = CliRunner().invoke(cli.app, [*common, "-o", str(tmp_path / "off")])
    assert off.exit_code == 0
    before = [(req.method, str(req.url), req.content, dict(req.headers)) for req in controlled]
    controlled.clear()
    on = CliRunner().invoke(
        cli.app, [*common, "--auth-security-review", "-o", str(tmp_path / "on")]
    )
    assert on.exit_code == 0
    assert before == [
        (req.method, str(req.url), req.content, dict(req.headers)) for req in controlled
    ]
    assert "authentication_token_security" not in json.loads(
        next((tmp_path / "off").glob("*.json")).read_text()
    )


def test_help_discovers_flag_without_new_token_options():
    result = CliRunner().invoke(cli.app, ["scan", "--help"])
    assert result.exit_code == 0 and "--auth-security-review" in result.output
    assert "--token " not in result.output and "--jwt " not in result.output
