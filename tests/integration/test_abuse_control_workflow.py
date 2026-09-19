"""Ordinary ACTIVE requests and separate Phase 27 consent over a mocked target."""

import json
from collections import Counter

import httpx
import pytest
from graphql import OperationDefinitionNode, parse
from typer.testing import CliRunner

from fixtures.phase27_target import response_for
from gqlsleuth import cli
from gqlsleuth.infrastructure.http import HttpClient

TARGET = "https://example.com/graphql"
OPTIONS = ["--mode", "active", "--rate-limit-review"]
SECRET = "PHASE27_CLI_HEADER_CANARY"


@pytest.fixture
def controlled(monkeypatch):
    requests = []
    counts = Counter()

    def factory(**kwargs):
        def handler(request):
            requests.append(request)
            payload = json.loads(request.content) if request.method == "POST" else {}
            if payload:
                operation = parse(payload["query"]).definitions[0]
                assert isinstance(operation, OperationDefinitionNode)
                counts[operation.selection_set.selections[0].name.value] += 1
            status, body = response_for(request.method, payload)
            return httpx.Response(status, json=body)

        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", factory)
    # Those independent opt-in interactions already have their own workflow tests.
    monkeypatch.setattr(cli, "_run_multiplicity_stage", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_run_depth_stage", lambda *args, **kwargs: None)
    return requests, counts


@pytest.mark.parametrize(
    "options",
    [
        ["--rate-limit-review"],
        [*OPTIONS, "--auth-context", "label"],
        [*OPTIONS, "--auth-context", "one", "--auth-context", "two=Cookie: " + SECRET],
        [*OPTIONS, "--idor-review", "--auth-context", "label=Authorization: Bearer " + SECRET],
    ],
)
def test_invalid_mode_and_context_fail_before_scanning(monkeypatch, options):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid input sent HTTP"))
    result = CliRunner().invoke(cli.app, ["scan", TARGET, *options])
    assert result.exit_code == 2
    assert SECRET not in result.output and "Traceback" not in result.output


@pytest.mark.parametrize(
    "interactive,inputs,repeats,generic_mutations,confirmations",
    [
        (False, "", 0, 0, 0),
        (True, "\n\n", 0, 0, 0),
        (True, "\n1\nn\n", 0, 0, 1),
        (True, "\n1\n\n", 0, 0, 1),
        (True, "\n1\ny\n", 5, 0, 1),
        (True, "\nall\n*\n1,2\n1-2\n0\n1\ny\n", 5, 0, 1),
        (True, "2\ny\n1\nn\n", 0, 1, 1),
        (True, "2\ny\n1\ny\n", 3, 1, 1),
    ],
)
def test_independent_selection_confirmation_exact_replay_and_reports(
    controlled,
    monkeypatch,
    tmp_path,
    interactive,
    inputs,
    repeats,
    generic_mutations,
    confirmations,
):
    requests, counts = controlled
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            *OPTIONS,
            "-H",
            "X-API-Key: " + SECRET,
            "-f",
            "json,markdown,html",
            "-o",
            str(tmp_path),
        ],
        input=inputs,
    )
    assert result.exit_code == 0, (result.exception, result.output)
    assert result.output.count("Execute rate limiting / abuse-control validation?") == confirmations
    assert counts["search"] == 1 + (repeats if not generic_mutations else 0)
    assert counts["login"] == generic_mutations + (repeats if generic_mutations else 0)
    assert counts["deleteUser"] == counts["requestPasswordReset"] == 0
    assert all(req.headers.get("x-api-key") == SECRET for req in requests)
    if repeats:
        last = requests[-repeats:]
        assert all(req.content == last[0].content for req in last)
        assert all(dict(req.headers) == dict(last[0].headers) for req in last)
    assert SECRET not in result.output
    report = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    review = report["rate_limiting_abuse_controls"]
    assert review["attempted_request_count"] == repeats
    assert len(review["findings"]) == int(repeats > 0)
    assert sum(e["evidence_type"] == "abuse_control_probe" for e in report["evidence"]) == repeats
    assert {c["operation"]["name"] for c in review["candidates"]} == (
        {"search", "login"} if generic_mutations else {"search"}
    )
    if generic_mutations:
        assert review["selected"]["baseline_status"] == "graphql_error"
        assert "repeated application side effects" in " ".join(result.output.split())
    for suffix in ("md", "html"):
        text = next(tmp_path.glob("*." + suffix)).read_text(encoding="utf-8")
        assert text.count("Safety Notice") == 1
        assert "Rate Limiting" in text[: text.index("Safety Notice")]
        assert SECRET not in text
    assert SECRET not in json.dumps(report)


def test_disabled_and_noninteractive_have_identical_request_sequences(
    controlled, monkeypatch, tmp_path
):
    requests, _ = controlled
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    common = ["scan", TARGET, "--mode", "active", "-f", "json"]
    off = CliRunner().invoke(cli.app, [*common, "-o", str(tmp_path / "off")])
    assert off.exit_code == 0, off.output
    baseline = [(req.method, str(req.url), req.content, dict(req.headers)) for req in requests]
    requests.clear()
    on = CliRunner().invoke(cli.app, [*common, "--rate-limit-review", "-o", str(tmp_path / "on")])
    assert on.exit_code == 0, on.output
    assert baseline == [
        (req.method, str(req.url), req.content, dict(req.headers)) for req in requests
    ]
    assert "rate_limiting_abuse_controls" not in json.loads(
        next((tmp_path / "off").glob("*.json")).read_text(encoding="utf-8")
    )


def test_phase27_does_not_add_ai_calls(controlled, monkeypatch):
    from gqlsleuth.ai.context import build_ai_context

    calls = []
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    monkeypatch.setattr(
        cli, "interpret_completed_scan", lambda result: calls.append(build_ai_context(result))
    )
    monkeypatch.setattr(cli, "render_ai", lambda *args, **kwargs: None)
    result = CliRunner().invoke(cli.app, ["scan", TARGET, *OPTIONS, "--ai"], input="\n1\ny\n")
    assert result.exit_code == 0, (result.exception, result.output)
    assert len(calls) == 1
    assert "abuse_control" not in repr(calls[0]).lower()


def test_help_exposes_only_fixed_budget_flag():
    result = CliRunner().invoke(cli.app, ["scan", "--help"])
    assert result.exit_code == 0 and "--rate-limit-review" in result.output
    assert "--repeat-count" not in result.output and "--rate-limit-count" not in result.output
