"""Exercise real CLI/application/HTTP paths using offline target and Ollama transports."""

import json
import logging

import httpx
import pytest
from graphql import build_schema, introspection_from_schema
from typer.testing import CliRunner

import gqlsleuth.cli as cli
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIContext
from gqlsleuth.ai.prompt import execution_summary
from gqlsleuth.application.graphql_detection import MINIMAL_TYPENAME_QUERY
from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY

CANARIES = (
    "AUTH_CANARY_PHASE14",
    "COOKIE_CANARY_PHASE14",
    "KEY_CANARY_PHASE14",
    "PROXY_CANARY_PHASE14",
)
TARGET = "https://example.com/graphql"
SDL = """
type Query { health: String denied: String forbidden: String readAndBurn: String }
type Mutation { createUser(id: ID!): String deleteUser: String }
"""


@pytest.fixture
def configured_cli(monkeypatch, tmp_path):
    introspection = introspection_from_schema(build_schema(SDL))
    target_requests = []
    ai_requests = []
    completed_results = []
    original_interpret = cli.interpret_completed_scan

    def handler(request, settings):
        if request.url.host == "127.0.0.1":
            ai_requests.append((request, settings))
            payload = json.loads(request.content)
            context = AIContext.model_validate_json(payload["messages"][1]["content"])
            answer = {
                "scan_summary": {"text": execution_summary(context), "operations": []},
                "operation_review": [],
                "limitations": [],
            }
            return httpx.Response(
                200,
                json={
                    "model": "qwen3:8b",
                    "done": True,
                    "message": {"role": "assistant", "content": json.dumps(answer)},
                },
            )
        assert request.url.host == "example.com"
        target_requests.append((request, settings))
        if request.method == "GET":
            return httpx.Response(200, text="No conclusive GraphQL signals")
        query = json.loads(request.content)["query"]
        if query == MINIMAL_TYPENAME_QUERY:
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(
                200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
            )
        if query == FULL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": introspection})
        if "denied" in query:
            return httpx.Response(401, text="Authentication required")
        if "forbidden" in query:
            return httpx.Response(403, text="Access denied")
        assert "readAndBurn" not in query and "deleteUser" not in query
        return httpx.Response(200, json={"data": None})

    def transport_factory(**settings):
        return httpx.MockTransport(lambda request: handler(request, settings))

    def interpret(result):
        completed_results.append(result)
        return original_interpret(result)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport_factory)
    monkeypatch.setattr(cli, "interpret_completed_scan", interpret)
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    monkeypatch.chdir(tmp_path)
    return target_requests, ai_requests, completed_results


def invoke(*options, input="\n", target=TARGET):
    return CliRunner().invoke(cli.app, ["scan", target, *options], input=input)


@pytest.mark.parametrize("mode,input", [("safe", "\n"), ("active", "\n"), ("active", "1\ny\n")])
@pytest.mark.parametrize("verbose", [False, True])
def test_headers_all_stages_reports_secrets_and_ollama_isolation(
    configured_cli, tmp_path, caplog, mode, input, verbose
):
    caplog.set_level(logging.DEBUG)
    result = invoke(
        "--mode",
        mode,
        "-H",
        f"Authorization: Bearer {CANARIES[0]}",
        "--header",
        f"Cookie: session={CANARIES[1]}",
        "-H",
        f"X-API-Key: {CANARIES[2]}",
        "-H",
        "X-Test: one",
        "-H",
        "X-Test: two",
        "--proxy",
        f"http://user:{CANARIES[3]}@localhost:8080",
        "--timeout",
        "7.5",
        "--no-verify-tls",
        "--ai",
        "-f",
        "json,markdown,html",
        *(["-v"] if verbose else []),
        input=input,
    )
    assert result.exit_code == 0, result.exception
    requests, ai_requests, results = configured_cli
    assert result.stdout.count("TLS certificate verification is disabled for target requests.") == 1
    assert len(ai_requests) == 1
    assert all(canary not in result.output + caplog.text for canary in CANARIES)
    assert requests[0][0].method == "GET"
    queries = [json.loads(req.content)["query"] for req, _ in requests if req.method == "POST"]
    assert queries[:3] == [
        MINIMAL_TYPENAME_QUERY,
        MINIMAL_INTROSPECTION_QUERY,
        FULL_INTROSPECTION_QUERY,
    ]
    mutations = [query for query in queries if query.startswith("mutation")]
    assert len(mutations) == (1 if "y" in input else 0)
    for request, transport in requests:
        assert request.headers["authorization"] == f"Bearer {CANARIES[0]}"
        assert request.headers["cookie"] == f"session={CANARIES[1]}"
        assert request.headers["x-api-key"] == CANARIES[2]
        assert request.headers.get_list("x-test") == ["one", "two"]
        assert set(request.extensions["timeout"].values()) == {7.5}
        assert transport["verify"] is False
        assert transport["proxy"].url.host == "localhost"
        assert transport["proxy"].auth == ("user", CANARIES[3])
        assert transport["trust_env"] is False
    ai_request, ai_transport = ai_requests[0]
    assert ai_transport["verify"] is True
    assert ai_transport.get("proxy") is None
    assert ai_transport["trust_env"] is False
    assert ai_request.extensions["timeout"] == {
        "connect": 5,
        "read": 180,
        "write": 180,
        "pool": 180,
    }
    assert all(
        canary not in str(ai_request.headers.multi_items()) + ai_request.content.decode()
        for canary in CANARIES
    )
    context = serialize_context(build_ai_context(results[0]))
    assert all(canary not in context for canary in CANARIES)
    reports = list((tmp_path / "gqlsleuth-reports").iterdir())
    assert len(reports) == 3
    for report in reports:
        assert all(canary not in report.read_text(encoding="utf-8") for canary in CANARIES)
    canonical = json.loads(next(path for path in reports if path.suffix == ".json").read_text())
    statuses = [item["execution"]["status"] for item in canonical["queries"]]
    assert statuses.count("http_error") == 2
    assert statuses.count("success") == 1
    assert statuses.count("skipped_safety") == 1
    if mode == "safe":
        assert "Select Mutations" not in result.stdout


@pytest.mark.parametrize("target", [TARGET, "https://example.com/"])
def test_omitted_options_preserve_requests_console_and_default_timeouts(configured_cli, target):
    baseline = invoke(target=target)
    requests = configured_cli[0]
    before = [(request.method, str(request.url), request.content) for request, _ in requests]
    for request, transport in requests:
        assert set(request.extensions["timeout"].values()) == (
            {8} if request.method == "GET" else {10}
        )
        assert transport["verify"] is True and transport.get("proxy") is None
    requests.clear()
    configured = invoke("-H", "X-Innocuous: value", "--verify-tls", target=target)
    assert configured.exit_code == baseline.exit_code == 0
    assert configured.stdout == baseline.stdout
    assert before == [
        (request.method, str(request.url), request.content) for request, _ in requests
    ]
    assert all(request.headers["x-innocuous"] == "value" for request, _ in requests)
    assert "TLS certificate verification is disabled" not in configured.stdout


@pytest.mark.parametrize(
    "options",
    [
        ("-H", CANARIES[0]),
        ("--header", "Authorization: " + CANARIES[0] + "\r\nInjected: yes"),
        ("-H", ": " + CANARIES[0]),
        ("--timeout", "0"),
        ("--timeout", "-1"),
        ("--timeout", "nan"),
        ("--timeout", "inf"),
        ("--timeout", "not-a-number"),
        ("--proxy", "socks5://user:" + CANARIES[3] + "@localhost"),
    ],
)
def test_invalid_cli_configuration_fails_before_any_request_without_echo(configured_cli, options):
    result = invoke(*options)
    assert result.exit_code == 2
    assert configured_cli == ([], [], [])
    assert all(canary not in result.output for canary in CANARIES)
    assert "Traceback" not in result.output


def test_target_help_is_explicit_and_remains_separate_from_ollama():
    for command in ([], ["scan"]):
        result = CliRunner().invoke(cli.app, [*command, "--help"])
        assert result.exit_code == 0
        for option in ("--header", "-H", "--timeout", "--proxy", "--verify-tls", "--no-verify-tls"):
            assert option in result.output
        assert "Ollama" in result.output
        if command:
            assert "insecure" in result.output and "Never sent to" in result.output
        else:
            assert "Target HTTP options do not affect local Ollama." not in result.output
