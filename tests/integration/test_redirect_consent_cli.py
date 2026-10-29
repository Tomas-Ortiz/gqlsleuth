"""Real CLI/workflow consent using mocked target transports only."""

import json
from io import StringIO
from threading import Barrier, current_thread, main_thread

import httpx
import pytest
from graphql import build_schema, introspection_from_schema
from rich.console import Console
from typer.testing import CliRunner

from fixtures.cli_output import plain_cli_output
from gqlsleuth import cli
from gqlsleuth.application.graphql_detection import MINIMAL_TYPENAME_QUERY
from gqlsleuth.graphql.introspection import (
    FULL_INTROSPECTION_QUERY,
    MINIMAL_INTROSPECTION_QUERY,
    REDUCED_INTROSPECTION_QUERY,
)
from gqlsleuth.presentation.console import CONSOLE_THEME

SDL = "type Query { health: String } type Mutation { createNote(text: String!): String }"
TARGET = "https://example.com/graphql"
SECRET = "REDIRECT_CONTEXT_CANARY"


@pytest.fixture
def redirected_cli(monkeypatch):
    seen = []
    options = {"reduced": False, "at_mutation": False}
    schema = introspection_from_schema(build_schema(SDL))

    def handler(request):
        seen.append(request)
        assert request.url.host in {"example.com", "api.example.com", "mutation.example.com"}
        query = json.loads(request.content)["query"] if request.method == "POST" else ""
        destination = (
            "mutation.example.com"
            if options["at_mutation"] and query.startswith("mutation")
            else "api.example.com"
        )
        if request.url.host == "example.com":
            return httpx.Response(307, headers={"Location": f"https://{destination}/graphql"})
        if request.method == "GET":
            return httpx.Response(200, text="Not conclusive")
        if query == MINIMAL_TYPENAME_QUERY:
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(
                200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
            )
        if query == FULL_INTROSPECTION_QUERY and options["reduced"]:
            return httpx.Response(200, json={"errors": [{"message": "Query depth limit exceeded"}]})
        if query in {FULL_INTROSPECTION_QUERY, REDUCED_INTROSPECTION_QUERY}:
            return httpx.Response(200, json={"data": schema})
        return httpx.Response(200, json={"data": None})

    monkeypatch.setattr("httpx._client.HTTPTransport", lambda **_: httpx.MockTransport(handler))
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    return seen, options


@pytest.mark.parametrize("mode,execute", [("safe", False), ("active", False), ("active", True)])
@pytest.mark.parametrize("reduced", [False, True])
def test_full_pipeline_single_consent_exact_headers_reports_and_active_gate(
    redirected_cli, monkeypatch, tmp_path, mode, execute, reduced
):
    seen, options = redirected_cli
    options["reduced"] = reduced
    events = []

    def confirm(message, **kwargs):
        assert current_thread() is main_thread()
        assert kwargs.get("default") is False
        events.append((message, len(seen)))
        if "redirect" in message:
            assert len(seen) == 1
            return True
        assert "Mutation" in message
        assert not any(b"mutation (" in request.content for request in seen)
        return execute

    monkeypatch.setattr(cli.typer, "confirm", confirm)
    monkeypatch.setattr(
        cli.typer, "prompt", lambda message, **_: "1" if "Mutations" in message else ""
    )
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            "--mode",
            mode,
            "-H",
            f"X-Key: {SECRET}",
            "-f",
            "json,markdown,html",
            "-o",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, (result.exception, result.output)
    assert sum("redirect" in event[0] for event in events) == 1
    assert len(seen) == 10 + 2 * reduced + 2 * execute
    for request in seen:
        assert request.headers["x-key"] == SECRET
    for original, redirected in zip(seen[::2], seen[1::2], strict=True):
        assert original.method == redirected.method
        assert original.content == redirected.content
    assert SECRET not in result.output
    assert result.output.count("CROSS-ORIGIN REDIRECT") == 1
    if mode == "active":
        assert result.output.index("CROSS-ORIGIN REDIRECT") < result.output.index(
            "PRE-ACTIVE CONTEXT"
        )
    for path in tmp_path.iterdir():
        text = path.read_text(encoding="utf-8")
        assert SECRET not in text and "redirect_consent" not in text
        if path.suffix == ".json":
            report = json.loads(text)
            assert report["report_schema_version"] == 2
            assert report["evidence_counts"].get("mutation_execution", 0) == int(execute)


@pytest.mark.parametrize("interactive,answer", [(True, "\n"), (True, "n\n"), (False, "")])
def test_default_no_and_noninteractive_deny_without_destination_requests(
    redirected_cli, monkeypatch, interactive, answer
):
    seen, _ = redirected_cli
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: interactive)
    result = CliRunner().invoke(cli.app, ["scan", TARGET], input=answer)
    assert result.exit_code == 0, result.exception
    assert all(request.url.host == "example.com" for request in seen)
    assert "blocked locally" in result.output
    assert result.output.count("Allow redirect and credential forwarding") == int(interactive)
    assert "Traceback" not in result.output


@pytest.mark.parametrize("at_mutation", [False, True])
def test_cli_ctrl_c_during_redirect_stops_scan_including_active(
    redirected_cli, monkeypatch, at_mutation
):
    seen, options = redirected_cli
    options["at_mutation"] = at_mutation
    at_cancel = []

    def confirm(message, **_):
        if "redirect" in message and (not at_mutation or len(seen) > 10):
            at_cancel.append(len(seen))
            raise KeyboardInterrupt
        return True

    monkeypatch.setattr(cli.typer, "confirm", confirm)
    monkeypatch.setattr(cli.typer, "prompt", lambda text, **_: "1" if "Mutations" in text else "")
    result = CliRunner().invoke(cli.app, ["scan", TARGET, "--mode", "active"])
    assert result.exit_code == 130, (result.exception, result.output)
    assert at_cancel == [len(seen)]
    assert len(seen) == (11 if at_mutation else 1)
    assert all(request.url.host != "mutation.example.com" for request in seen)
    assert result.output.count("Scan cancelled by user.") == 1
    assert "GQLSLEUTH ASSESSMENT" not in result.output and "Traceback" not in result.output


def test_cli_worker_redirect_cancel_releases_pool_before_exit(monkeypatch):
    seen, prompts = [], []
    barrier = Barrier(4, timeout=5)
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    monkeypatch.setattr(
        "gqlsleuth.application.graphql_detection.generate_endpoint_candidate_stages",
        lambda _: ((TARGET, *(f"https://example.com/path{i}" for i in range(8))), ()),
    )

    def handler(request):
        assert request.url.host == "example.com", "Destination received unapproved request"
        seen.append(request)
        if request.url.path == "/graphql":
            return httpx.Response(404)
        barrier.wait()
        return httpx.Response(307, headers={"Location": "https://other.example/graphql"})

    def confirm(*args, **kwargs):
        assert current_thread() is main_thread()
        prompts.append(len(seen))
        raise cli.typer.Abort

    monkeypatch.setattr("httpx._client.HTTPTransport", lambda **_: httpx.MockTransport(handler))
    monkeypatch.setattr(cli.typer, "confirm", confirm)
    result = CliRunner().invoke(cli.app, ["scan", TARGET, "--mode", "active"])
    assert result.exit_code == 130, (result.exception, result.output)
    assert prompts == [len(seen)] == [6]
    assert "ACTIVE QUERY" not in result.output


@pytest.mark.parametrize("width", [45, 100])
def test_terminal_status_pauses_and_notice_has_only_origins(redirected_cli, monkeypatch, width):
    stream = StringIO()
    console = Console(file=stream, force_terminal=True, width=width, theme=CONSOLE_THEME)
    monkeypatch.setattr(cli, "console", console)
    statuses = []
    original = console.status

    def status(*args, **kwargs):
        instance = original(*args, **kwargs)
        statuses.append(instance)
        return instance

    def confirm(*args, **kwargs):
        assert len(statuses) == 1
        assert not statuses[0]._live.is_started
        return True

    monkeypatch.setattr(console, "status", status)
    monkeypatch.setattr(cli.typer, "confirm", confirm)
    result = CliRunner().invoke(cli.app, ["scan", TARGET, "-H", f"Cookie: {SECRET}"])
    assert result.exit_code == 0, result.exception
    assert not statuses[0]._live.is_started
    text = plain_cli_output(stream.getvalue())
    notice = text.split("CROSS-ORIGIN REDIRECT", 1)[1].split("GQLSLEUTH ASSESSMENT", 1)[0]
    assert SECRET not in text
    assert "/graphql" not in notice
    assert "credentials" in notice and "variables" in notice


def test_cli_named_contexts_share_decision_never_credentials(redirected_cli, monkeypatch, tmp_path):
    seen, _ = redirected_cli
    prompts = []
    monkeypatch.setattr(cli.typer, "confirm", lambda text, **_: prompts.append(text) or True)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            "--auth-context",
            "first=Authorization: Bearer CONTEXT_A_REDIRECT_CANARY",
            "--auth-context",
            "second=Cookie: session=CONTEXT_B_REDIRECT_CANARY",
            "-f",
            "json,markdown,html",
            "-o",
            str(tmp_path),
            "-v",
        ],
    )
    assert result.exit_code == 0, (result.exception, result.output)
    assert len(prompts) == 1 and len(seen) == 20
    for request in seen[:10]:
        assert request.headers["authorization"] == "Bearer CONTEXT_A_REDIRECT_CANARY"
        assert "cookie" not in request.headers
    for request in seen[10:]:
        assert request.headers["cookie"] == "session=CONTEXT_B_REDIRECT_CANARY"
        assert "authorization" not in request.headers
    for secret in ("CONTEXT_A_REDIRECT_CANARY", "CONTEXT_B_REDIRECT_CANARY"):
        assert secret not in result.output
        assert all(secret not in path.read_text(encoding="utf-8") for path in tmp_path.iterdir())


def test_downgrade_notice_precedes_default_no_and_excludes_private_material(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)

    def handler(request):
        seen.append(request)
        return httpx.Response(
            307, headers={"Location": "http://example.com/private?secret=PRIVATE_URL_CANARY"}
        )

    monkeypatch.setattr("httpx._client.HTTPTransport", lambda **_: httpx.MockTransport(handler))
    result = CliRunner().invoke(
        cli.app, ["scan", TARGET, "-H", f"Authorization: Bearer {SECRET}"], input="\n"
    )
    assert result.exit_code == 0, result.exception
    text = " ".join(result.output.split())
    assert text.index("unencrypted HTTP") < text.index("Allow redirect and credential forwarding")
    assert "[y/N]" in text
    assert SECRET not in text and "PRIVATE_URL_CANARY" not in text and "/private" not in text
    assert all(request.url.scheme == "https" for request in seen)


def test_rejected_query_and_mutation_preserve_original_attempt_only(phase_ten_scan):
    from gqlsleuth.application.active_execution import (
        execute_selected_mutations,
        prepare_active_mutations,
    )
    from gqlsleuth.application.safe_execution import execute_generated_queries
    from gqlsleuth.infrastructure.http import HttpClient

    safe, _ = phase_ten_scan(SDL)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(307, headers={"Location": "https://unapproved.example/graphql"})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        query_result = execute_generated_queries(safe.query_generation, client=client)
        preview = prepare_active_mutations(safe)
        declined = execute_selected_mutations(
            preview, selected_indices=(1,), confirmed=False, client=client
        )
        assert len(seen) == 1 and not declined.execution_evidence
        active = execute_selected_mutations(
            preview, selected_indices=(1,), confirmed=True, client=client
        )
    assert len(seen) == 2
    assert all(request.url.host == "example.com" for request in seen)
    assert len(query_result.execution_evidence) == len(active.execution_evidence) == 1
    for result in (query_result.executions[0], active.executions[0]):
        assert result.attempted and result.response is None
        assert result.error_type == "HttpRedirectDeniedError"
        assert result.status.value == "network_failure"
