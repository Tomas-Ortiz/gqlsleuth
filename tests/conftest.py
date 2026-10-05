"""Offline full-workflow fixture for Phase 10 regression boundaries."""

import json
from collections.abc import Callable
from importlib import import_module

import httpx
import pytest
from graphql import build_schema, introspection_from_schema
from typer.testing import CliRunner

from fixtures.consent_preview import watch_consent
from gqlsleuth import cli
from gqlsleuth.application.graphql_detection import discover_and_detect_graphql
from gqlsleuth.application.introspection import introspect_detected_endpoints
from gqlsleuth.application.operation_analysis import analyze_schema_results
from gqlsleuth.application.query_generation import generate_analyzed_queries
from gqlsleuth.application.safe_execution import SafeExecutionScanResult, execute_generated_queries
from gqlsleuth.application.schema_parsing import parse_introspection_schemas
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.rules.loader import load_bundled_rules

DEFAULT_ACTIVE_SCHEMA = """
type Query { health: String readAndBurn: String }
type Mutation {
  createUser(id: ID!): String
  updateProfile: String
  setPreference: String
  deleteUser: String
  purgeLogs: String
  burnHistory: String
}
"""


@pytest.fixture
def consent_trace(monkeypatch):
    return watch_consent(monkeypatch)


@pytest.fixture
def run_interrupted_cli(monkeypatch):
    """Interrupt actual Typer input and assert the scan stops at that prompt."""

    def run(arguments, requests, prompt_hint, input_text="", *, raw_interrupt=False):
        at_interrupt = []
        monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)

        def wrap(original):
            def interact(text, *args, **kwargs):
                assert not at_interrupt, "Another prompt appeared after Ctrl+C"
                if prompt_hint not in text:
                    return original(text, *args, **kwargs)
                at_interrupt.append(tuple(requests))

                def ctrl_c(*args, **kwargs):
                    raise KeyboardInterrupt

                if raw_interrupt:
                    ctrl_c()
                # Exercise Typer's real KeyboardInterrupt -> Abort translation too.
                with monkeypatch.context() as patch:
                    patch.setattr(import_module(original.__module__), "visible_prompt_func", ctrl_c)
                    return original(text, *args, **kwargs)

            return interact

        monkeypatch.setattr(cli.typer, "prompt", wrap(cli.typer.prompt))
        monkeypatch.setattr(cli.typer, "confirm", wrap(cli.typer.confirm))
        result = CliRunner().invoke(cli.app, arguments, input=input_text)
        assert len(at_interrupt) == 1, (result.exception, result.output)
        assert tuple(requests) == at_interrupt[0], "Target requests continued after Ctrl+C"
        assert result.exit_code == 130, (result.exception, result.output)
        assert result.output.count("Scan cancelled by user.") == 1
        assert "Traceback" not in result.output
        assert "GQLSleuth Assessment" not in result.output
        return result

    return run


@pytest.fixture
def phase_ten_scan() -> Callable[..., tuple[SafeExecutionScanResult, list[dict[str, object]]]]:
    def scan(
        sdl: str = DEFAULT_ACTIVE_SCHEMA,
        mode: ScanMode = ScanMode.ACTIVE,
    ) -> tuple[SafeExecutionScanResult, list[dict[str, object]]]:
        introspection = introspection_from_schema(build_schema(sdl))
        requests: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, json={"data": {"__typename": "Query"}})
            payload = json.loads(request.content)
            requests.append(payload)
            if payload["query"] == MINIMAL_INTROSPECTION_QUERY:
                return httpx.Response(
                    200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
                )
            if payload["query"] == FULL_INTROSPECTION_QUERY:
                return httpx.Response(200, json={"data": introspection})
            assert payload["query"].startswith("query")
            return httpx.Response(200, json={"data": None})

        with HttpClient(transport=httpx.MockTransport(handler)) as client:
            detection = discover_and_detect_graphql(
                Target.parse("https://example.com/graphql"), mode=mode, client=client
            )
            introspections = introspect_detected_endpoints(detection, client=client)
            schemas = parse_introspection_schemas(introspections)
            analysis = analyze_schema_results(schemas, load_bundled_rules())
            generated = generate_analyzed_queries(analysis)
            return execute_generated_queries(generated, client=client), requests

    return scan
