"""Release hardening smokes with fake credentials, mock transport and a socket guard."""

import base64
import json
import logging
import socket
from unittest.mock import Mock

import httpx
import pytest
from graphql import build_schema, introspection_from_schema
from typer.testing import CliRunner

from gqlsleuth import cli
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.safe_execution import run_safe_execution_scan
from gqlsleuth.discovery.endpoint_candidates import generate_endpoint_candidates
from gqlsleuth.domain.exceptions import InvalidUrlError, ResponseTooLargeError, SchemaParsingError
from gqlsleuth.domain.models import ConfidenceLevel, EvidenceType, ScanMode, Target
from gqlsleuth.graphql.detection import analyze_graphql_response
from gqlsleuth.graphql.introspection import (
    FULL_INTROSPECTION_QUERY,
    MINIMAL_INTROSPECTION_QUERY,
    IntrospectionStatus,
    classify_introspection_response,
)
from gqlsleuth.graphql.safe_execution import classify_execution_response
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.infrastructure.http import (
    DEFAULT_MAX_RESPONSE_BODY_BYTES,
    HttpClient,
    HttpClientSettings,
    HttpRequest,
)

TARGET = "http://127.0.0.1:8765/graphql"
CANARIES = ("BATCH_A_USERNAME", "BATCH_A_PASSWORD")
# Construct text iteratively: the test itself must not recurse or raise the recursion limit.
DEEP_JSON = b'{"data":' + b"[" * 5000 + b"0" + b"]" * 5000 + b"}"
SDL = """
type Query { alpha: String beta: String }
type Mutation { createAlpha: String createBeta: String }
"""


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Real socket/DNS activity is forbidden in hardening tests.")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.fixture
def mocked_scan(monkeypatch):
    requests = []
    results = []
    state = {"failure": None}
    schema = introspection_from_schema(build_schema(SDL))
    original_render = cli.render_completed_assessment

    def respond(request):
        requests.append(request)
        if state["failure"] == "transport":
            raise httpx.ConnectError(" ".join(CANARIES), request=request)
        if state["failure"] == "detection":
            return httpx.Response(200, content=DEEP_JSON)
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        query = json.loads(request.content)["query"]
        if query == MINIMAL_INTROSPECTION_QUERY:
            if state["failure"] == "minimal":
                return httpx.Response(200, content=DEEP_JSON)
            return httpx.Response(200, json={"data": {"__schema": {}}})
        if query == FULL_INTROSPECTION_QUERY:
            if state["failure"] == "full":
                return httpx.Response(200, content=DEEP_JSON)
            return httpx.Response(200, json={"data": schema})
        if state["failure"] == "execution" and ("alpha" in query or "createAlpha" in query):
            return httpx.Response(200, content=DEEP_JSON)
        return httpx.Response(200, json={"data": None})

    def render(console, result, **kwargs):
        results.append(result)
        original_render(console, result, **kwargs)

    monkeypatch.setattr(
        "httpx._client.HTTPTransport", lambda **kwargs: httpx.MockTransport(respond)
    )
    monkeypatch.setattr(cli, "render_completed_assessment", render)
    return state, requests, results


@pytest.mark.parametrize(
    "userinfo",
    [
        "BATCH_A_USERNAME",
        "BATCH_A_USERNAME:BATCH_A_PASSWORD",
        "BATCH_A_USERNAME%40x:BATCH_A_PASSWORD%3A",
        "",
        ":",
    ],
)
@pytest.mark.parametrize("verbose", [False, True])
def test_credential_urls_rejected_before_http_ai_or_reports(
    mocked_scan, monkeypatch, tmp_path, caplog, userinfo, verbose
):
    _, requests, _ = mocked_scan
    ai = Mock(side_effect=AssertionError("AI must not run"))
    reports = Mock(side_effect=AssertionError("Reports must not be generated"))
    monkeypatch.setattr(cli, "interpret_completed_scan", ai)
    monkeypatch.setattr(cli, "generate_reports", reports)
    caplog.set_level(logging.DEBUG)
    url = f"http://{userinfo}@127.0.0.1:8765/graphql?x=1"
    with pytest.raises(InvalidUrlError) as error:
        Target.parse(url)
    assert "embedded credentials" in str(error.value)
    assert "--header" in str(error.value)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            url,
            "--ai",
            "-f",
            "json,markdown,html",
            "-o",
            str(tmp_path),
            *(["-v"] if verbose else []),
        ],
    )
    assert result.exit_code == 2
    assert "--header" in result.output
    assert not requests and not list(tmp_path.iterdir())
    ai.assert_not_called()
    reports.assert_not_called()
    for text in (str(error.value), result.output, str(result.exception), caplog.text):
        assert url not in text
        assert all(canary not in text for canary in CANARIES)
        assert "Traceback" not in text


@pytest.mark.parametrize("body", [DEEP_JSON, b"not json", b"\xff"])
def test_unusable_json_keeps_existing_response_classifications(body):
    assert analyze_graphql_response(body, {}).confidence is ConfidenceLevel.NOT_DETECTED
    assert (
        analyze_graphql_response(
            body, {"content-type": "application/graphql-response+json"}
        ).confidence
        is ConfidenceLevel.POSSIBLE
    )
    assert classify_introspection_response(200, body).status is IntrospectionStatus.INVALID_RESPONSE
    assert classify_execution_response(200, body).status.value == "invalid_response"
    assert classify_execution_response(500, body).status.value == "http_error"
    with pytest.raises(SchemaParsingError):
        parse_introspection_response(body)


@pytest.mark.parametrize(
    "failure,count", [(None, 5), ("detection", 20), ("minimal", 2), ("full", 3), ("execution", 5)]
)
def test_mocked_cli_smokes_preserve_partial_results_and_exact_evidence(
    mocked_scan, tmp_path, failure, count
):
    state, requests, results = mocked_scan
    state["failure"] = failure
    outcome = CliRunner().invoke(
        cli.app, ["scan", TARGET, "-f", "json,markdown,html", "-o", str(tmp_path)]
    )
    assert outcome.exit_code == 0, (outcome.exception, outcome.output)
    assert "Traceback" not in outcome.output and "RecursionError" not in outcome.output
    assert len(requests) == count
    result = results[0]
    schema_scan = result.query_generation.operation_analysis.schema_scan
    introspection = schema_scan.introspection
    if failure == "detection":
        assert all(
            item.confidence is ConfidenceLevel.NOT_DETECTED
            for item in introspection.detection.detections
        )
    elif failure in {"minimal", "full"}:
        assert introspection.introspections[0].status is IntrospectionStatus.INVALID_RESPONSE
        assert introspection.detection.detections[0].confidence is ConfidenceLevel.CONFIRMED
    else:
        assert [item.status.value for item in result.executions] == [
            "invalid_response" if failure else "success",
            "success",
        ]
        assert [json.loads(r.content)["query"] for r in requests[3:]] == [
            q.query_text for q in result.query_generation.queries
        ]
    raw = next(tmp_path.glob("*.json")).read_text(encoding="utf-8")
    canonical = json.loads(raw)
    assert canonical["evidence"]
    if failure == "execution":
        assert any(e.response_body == DEEP_JSON for e in result.evidence)
        assert base64.b64encode(DEEP_JSON).decode() in raw
    elif failure == "detection":
        assert introspection.detection.discovery.probes[0].response.body == DEEP_JSON
        assert introspection.detection.detections[0].post_response.body == DEEP_JSON
    elif failure in {"minimal", "full"}:
        retained = introspection.introspections[0]
        response = retained.minimal_response if failure == "minimal" else retained.full_response
        assert response.body == DEEP_JSON
    for ext in ("md", "html"):
        human = next(tmp_path.glob(f"*.{ext}")).read_text(encoding="utf-8")
        assert human.count("Safety Notice") == 1
        assert "[" * 100 not in human
        if failure == "execution":
            assert "exceeds supported nesting" in human
    assert not any(e.evidence_type is EvidenceType.MUTATION_EXECUTION for e in result.evidence)


def test_mutation_invalid_response_does_not_stop_next_selected_mutation(mocked_scan):
    state, requests, _ = mocked_scan
    safe = run_safe_execution_scan(TARGET, mode=ScanMode.ACTIVE)
    preview = prepare_active_mutations(safe)
    before = len(requests)
    state["failure"] = "execution"
    with HttpClient() as client:
        result = execute_selected_mutations(
            preview, selected_indices=(1, 2), confirmed=True, client=client
        )
    assert len(requests) - before == 2
    assert [e.status.value for e in result.executions] == ["invalid_response", "success"]
    assert result.execution_evidence[0].response_body == DEEP_JSON
    assert result.evidence[: len(safe.evidence)] == safe.evidence


@pytest.mark.parametrize("boundary", ["build_client_schema", "_map_schema"])
def test_schema_recursion_is_retained_as_schema_failure(mocked_scan, monkeypatch, boundary):
    def too_deep(*args, **kwargs):
        raise RecursionError("FAKE_PRIVATE_SCHEMA_DETAIL")

    monkeypatch.setattr(f"gqlsleuth.graphql.schema_parser.{boundary}", too_deep)
    result = run_safe_execution_scan(TARGET)
    schema_scan = result.query_generation.operation_analysis.schema_scan
    assert len(mocked_scan[1]) == 3
    assert schema_scan.introspection.introspections[0].status is IntrospectionStatus.ENABLED
    assert len(schema_scan.schemas) == 1
    failed = schema_scan.schemas[0]
    assert not failed.success
    assert failed.error_type == "SchemaParsingError"
    assert failed.error_message == "Introspection schema exceeds supported nesting."
    assert not result.executions
    assert result.evidence == schema_scan.evidence


@pytest.mark.parametrize("verbose", [False, True])
def test_total_transport_failure_is_actionable_private_and_still_exits_zero(
    mocked_scan, tmp_path, caplog, verbose
):
    state, requests, _ = mocked_scan
    state["failure"] = "transport"
    caplog.set_level(logging.DEBUG)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            TARGET,
            "-H",
            f"Authorization: Bearer {CANARIES[1]}",
            "-H",
            f"Cookie: session={CANARIES[1]}",
            "-H",
            f"X-API-Key: {CANARIES[1]}",
            "--proxy",
            f"http://{CANARIES[0]}:{CANARIES[1]}@127.0.0.1:8888",
            *(["-v"] if verbose else []),
        ],
    )
    assert result.exit_code == 0, result.exception
    text = " ".join(result.output.split())
    assert "Check the URL, network reachability, proxy and TLS settings." in text
    assert "HTTPTRANSPORTERROR" not in text
    assert len(requests) == len(generate_endpoint_candidates(Target.parse(TARGET)))
    if verbose:
        assert "HttpTransportError" in result.output
    assert all(value not in result.output + caplog.text for value in CANARIES)


def test_small_nested_body_and_oversized_body_remain_distinct():
    assert (
        HttpClientSettings().max_response_body_bytes
        == DEFAULT_MAX_RESPONSE_BODY_BYTES
        == 5 * 1024 * 1024
    )
    assert len(DEEP_JSON) < DEFAULT_MAX_RESPONSE_BODY_BYTES
    settings = HttpClientSettings(max_response_body_bytes=len(DEEP_JSON))
    for body, oversized in [(DEEP_JSON, False), (DEEP_JSON + b" ", True)]:
        with HttpClient(
            settings,
            transport=httpx.MockTransport(
                lambda request, body=body: httpx.Response(200, content=body)
            ),
        ) as client:
            if oversized:
                with pytest.raises(ResponseTooLargeError):
                    client.send(HttpRequest(method="GET", url=TARGET))
            else:
                response = client.send(HttpRequest(method="GET", url=TARGET))
                assert (
                    classify_execution_response(200, response.body).status.value
                    == "invalid_response"
                )
