"""Transport-compatible target validation before workflow startup, with no real sockets."""

import json
import socket
from unittest.mock import Mock

import httpx
import pytest
from graphql import build_schema, introspection_from_schema
from typer.testing import CliRunner

from gqlsleuth import cli
from gqlsleuth.application.differential_review import run_differential_scan
from gqlsleuth.application.safe_execution import run_safe_execution_scan
from gqlsleuth.application.scan_configuration import map_scan_inputs
from gqlsleuth.discovery.endpoint_candidates import generate_endpoint_candidates
from gqlsleuth.domain.differential import NamedAuthContext
from gqlsleuth.domain.exceptions import HttpTransportError, InvalidUrlError, TargetError
from gqlsleuth.domain.models import Target
from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY
from gqlsleuth.infrastructure.http import HttpClient, HttpRequest

SECRET = "FAKE_AUD003_SECRET"
INCOMPATIBLE = [
    pytest.param(f"https://\u2603.example/graphql?token={SECRET}", id="snowman"),
    pytest.param(f"https://a\u200db.example/graphql?token={SECRET}", id="joiner"),
    pytest.param("https://example.com/" + "x" * 66000 + f"?token={SECRET}", id="long-path"),
]
VALID = [
    "https://Example.COM/graphql?x=1&x=2",
    "https://b\u00fccher.example/graphql?language=de",
    "http://127.0.0.1:8765/graphql",
    "https://[::1]:8443/graphql",
    "http://Example.COM:80/base///?x=1&x=2",
    "https://Example.COM:443/graphql",
    "https://Example.COM:8443/graphql?operation=ping",
    "https://example.com/path%2Fpart?q=a%2Bb",
    "https://example.com/caf\u00e9?name=\u00e9",
    "https://example.com/",
]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Unexpected real socket/DNS activity")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


@pytest.mark.parametrize("url", INCOMPATIBLE)
def test_application_rejects_httpx_incompatibility_without_changing_domain_parser(url):
    assert Target.parse(url).original_url == url
    with pytest.raises(httpx.InvalidURL):
        httpx.URL(url)
    with pytest.raises(InvalidUrlError, match="not supported by the HTTP transport") as failure:
        map_scan_inputs(url)
    assert SECRET not in str(failure.value)
    assert failure.value.__suppress_context__


@pytest.mark.parametrize("url", INCOMPATIBLE)
@pytest.mark.parametrize("mode", ["safe", "active", "differential"])
@pytest.mark.parametrize("verbose", [False, True])
def test_invalid_target_exits_two_before_workflow_client_ai_or_reports(
    monkeypatch, tmp_path, url, mode, verbose
):
    forbidden = Mock(side_effect=AssertionError("Invalid input must not start the workflow"))
    for name in (
        "run_safe_execution_scan",
        "run_differential_scan",
        "interpret_completed_scan",
        "generate_reports",
        "activity_status",
    ):
        monkeypatch.setattr(cli, name, forbidden)
    monkeypatch.setattr(HttpClient, "__init__", forbidden)
    output = tmp_path / "reports"
    options = (
        ["--auth-context", "left", "--auth-context", f"right=Authorization: Bearer {SECRET}"]
        if mode == "differential"
        else [
            "--mode",
            mode,
            "--ai",
            "-H",
            f"Authorization: Bearer {SECRET}",
            "-H",
            f"Cookie: session={SECRET}",
            "-H",
            f"X-API-Key: {SECRET}",
        ]
    )
    result = CliRunner().invoke(
        cli.app,
        ["scan", url, *options, "-f", "json", "-o", str(output), *(["-v"] if verbose else [])],
    )
    assert result.exit_code == 2
    assert "not supported by the HTTP transport" in " ".join(result.output.split())
    assert "Traceback" not in result.output and SECRET not in result.output
    assert "Scanning target" not in result.output
    forbidden.assert_not_called()
    assert not output.exists()


@pytest.mark.parametrize("url", INCOMPATIBLE)
def test_application_entry_points_validate_before_creating_clients(monkeypatch, url):
    forbidden = Mock(side_effect=AssertionError("No HTTP client expected"))
    monkeypatch.setattr(HttpClient, "__init__", forbidden)
    with pytest.raises(InvalidUrlError):
        run_safe_execution_scan(url)
    with pytest.raises(InvalidUrlError):
        run_differential_scan(
            url, contexts=(NamedAuthContext("left", ()), NamedAuthContext("right", ()))
        )
    forbidden.assert_not_called()


@pytest.mark.parametrize("url", VALID)
def test_valid_url_components_and_discovery_normalization_remain_unchanged(url):
    before = Target.parse(url)
    target, _ = map_scan_inputs(url)
    assert target == before
    assert target.original_url == url
    candidates = generate_endpoint_candidates(target)
    assert candidates == generate_endpoint_candidates(before)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        response = client.send(HttpRequest(method="GET", url=candidates[0]))
    assert len(seen) == 1
    assert seen[0].url == httpx.URL(candidates[0])
    assert response.request_url == candidates[0] and response.body == b"ok"


def test_valid_long_url_is_not_rejected_by_an_arbitrary_shorter_limit():
    url = "https://example.com/" + "x" * 64000
    httpx.URL(url)
    assert map_scan_inputs(url)[0].original_url == url


@pytest.mark.parametrize(
    "url",
    [
        f"https://user:{SECRET}@example.com/graphql",
        f"https://example.com:{SECRET}/graphql?token={SECRET}",
        f"{SECRET.lower()}://example.com/graphql?token={SECRET}",
        f"ftp://example.com/graphql?token={SECRET}",
        f"https://[INVALID_{SECRET}]/graphql",
        "https:///graphql",
    ],
)
def test_existing_invalid_urls_remain_controlled_and_private(monkeypatch, url):
    with pytest.raises(TargetError) as failure:
        map_scan_inputs(url)
    assert SECRET.lower() not in str(failure.value).lower()
    forbidden = Mock(side_effect=AssertionError("Must not scan invalid target"))
    monkeypatch.setattr(cli, "run_safe_execution_scan", forbidden)
    result = CliRunner().invoke(cli.app, ["scan", url, "-H", f"X-API-Key: {SECRET}"])
    assert result.exit_code == 2 and "Traceback" not in result.output
    assert SECRET.lower() not in result.output.lower()
    forbidden.assert_not_called()


@pytest.mark.parametrize("url", INCOMPATIBLE)
def test_direct_adapter_call_normalizes_invalid_url_without_dispatch(url):
    handler = Mock(side_effect=AssertionError("Invalid URL must never reach transport"))
    with (
        HttpClient(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(HttpTransportError, match="invalid URL") as failure,
    ):
        client.send(HttpRequest(method="GET", url=url))
    assert SECRET not in str(failure.value)
    handler.assert_not_called()


@pytest.mark.parametrize(
    "location",
    [
        pytest.param(f"https://other.example:{SECRET}/graphql", id="invalid-port"),
        pytest.param("/" + "x" * 66000 + f"?token={SECRET}", id="long-location"),
        # The relative URL parses, but HTTPX rejects the longer joined absolute URL.
        pytest.param("/" + "x" * 65530, id="long-joined-location"),
    ],
)
def test_malformed_redirect_is_transport_failure_not_initial_target_error(location):
    seen, responses = [], []

    def handler(request):
        seen.append(request)
        response = httpx.Response(302, headers={"location": location})
        responses.append(response)
        return response

    with (
        HttpClient(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(HttpTransportError) as failure,
    ):
        client.send(HttpRequest(method="GET", url="https://example.com/graphql"))
    assert not isinstance(failure.value, TargetError)
    assert SECRET not in str(failure.value)
    assert len(seen) == 1 and responses[0].is_closed


def test_cli_server_redirect_error_remains_a_completed_scan(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        assert request.url.host == "example.com"
        return httpx.Response(302, headers={"location": f"https://other.example:{SECRET}/"})

    monkeypatch.setattr(
        "httpx._client.HTTPTransport", lambda **kwargs: httpx.MockTransport(handler)
    )
    result = CliRunner().invoke(cli.app, ["scan", "https://example.com/graphql"])
    assert result.exit_code == 0, result.exception
    assert seen and "Traceback" not in result.output and SECRET not in result.output


@pytest.mark.parametrize("url", [VALID[0], VALID[1], VALID[3]])
def test_valid_cli_safe_scan_preserves_requests_and_supplied_target(monkeypatch, url):
    seen, completed = [], []
    schema = introspection_from_schema(build_schema("type Query { ping: String }"))

    def handler(request):
        seen.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        document = json.loads(request.content)["query"]
        if document == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(
                200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
            )
        if document == FULL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": schema})
        assert document == "query {\n  ping\n}"
        return httpx.Response(200, json={"data": {"ping": "ok"}})

    monkeypatch.setattr(
        "httpx._client.HTTPTransport", lambda **kwargs: httpx.MockTransport(handler)
    )
    monkeypatch.setattr(
        cli, "render_completed_assessment", lambda console, result, **kw: completed.append(result)
    )
    result = CliRunner().invoke(cli.app, ["scan", url])
    assert result.exit_code == 0, result.exception
    assert [request.method for request in seen] == ["GET", "POST", "POST", "POST"]
    discovery = completed[
        0
    ].query_generation.operation_analysis.schema_scan.introspection.detection.discovery
    assert discovery.target.original_url == url
    expected = httpx.URL(generate_endpoint_candidates(Target.parse(url))[0])
    assert all(request.url == expected for request in seen)
