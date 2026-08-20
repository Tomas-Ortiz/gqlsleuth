"""Integration tests for discovery through the mocked HTTPX transport."""

import httpx

from gqlsleuth.application.endpoint_discovery import (
    DISCOVERY_SOURCE,
    discover_endpoints,
)
from gqlsleuth.discovery.endpoint_candidates import BUNDLED_ENDPOINT_PATHS
from gqlsleuth.domain.models import EvidenceType, ScanMode, Target
from gqlsleuth.infrastructure.http import HttpClient


def test_discovery_probes_with_get_and_retains_http_statuses() -> None:
    statuses = {
        "/graphql": 200,
        "/api/graphql": 401,
        "/gql": 403,
        "/api/gql": 404,
        "/v1/graphql": 405,
        "/v2/graphql": 500,
    }
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(statuses.get(request.url.path, 204), content=b"candidate")

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_endpoints(
            Target.parse("https://example.com"),
            mode=ScanMode.SAFE,
            client=client,
        )

    assert len(requests) == len(BUNDLED_ENDPOINT_PATHS)
    assert all(request.method == "GET" for request in requests)
    assert [probe.response.status_code for probe in result.probes if probe.response] == [
        statuses.get(path, 204) for path in BUNDLED_ENDPOINT_PATHS
    ]
    assert all(probe.error_type is None for probe in result.probes)


def test_one_transport_failure_does_not_stop_remaining_candidates() -> None:
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path == "/graphql":
            raise httpx.ConnectError("unavailable", request=request)
        return httpx.Response(404)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_endpoints(
            Target.parse("https://example.com"),
            mode=ScanMode.ACTIVE,
            client=client,
        )

    assert requested_paths == list(BUNDLED_ENDPOINT_PATHS)
    assert result.mode is ScanMode.ACTIVE
    assert result.probes[0].response is None
    assert result.probes[0].error_type == "HttpTransportError"
    assert all(probe.response is not None for probe in result.probes[1:])


def test_discovery_creates_endpoint_candidate_evidence_for_every_probe() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/graphql":
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(404)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_endpoints(
            Target.parse("https://example.com"),
            mode=ScanMode.SAFE,
            client=client,
        )

    assert len(result.evidence) == len(BUNDLED_ENDPOINT_PATHS)
    assert all(item.evidence_type is EvidenceType.ENDPOINT_CANDIDATE for item in result.evidence)
    assert all(item.source == DISCOVERY_SOURCE for item in result.evidence)
    assert [item.endpoint for item in result.evidence] == [
        f"https://example.com{path}" for path in BUNDLED_ENDPOINT_PATHS
    ]
    assert all(item.confidence is None for item in result.evidence)
    assert "HTTP 404" in result.evidence[0].summary
    assert "HttpTimeoutError" in result.evidence[1].summary
