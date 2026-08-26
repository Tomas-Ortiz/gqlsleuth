"""Offline integration tests for the complete Phase 4 detection workflow."""

import json

import httpx

from gqlsleuth.application.endpoint_discovery import (
    EndpointDiscoveryResult,
    EndpointProbeResult,
)
from gqlsleuth.application.graphql_detection import (
    MINIMAL_TYPENAME_QUERY,
    detect_graphql,
)
from gqlsleuth.domain.models import (
    ConfidenceLevel,
    Evidence,
    EvidenceType,
    ScanMode,
    Target,
)
from gqlsleuth.graphql.detection import GraphQLSignal
from gqlsleuth.infrastructure.http import HttpClient, HttpResponse


def test_probable_get_response_does_not_send_a_duplicate_probe() -> None:
    discovery = _discovery(
        _response(
            "https://example.com/graphql",
            b'{"errors":[{"message":"Must provide query string."}]}',
        )
    )

    def unexpected_request(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected {request.method} request")

    with HttpClient(transport=httpx.MockTransport(unexpected_request)) as client:
        result = detect_graphql(discovery, client=client)

    detection = result.detections[0]
    assert detection.confidence is ConfidenceLevel.PROBABLE
    assert detection.post_probe_required is False
    assert GraphQLSignal.GRAPHQL_ERROR_MESSAGE in detection.get_signals


def test_inconclusive_get_sends_minimal_post_and_confirms_typename() -> None:
    candidate_url = "https://example.com/graphql"
    discovery = _discovery(_response(candidate_url, b'{"status":"ok"}'))
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/graphql-response+json"},
            json={"data": {"__typename": "Query"}},
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = detect_graphql(discovery, client=client)

    detection = result.detections[0]
    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert str(requests[0].url) == candidate_url
    assert json.loads(requests[0].content) == {"query": MINIMAL_TYPENAME_QUERY}
    assert detection.post_probe_required is True
    assert detection.confidence is ConfidenceLevel.CONFIRMED
    assert detection.post_response is not None
    assert GraphQLSignal.TYPENAME_STRING in detection.post_signals


def test_post_transport_failure_does_not_stop_remaining_candidates() -> None:
    discovery = _discovery(
        _response("https://example.com/graphql", b"not graphql"),
        _response("https://example.com/api/graphql", b"not graphql"),
    )
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path == "/graphql":
            raise httpx.ConnectError("unavailable", request=request)
        return httpx.Response(200, json={"data": {"__typename": "Query"}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = detect_graphql(discovery, client=client)

    assert requested_paths == ["/graphql", "/api/graphql"]
    assert result.detections[0].post_error_type == "HttpTransportError"
    assert result.detections[0].confidence is ConfidenceLevel.NOT_DETECTED
    assert result.detections[1].confidence is ConfidenceLevel.CONFIRMED


def test_generic_json_and_html_remain_not_detected_after_fallback() -> None:
    generic_json = b'{"status":"ok","query":"stored"}'
    generic_html = b"<html><h1>Generic error</h1></html>"
    discovery = _discovery(
        _response("https://example.com/graphql", generic_json),
        _response(
            "https://example.com/api/graphql",
            generic_html,
            headers={"content-type": "text/html"},
        ),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/graphql":
            return httpx.Response(200, content=generic_json)
        return httpx.Response(500, headers={"content-type": "text/html"}, content=generic_html)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = detect_graphql(discovery, client=client)

    assert all(item.post_probe_required for item in result.detections)
    assert all(item.confidence is ConfidenceLevel.NOT_DETECTED for item in result.detections)


def test_confirmation_evidence_preserves_discovery_evidence() -> None:
    candidate_url = "https://example.com/graphql"
    discovery = _discovery(_response(candidate_url, b'{"status":"ok"}'))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"__typename": "Query"}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = detect_graphql(discovery, client=client)

    confirmation = result.confirmation_evidence[0]
    assert result.discovery is discovery
    assert result.evidence[0] is discovery.evidence[0]
    assert result.evidence == discovery.evidence + result.confirmation_evidence
    assert confirmation.evidence_type is EvidenceType.GRAPHQL_CONFIRMATION
    assert confirmation.endpoint == candidate_url
    assert confirmation.confidence is ConfidenceLevel.CONFIRMED
    assert confirmation.source == "gqlsleuth.application.graphql_detection"
    assert "POST signals" in confirmation.notes[2]


def _discovery(*responses: HttpResponse) -> EndpointDiscoveryResult:
    target = Target.parse("https://example.com/graphql")
    probes = tuple(
        EndpointProbeResult(candidate_url=response.request_url, response=response)
        for response in responses
    )
    evidence = tuple(
        Evidence(
            evidence_type=EvidenceType.ENDPOINT_CANDIDATE,
            target=target,
            endpoint=response.request_url,
            summary=f"GET probe returned HTTP {response.status_code}.",
            source="test_graphql_detection",
        )
        for response in responses
    )
    return EndpointDiscoveryResult(
        target=target,
        mode=ScanMode.SAFE,
        probes=probes,
        evidence=evidence,
    )


def _response(
    url: str,
    body: bytes,
    *,
    headers: dict[str, str] | None = None,
) -> HttpResponse:
    return HttpResponse(
        request_url=url,
        final_url=url,
        status_code=200,
        headers=headers or {"content-type": "application/json"},
        body=body,
        duration_seconds=0,
        redirect_count=0,
    )
