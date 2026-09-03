"""Offline integration tests for the complete Phase 4 detection workflow."""

import json

import httpx
import pytest

from gqlsleuth.application.endpoint_discovery import (
    EndpointDiscoveryResult,
    EndpointProbeResult,
)
from gqlsleuth.application.graphql_detection import (
    MINIMAL_TYPENAME_QUERY,
    detect_graphql,
    discover_and_detect_graphql,
)
from gqlsleuth.discovery.endpoint_candidates import generate_endpoint_candidates
from gqlsleuth.domain.models import (
    ConfidenceLevel,
    Evidence,
    EvidenceType,
    ScanMode,
    Target,
)
from gqlsleuth.graphql.detection import GraphQLSignal
from gqlsleuth.infrastructure.http import DEFAULT_TIMEOUT_SECONDS, HttpClient, HttpResponse


def test_confirmed_preferred_candidate_stops_before_remaining_discovery() -> None:
    target = Target.parse("https://example.com")
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        return httpx.Response(404, json={"status": "not graphql"})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_and_detect_graphql(target, mode=ScanMode.SAFE, client=client)

    assert [(request.method, request.url.path) for request in requests] == [
        ("GET", "/graphql"),
        ("POST", "/graphql"),
    ]
    assert requests[1].extensions["timeout"]["read"] == DEFAULT_TIMEOUT_SECONDS
    assert result.detections[0].confidence is ConfidenceLevel.CONFIRMED
    assert len(result.discovery.probes) == len(result.detections) == 1
    assert len(result.discovery.evidence) == len(result.confirmation_evidence) == 1


def test_probable_direct_candidate_is_first_and_stops_remaining_discovery() -> None:
    target = Target.parse("https://example.com/custom-graphql")
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            400,
            json={"errors": [{"message": "Must provide query string."}]},
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_and_detect_graphql(target, mode=ScanMode.SAFE, client=client)

    assert [(request.method, request.url.path) for request in requests] == [
        ("GET", "/custom-graphql")
    ]
    assert result.detections[0].confidence is ConfidenceLevel.PROBABLE
    assert [probe.candidate_url for probe in result.discovery.probes] == [
        "https://example.com/custom-graphql"
    ]


@pytest.mark.parametrize(
    ("headers", "expected_confidence"),
    [
        ({"content-type": "application/graphql-response+json"}, ConfidenceLevel.POSSIBLE),
        ({"content-type": "application/json"}, ConfidenceLevel.NOT_DETECTED),
    ],
)
def test_inconclusive_preferred_candidate_continues_all_discovery(
    headers: dict[str, str],
    expected_confidence: ConfidenceLevel,
) -> None:
    target = Target.parse("https://example.com")

    def handler(request: httpx.Request) -> httpx.Response:
        response_headers = headers if request.url.path == "/graphql" else {}
        return httpx.Response(200, headers=response_headers, json={"status": "generic"})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_and_detect_graphql(target, mode=ScanMode.SAFE, client=client)

    candidates = generate_endpoint_candidates(target)
    assert result.detections[0].confidence is expected_confidence
    assert [probe.candidate_url for probe in result.discovery.probes] == list(candidates)
    assert [detection.candidate_url for detection in result.detections] == list(candidates)


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


@pytest.mark.parametrize("error_type", ["HttpTimeoutError", "HttpTransportError"])
def test_discovery_transport_failure_does_not_send_fallback_post(error_type: str) -> None:
    candidate_url = "https://example.com/graphql"
    discovery = _failed_discovery(candidate_url, error_type)

    def unexpected_request(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected {request.method} request")

    with HttpClient(transport=httpx.MockTransport(unexpected_request)) as client:
        result = detect_graphql(discovery, client=client)

    detection = result.detections[0]
    assert detection.confidence is ConfidenceLevel.NOT_DETECTED
    assert detection.post_probe_required is False
    assert detection.post_response is None
    assert error_type in detection.reason
    assert "Fallback POST was not sent" in detection.reason


def test_http_405_response_can_still_reach_fallback_post() -> None:
    candidate_url = "https://example.com/graphql"
    discovery = _discovery(_response(candidate_url, b"Method Not Allowed", status_code=405))
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"data": {"__typename": "Query"}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = detect_graphql(discovery, client=client)

    assert [request.method for request in requests] == ["POST"]
    assert result.detections[0].post_probe_required is True
    assert result.detections[0].confidence is ConfidenceLevel.CONFIRMED


def test_other_candidates_continue_after_discovery_transport_failure() -> None:
    target = Target.parse("https://example.com")
    requests: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        if request.method == "GET" and request.url.path == "/graphql":
            raise httpx.ReadTimeout("unavailable", request=request)
        if request.method == "GET" and request.url.path == "/api/graphql":
            raise httpx.ConnectError("unavailable", request=request)
        return httpx.Response(405, content=b"Method Not Allowed")

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_and_detect_graphql(target, mode=ScanMode.SAFE, client=client)

    candidates = generate_endpoint_candidates(target)
    assert {path for method, path in requests if method == "GET"} == {
        httpx.URL(candidate).path for candidate in candidates
    }
    assert ("POST", "/graphql") not in requests
    assert ("POST", "/api/graphql") not in requests
    assert len([request for request in requests if request[0] == "POST"]) == len(candidates) - 2
    assert [detection.candidate_url for detection in result.detections] == list(candidates)
    assert result.detections[0].post_probe_required is False
    assert result.detections[1].post_probe_required is False
    assert all(detection.post_probe_required for detection in result.detections[2:])


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
    status_code: int = 200,
) -> HttpResponse:
    return HttpResponse(
        request_url=url,
        final_url=url,
        status_code=status_code,
        headers=headers or {"content-type": "application/json"},
        body=body,
        duration_seconds=0,
        redirect_count=0,
    )


def _failed_discovery(candidate_url: str, error_type: str) -> EndpointDiscoveryResult:
    target = Target.parse(candidate_url)
    return EndpointDiscoveryResult(
        target=target,
        mode=ScanMode.SAFE,
        probes=(
            EndpointProbeResult(
                candidate_url=candidate_url,
                error_type=error_type,
                error_message="Normalized discovery failure.",
            ),
        ),
        evidence=(
            Evidence(
                evidence_type=EvidenceType.ENDPOINT_CANDIDATE,
                target=target,
                endpoint=candidate_url,
                summary=f"GET probe failed with {error_type}.",
                source="test_graphql_detection",
            ),
        ),
    )
