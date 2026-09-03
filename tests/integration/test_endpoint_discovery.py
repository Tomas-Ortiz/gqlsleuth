"""Integration tests for discovery through the mocked HTTPX transport."""

from threading import Barrier, Event, Lock

import httpx

from gqlsleuth.application.endpoint_discovery import (
    DISCOVERY_MAX_WORKERS,
    DISCOVERY_SOURCE,
    DISCOVERY_TIMEOUT_SECONDS,
    discover_endpoints,
)
from gqlsleuth.discovery.endpoint_candidates import (
    BUNDLED_ENDPOINT_PATHS,
    generate_endpoint_candidates,
)
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

    assert requested_paths[0] == BUNDLED_ENDPOINT_PATHS[0]
    assert set(requested_paths) == set(BUNDLED_ENDPOINT_PATHS)
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


def test_discovery_gets_use_short_timeout() -> None:
    observed_timeouts: list[float] = []
    lock = Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        with lock:
            observed_timeouts.append(request.extensions["timeout"]["read"])
        return httpx.Response(404)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        discover_endpoints(Target.parse("https://example.com"), mode=ScanMode.SAFE, client=client)

    assert observed_timeouts
    assert set(observed_timeouts) == {DISCOVERY_TIMEOUT_SECONDS}


def test_remaining_candidates_use_at_most_four_workers_and_keep_result_order() -> None:
    target = Target.parse("https://example.com")
    candidates = generate_endpoint_candidates(target)
    synchronized_paths = set(BUNDLED_ENDPOINT_PATHS[1:5])
    first_remaining = BUNDLED_ENDPOINT_PATHS[1]
    later_remaining = BUNDLED_ENDPOINT_PATHS[4]
    barrier = Barrier(DISCOVERY_MAX_WORKERS)
    later_completed = Event()
    lock = Lock()
    active_workers = 0
    maximum_workers = 0
    completion_order: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_workers, maximum_workers
        path = request.url.path
        if path == BUNDLED_ENDPOINT_PATHS[0]:
            return httpx.Response(404)

        with lock:
            active_workers += 1
            maximum_workers = max(maximum_workers, active_workers)

        if path in synchronized_paths:
            barrier.wait(timeout=5)
        if path == first_remaining:
            assert later_completed.wait(timeout=5)
        with lock:
            completion_order.append(path)
        if path == later_remaining:
            later_completed.set()
        with lock:
            active_workers -= 1
        return httpx.Response(404)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = discover_endpoints(target, mode=ScanMode.SAFE, client=client)

    assert maximum_workers == DISCOVERY_MAX_WORKERS
    assert completion_order.index(later_remaining) < completion_order.index(first_remaining)
    assert [probe.candidate_url for probe in result.probes] == list(candidates)
    assert [evidence.endpoint for evidence in result.evidence] == list(candidates)
