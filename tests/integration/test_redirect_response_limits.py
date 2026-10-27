"""Streamed redirect limits and their existing scanner failure/consent boundaries."""

import gzip
import json

import httpx
import pytest

from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.endpoint_discovery import probe_endpoint_candidates
from gqlsleuth.application.introspection import introspect_detected_endpoints
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.application.schema_parsing import parse_introspection_schemas
from gqlsleuth.domain.exceptions import (
    HttpRedirectDeniedError,
    HttpTimeoutError,
    HttpTransportError,
    ResponseTooLargeError,
)
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.graphql.introspection import MINIMAL_INTROSPECTION_QUERY
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest
from gqlsleuth.infrastructure.redirect_consent import RedirectConsent

SOURCE = "https://example.com/graphql"
DESTINATION = "https://api.example.com/final"


class TrackedStream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.consumed = 0
        self.closes = 0

    def __iter__(self):
        for chunk in self.chunks:
            self.consumed += 1
            if isinstance(chunk, BaseException):
                raise chunk
            yield chunk

    def close(self):
        self.closes += 1


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("length_header", [None, "0", "999"])
@pytest.mark.parametrize("size", [8, 16, 64])
def test_streamed_redirect_sizes_ignore_unreliable_content_length(method, length_header, size):
    stream = TrackedStream([b"x" * 8] * (size // 8))
    seen, responses = [], []
    headers = {"location": "/final"}
    if length_header is not None:
        headers["content-length"] = length_header

    def handler(request):
        seen.append(request)
        response = (
            httpx.Response(307, headers=headers, stream=stream)
            if len(seen) == 1
            else httpx.Response(200, content=b"ok")
        )
        responses.append(response)
        return response

    with HttpClient(
        HttpClientSettings(max_response_body_bytes=16), transport=httpx.MockTransport(handler)
    ) as client:
        request = HttpRequest(
            method=method, url=SOURCE, json_body={"query": "{ ping }"} if method == "POST" else None
        )
        if size > 16:
            with pytest.raises(ResponseTooLargeError, match="16-byte limit"):
                client.send(request)
            assert len(seen) == 1
            assert stream.consumed == 3  # Stop at the first over-limit chunk, not all eight.
        else:
            result = client.send(request)
            assert result.body == b"ok" and result.redirect_count == 1
            assert seen[1].method == method
            assert seen[1].content == seen[0].content
            assert responses[0].read() == b"x" * size  # HTTPX's history cache is intact.
            assert responses[1].history == responses[:1]
            assert responses[0].headers == httpx.Headers(headers)
    assert stream.closes == 1
    assert responses[0].is_closed


@pytest.mark.parametrize("answer", [True, False, None])
@pytest.mark.parametrize("oversized", [False, True])
def test_cross_origin_body_limit_precedes_destination_transmission(answer, oversized):
    stream = TrackedStream([b"x" * 8] * (8 if oversized else 2))
    seen, notices = [], []

    def handler(request):
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(
                302,
                headers={
                    "location": DESTINATION,
                    "set-cookie": "session=FAKE_COOKIE; Domain=example.com; Path=/",
                },
                stream=stream,
            )
        return httpx.Response(200, content=b"ok")

    consent = RedirectConsent(
        (lambda notice: notices.append(notice) or answer) if answer is not None else None
    )
    with HttpClient(
        HttpClientSettings(max_response_body_bytes=16, redirect_consent=consent),
        transport=httpx.MockTransport(handler),
    ) as client:
        if oversized:
            with pytest.raises(ResponseTooLargeError):
                client.send(HttpRequest(method="GET", url=SOURCE))
            assert not notices  # Failure is at the source; no consent decision is fabricated.
        elif answer:
            client.send(HttpRequest(method="GET", url=SOURCE))
            assert seen[-1].headers["cookie"] == "session=FAKE_COOKIE"
        else:
            with pytest.raises(HttpRedirectDeniedError):
                client.send(HttpRequest(method="GET", url=SOURCE))
    assert len(seen) == (2 if answer and not oversized else 1)
    assert stream.consumed == (3 if oversized else 2)
    assert stream.closes == 1


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_approved_nonempty_redirect_preserves_httpx_post_and_context_semantics(code):
    seen, notices, streams = [], [], []
    body = {"query": "query ($id: ID!) { item(id: $id) { id } }", "variables": {"id": "1"}}
    consent = RedirectConsent(lambda notice: notices.append(notice) or True)

    def handler(request):
        seen.append(request)
        if request.url.host == "example.com":
            stream = TrackedStream([b"redirect"])
            streams.append(stream)
            return httpx.Response(code, headers={"location": DESTINATION}, stream=stream)
        return httpx.Response(200, content=b"ok")

    for secret in ("FAKE_CONTEXT_A", "FAKE_CONTEXT_B"):
        settings = HttpClientSettings(
            max_response_body_bytes=16,
            timeout_seconds=7,
            redirect_consent=consent,
            custom_headers=(("Authorization", secret), ("Cookie", f"session={secret}")),
        )
        with HttpClient(settings, transport=httpx.MockTransport(handler)) as client:
            result = client.send(HttpRequest(method="POST", url=SOURCE, json_body=body))
        assert result.redirect_count == 1
        assert seen[-1].headers["authorization"] == secret
        assert seen[-1].headers["cookie"] == f"session={secret}"
        assert seen[-1].method == ("POST" if code in {307, 308} else "GET")
        assert seen[-1].content == (seen[-2].content if code in {307, 308} else b"")
        # HTTPX retains Content-Type even when a POST becomes GET; only framing changes.
        assert seen[-1].headers["content-type"] == "application/json"
        assert ("content-length" in seen[-1].headers) is (code in {307, 308})
        assert seen[-1].extensions["timeout"] == seen[-2].extensions["timeout"]
    assert len(seen) == 4 and len(notices) == 1
    assert all(stream.closes == 1 for stream in streams)


def test_multihop_failure_closes_streams_and_client_can_send_next_request():
    streams = [TrackedStream([b"x" * 8] * n) for n in (2, 2, 8)]
    seen = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path == "/independent":
            return httpx.Response(200, content=b"ok")
        index = int(request.url.path[1:])
        assert index < 3
        return httpx.Response(302, headers={"location": f"/{index + 1}"}, stream=streams[index])

    with HttpClient(
        HttpClientSettings(max_response_body_bytes=16), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ResponseTooLargeError):
            client.send(HttpRequest(method="GET", url="https://example.com/0"))
        assert (
            client.send(HttpRequest(method="GET", url="https://example.com/independent")).body
            == b"ok"
        )
    assert seen == ["/0", "/1", "/2", "/independent"]
    assert [stream.consumed for stream in streams] == [2, 2, 3]
    assert all(stream.closes == 1 for stream in streams)


@pytest.mark.parametrize("size", [16, 64])
def test_redirect_limit_counts_decoded_bytes_and_preserves_encoding_headers(size):
    encoded = gzip.compress(b"x" * size)
    stream = TrackedStream([encoded, b"unread"] if size > 16 else [encoded])
    responses = []

    def handler(request):
        response = (
            httpx.Response(
                302,
                headers={"location": "/final", "content-encoding": "gzip"},
                stream=stream,
            )
            if not responses
            else httpx.Response(200, content=b"ok")
        )
        responses.append(response)
        return response

    with HttpClient(
        HttpClientSettings(max_response_body_bytes=16), transport=httpx.MockTransport(handler)
    ) as client:
        if size > 16:
            with pytest.raises(ResponseTooLargeError):
                client.send(HttpRequest(method="GET", url=SOURCE))
            assert len(responses) == 1
        else:
            client.send(HttpRequest(method="GET", url=SOURCE))
            assert responses[0].read() == b"x" * size
        assert responses[0].headers["content-encoding"] == "gzip"
    assert stream.consumed == stream.closes == 1


@pytest.mark.parametrize("follow", [False, True])
def test_redirect_stream_interrupt_closes_response_without_forwarding(follow):
    stream = TrackedStream([b"x", KeyboardInterrupt()])
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(307, headers={"location": DESTINATION}, stream=stream)

    with (
        HttpClient(
            HttpClientSettings(follow_redirects=follow), transport=httpx.MockTransport(handler)
        ) as client,
        pytest.raises(KeyboardInterrupt),
    ):
        client.send(HttpRequest(method="GET", url=SOURCE))
    assert len(seen) == stream.closes == 1


def test_discovery_workers_retain_normalized_size_failure():
    streams = []

    def handler(request):
        assert request.url.host == "example.com"
        stream = TrackedStream([b"x" * 8] * 8)
        streams.append(stream)
        return httpx.Response(302, headers={"location": DESTINATION}, stream=stream)

    with HttpClient(
        HttpClientSettings(max_response_body_bytes=16), transport=httpx.MockTransport(handler)
    ) as client:
        result = probe_endpoint_candidates(
            Target.parse(SOURCE),
            mode=ScanMode.SAFE,
            client=client,
            candidate_urls=tuple(f"https://example.com/path{i}" for i in range(4)),
        )
    assert len(streams) == 4
    assert all(s.consumed == 3 and s.closes == 1 for s in streams)
    assert all(
        p.error_type == "ResponseTooLargeError" and p.response is None for p in result.probes
    )
    assert all(e.response_status_code is None and e.response_body is None for e in result.evidence)


def test_full_introspection_redirect_failure_does_not_create_schema(phase_ten_scan):
    safe, _ = phase_ten_scan(mode=ScanMode.SAFE)
    detection = safe.query_generation.operation_analysis.schema_scan.introspection.detection
    stream = TrackedStream([b"x" * 128] * 8)
    seen = []

    def handler(request):
        seen.append(request)
        assert str(request.url) == SOURCE
        if json.loads(request.content)["query"] == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(
                200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
            )
        return httpx.Response(307, headers={"location": "/full"}, stream=stream)

    with HttpClient(
        HttpClientSettings(max_response_body_bytes=256), transport=httpx.MockTransport(handler)
    ) as client:
        result = introspect_detected_endpoints(detection, client=client)
    endpoint = result.introspections[0]
    assert endpoint.full_error_type == "ResponseTooLargeError"
    assert endpoint.full_response is None
    assert len(seen) == 2  # No redirect, retry or reduced fallback for a size failure.
    assert stream.consumed == 3 and stream.closes == 1
    assert not any(item.success for item in parse_introspection_schemas(result).schemas)


@pytest.mark.parametrize("active", [False, True])
def test_execution_size_failure_preserves_attempt_evidence_and_active_gate(phase_ten_scan, active):
    safe, _ = phase_ten_scan("type Query { ping: String } type Mutation { createItem: String }")
    preview = prepare_active_mutations(safe)
    stream = TrackedStream([b"x" * 8] * 8)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(307, headers={"location": DESTINATION}, stream=stream)

    with HttpClient(
        HttpClientSettings(max_response_body_bytes=16), transport=httpx.MockTransport(handler)
    ) as client:
        if active:
            declined = execute_selected_mutations(preview, selected_indices=(1,), client=client)
            assert not seen and not declined.execution_evidence
            result = execute_selected_mutations(
                preview, selected_indices=(1,), confirmed=True, client=client
            )
        else:
            result = execute_generated_queries(safe.query_generation, client=client)
    assert len(seen) == len(result.execution_evidence) == 1
    assert stream.consumed == 3 and stream.closes == 1
    execution = result.executions[0]
    assert execution.status is QueryExecutionStatus.NETWORK_FAILURE
    assert execution.error_type == "ResponseTooLargeError" and execution.response is None
    evidence = result.execution_evidence[0]
    assert evidence.response_status_code is None and evidence.response_body is None
    assert evidence.error_type == "ResponseTooLargeError"


@pytest.mark.parametrize(
    ("failure", "normalized"),
    [
        (httpx.ReadTimeout("fake timeout"), HttpTimeoutError),
        (httpx.ReadError("fake read failure"), HttpTransportError),
    ],
)
def test_redirect_stream_failure_is_normalized_and_closed(failure, normalized):
    stream = TrackedStream([b"x", failure, b"unread"])
    with (
        HttpClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(307, headers={"location": "/next"}, stream=stream)
            )
        ) as client,
        pytest.raises(normalized),
    ):
        client.send(HttpRequest(method="GET", url=SOURCE))
    assert stream.consumed == 2 and stream.closes == 1


def test_cancelled_consent_leaves_redirect_closed_and_stops_later_requests():
    stream = TrackedStream([b"small"])
    seen = []

    def confirm(notice):
        assert stream.closes == 1
        raise KeyboardInterrupt

    def handler(request):
        seen.append(request)
        return httpx.Response(307, headers={"location": DESTINATION}, stream=stream)

    with HttpClient(
        HttpClientSettings(redirect_consent=RedirectConsent(confirm)),
        transport=httpx.MockTransport(handler),
    ) as client:
        for _ in range(2):
            with pytest.raises(KeyboardInterrupt):
                client.send(HttpRequest(method="GET", url=SOURCE))
    assert len(seen) == stream.closes == 1


@pytest.mark.parametrize("oversized", [False, True])
def test_no_follow_keeps_redirect_as_final_response_and_still_limits_body(oversized):
    stream = TrackedStream([b"x" * 8] * (8 if oversized else 2))
    with HttpClient(
        HttpClientSettings(follow_redirects=False, max_response_body_bytes=16),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"location": DESTINATION}, stream=stream)
        ),
    ) as client:
        if oversized:
            with pytest.raises(ResponseTooLargeError):
                client.send(HttpRequest(method="GET", url=SOURCE))
        else:
            result = client.send(HttpRequest(method="GET", url=SOURCE))
            assert result.status_code == 302 and result.redirect_count == 0
            assert result.final_url == SOURCE and result.body == b"x" * 16
    assert stream.consumed == (3 if oversized else 2)
    assert stream.closes == 1
