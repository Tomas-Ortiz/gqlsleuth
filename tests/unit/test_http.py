"""Mocked tests for the centralized synchronous HTTP layer."""

import json
from collections.abc import Iterator

import httpx
import pytest

from gqlsleuth import __version__
from gqlsleuth.domain.exceptions import (
    HttpProxyError,
    HttpRedirectError,
    HttpTimeoutError,
    HttpTransportError,
    ResponseTooLargeError,
)
from gqlsleuth.infrastructure.http import (
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_MAX_RESPONSE_BODY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    HttpClient,
    HttpClientSettings,
    HttpRequest,
)


class ChunkStream(httpx.SyncByteStream):
    """Yield tracked chunks so size-limit tests can verify early termination."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.chunks_read = 0

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self.chunks:
            self.chunks_read += 1
            yield chunk


def test_http_client_settings_have_conservative_defaults() -> None:
    settings = HttpClientSettings()

    assert settings.timeout_seconds == DEFAULT_TIMEOUT_SECONDS == 10.0
    assert settings.verify_tls is True
    assert settings.follow_redirects is True
    assert settings.max_redirects == DEFAULT_MAX_REDIRECTS == 5
    assert settings.max_response_body_bytes == DEFAULT_MAX_RESPONSE_BODY_BYTES == 5 * 1024 * 1024
    assert settings.proxy is None
    assert HttpClientSettings(proxy="http://proxy.example").proxy == "http://proxy.example"


def test_successful_response_preserves_transport_information() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"X-Server": "test"}, content=b"response", request=request
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        response = client.send(HttpRequest(method="GET", url="https://example.com/resource"))

    assert response.request_url == "https://example.com/resource"
    assert response.final_url == "https://example.com/resource"
    assert response.status_code == 200
    assert response.headers["x-server"] == "test"
    assert response.body == b"response"
    assert response.duration_seconds >= 0
    assert response.redirect_count == 0


def test_request_maps_method_url_json_body_and_custom_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://example.com/resource?view=full"
        assert request.headers["X-Test"] == "value"
        assert request.headers["User-Agent"] == f"GQLSleuth/{__version__}"
        assert json.loads(request.content) == {"query": "value", "enabled": True}
        return httpx.Response(201, content=b"created", request=request)

    request = HttpRequest(
        method="POST",
        url="https://example.com/resource?view=full",
        headers={"X-Test": "value"},
        json_body={"query": "value", "enabled": True},
    )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        response = client.send(request)

    assert response.status_code == 201


def test_request_can_override_default_user_agent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["User-Agent"] == "CustomAgent/1.0"
        return httpx.Response(200, request=request)

    request = HttpRequest(
        method="GET",
        url="https://example.com",
        headers={"User-Agent": "CustomAgent/1.0"},
    )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        client.send(request)


@pytest.mark.parametrize("status_code", [404, 500])
def test_http_error_statuses_are_returned_normally(status_code: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, content=b"error response", request=request)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        response = client.send(HttpRequest(method="GET", url="https://example.com"))

    assert response.status_code == status_code
    assert response.body == b"error response"


def test_redirects_are_followed_and_recorded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/final"}, request=request)
        return httpx.Response(200, content=b"done", request=request)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        response = client.send(HttpRequest(method="GET", url="https://example.com/start"))

    assert response.request_url == "https://example.com/start"
    assert response.final_url == "https://example.com/final"
    assert response.redirect_count == 1
    assert response.body == b"done"


def test_timeout_is_normalized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    with (
        HttpClient(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(HttpTimeoutError) as captured,
    ):
        client.send(HttpRequest(method="GET", url="https://example.com"))

    assert isinstance(captured.value.__cause__, httpx.ReadTimeout)


@pytest.mark.parametrize(
    ("httpx_error", "expected_error"),
    [
        (httpx.ProxyError, HttpProxyError),
        (httpx.ConnectError, HttpTransportError),
    ],
)
def test_proxy_and_transport_errors_are_normalized(
    httpx_error: type[httpx.RequestError],
    expected_error: type[Exception],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx_error("failed", request=request)

    with (
        HttpClient(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(expected_error),
    ):
        client.send(HttpRequest(method="GET", url="https://example.com"))


def test_redirect_limit_error_is_normalized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "/again"}, request=request)

    settings = HttpClientSettings(max_redirects=1)
    with (
        HttpClient(settings, transport=httpx.MockTransport(handler)) as client,
        pytest.raises(HttpRedirectError),
    ):
        client.send(HttpRequest(method="GET", url="https://example.com/start"))


def test_response_at_size_limit_succeeds() -> None:
    stream = ChunkStream([b"abc", b"def"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream, request=request)

    settings = HttpClientSettings(max_response_body_bytes=6)
    with HttpClient(settings, transport=httpx.MockTransport(handler)) as client:
        response = client.send(HttpRequest(method="GET", url="https://example.com"))

    assert response.body == b"abcdef"
    assert stream.chunks_read == 2


def test_oversized_response_stops_streaming_and_raises() -> None:
    stream = ChunkStream([b"abc", b"def", b"unread"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream, request=request)

    settings = HttpClientSettings(max_response_body_bytes=5)
    with (
        HttpClient(settings, transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ResponseTooLargeError, match="5-byte limit"),
    ):
        client.send(HttpRequest(method="GET", url="https://example.com"))

    assert stream.chunks_read == 2
