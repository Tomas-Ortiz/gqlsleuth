"""Offline Phase 14 parsing, merging, redirect scope, and transport configuration."""

import logging

import httpx
import pytest
from pydantic import ValidationError

from gqlsleuth.application.scan_configuration import map_target_http_inputs
from gqlsleuth.domain.exceptions import HttpConfigurationError, HttpTransportError
from gqlsleuth.infrastructure.http import (
    DEFAULT_USER_AGENT,
    HttpClient,
    HttpClientSettings,
    HttpRequest,
)

CANARY = "AUTH_CANARY_PHASE14"
HEADERS = (
    ("Authorization", f"Bearer {CANARY}"),
    ("Cookie", f"session={CANARY}"),
    ("X-API-Key", CANARY),
    ("X-Custom-Credential", CANARY),
)


def test_headers_split_first_colon_trim_whitespace_and_preserve_duplicates():
    settings = map_target_http_inputs(
        headers=[" Authorization \t: Bearer abc:def:ghi ", "X-Test: one", "x-test: two", "X-Empty:"]
    )
    assert settings.custom_headers == (
        ("Authorization", "Bearer abc:def:ghi"),
        ("X-Test", "one"),
        ("x-test", "two"),
        ("X-Empty", ""),
    )


@pytest.mark.parametrize(
    "entry",
    [
        CANARY,
        ": " + CANARY,
        "Bad Name: " + CANARY,
        "Name\r: " + CANARY,
        "Name: " + CANARY + "\nInjected: yes",
        "Name: " + CANARY + "\x00",
        "Name: " + CANARY + "\x7f",
        "Náme: " + CANARY,
        "Name: café",
        "Content-Length: 1",
        "Transfer-Encoding: chunked",
        "Host: example.com",
        "Connection: X-Secret",
        "Proxy-Authorization: " + CANARY,
    ],
)
def test_invalid_headers_are_controlled_and_do_not_echo_values(entry):
    with pytest.raises(HttpConfigurationError) as error:
        map_target_http_inputs(headers=["X-Valid: one", entry])
    assert "Header argument 2" in str(error.value)
    assert CANARY not in str(error.value)


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "1e999", "abc"])
def test_invalid_timeout_is_controlled(value):
    with pytest.raises(HttpConfigurationError, match="finite positive"):
        map_target_http_inputs(timeout=value)


@pytest.mark.parametrize(
    "value,normal,discovery", [(None, 10, 8), ("20", 20, 20), ("7.5", 7.5, 7.5)]
)
def test_timeout_defaults_and_explicit_override(value, normal, discovery):
    settings = map_target_http_inputs(timeout=value)
    assert settings.timeout_seconds == normal
    assert settings.discovery_timeout_seconds == discovery


@pytest.mark.parametrize(
    "value",
    [
        "",
        "127.0.0.1:8080",
        "socks5://localhost:1080",
        "ftp://localhost",
        "http://",
        "http://localhost:0",
        "http://localhost:65536",
        "http://localhost:bad",
        "http://localhost/path",
        "http://localhost?x=1",
        "http://localhost/#fragment",
        "http://user:" + CANARY + "@bad host",
        "http://localhost\n",
        "http://[broken",
    ],
)
def test_invalid_proxy_never_echoes_credentials(value):
    with pytest.raises(HttpConfigurationError, match="--proxy") as error:
        map_target_http_inputs(proxy=value)
    assert CANARY not in str(error.value)


def test_settings_are_immutable_and_representations_hide_supplied_secrets():
    settings = HttpClientSettings(
        custom_headers=HEADERS, proxy=f"http://user:{CANARY}@localhost:8080"
    )
    assert CANARY not in repr(settings)
    with pytest.raises(ValidationError):
        settings.verify_tls = False
    with pytest.raises(ValidationError) as error:
        HttpClientSettings(proxy=f"socks5://user:{CANARY}@localhost")
    assert CANARY not in str(error.value)


def test_header_merge_duplicates_user_agent_and_json_framing():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"data": None})

    settings = map_target_http_inputs(
        headers=[
            "X-Test: one",
            "x-test: two",
            "User-Agent: Tester/1",
            "Content-Type: text/plain",
            "X-Protocol: user",
        ]
    )
    with HttpClient(settings, transport=httpx.MockTransport(handler)) as client:
        client.send(HttpRequest(method="GET", url="https://example.com"))
        client.send(
            HttpRequest(
                method="POST",
                url="https://example.com",
                headers={"X-Protocol": "scanner"},
                json_body={"query": "query { health }"},
            )
        )
    for request in seen:
        assert request.headers.get_list("x-test") == ["one", "two"]
        assert request.headers["user-agent"] == "Tester/1"
    assert seen[0].headers["content-type"] == "text/plain"
    assert seen[1].headers.get_list("content-type") == ["application/json"]
    assert seen[1].headers.get_list("x-protocol") == ["scanner"]
    assert seen[1].headers.get_list("content-length") == [str(len(seen[1].content))]


def test_no_options_preserve_default_request_bytes_and_headers():
    seen = []
    transport = httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200))
    body = {"query": "query { health }", "variables": {}}
    with httpx.Client(
        headers={"User-Agent": DEFAULT_USER_AGENT}, trust_env=False, transport=transport
    ) as baseline:
        baseline.post("https://example.com", json=body)
    with HttpClient(transport=transport) as client:
        client.send(HttpRequest(method="POST", url="https://example.com", json_body=body))
    assert seen[0].headers.raw == seen[1].headers.raw
    assert seen[0].content == seen[1].content


def test_initial_custom_header_order_including_explicit_cookie_is_preserved():
    seen = []
    transport = httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200))
    with HttpClient(HttpClientSettings(custom_headers=HEADERS), transport=transport) as client:
        client.send(HttpRequest(method="GET", url="https://example.com"))
    names = {name.lower() for name, _ in HEADERS}
    assert [(name, value) for name, value in seen[0].headers.multi_items() if name in names] == [
        (name.lower(), value) for name, value in HEADERS
    ]
    assert CANARY not in repr(seen[0].extensions)


@pytest.mark.parametrize(
    "destination",
    [
        "https://example.com/next",
        "https://other.example/next",
        "http://example.com/next",
        "https://example.com:8443/next",
    ],
)
def test_redirects_keep_same_origin_headers_and_strip_cross_origin_canaries(destination):
    seen = []

    def handler(request):
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(307, headers={"Location": destination})
        if len(seen) == 2:
            return httpx.Response(307, headers={"Location": "https://example.com/final"})
        return httpx.Response(200, json={"data": None})

    with HttpClient(
        HttpClientSettings(custom_headers=HEADERS), transport=httpx.MockTransport(handler)
    ) as client:
        response = client.send(
            HttpRequest(
                method="POST",
                url="https://example.com/start",
                json_body={"query": "query { health }"},
            )
        )
    assert response.redirect_count == 2
    assert len(seen) == 3
    for request in seen:
        assert request.headers["content-type"] == "application/json"
    assert CANARY in str(seen[0].headers.multi_items())
    for request in seen[1:]:
        if destination == "https://example.com/next":
            for name, value in HEADERS:
                assert request.headers[name] == value
        else:
            assert CANARY not in str(request.headers.multi_items())


@pytest.mark.parametrize(
    "proxy", [None, "http://user:PROXY_CANARY@localhost:8080", "https://localhost:8443"]
)
@pytest.mark.parametrize("verify", [True, False])
def test_httpx_transport_receives_explicit_tls_proxy_and_ignores_environment(
    monkeypatch, proxy, verify
):
    constructed = []
    routed = []

    def transport_factory(**kwargs):
        constructed.append(kwargs)
        return httpx.MockTransport(lambda request: routed.append(kwargs) or httpx.Response(200))

    monkeypatch.setattr("httpx._client.HTTPTransport", transport_factory)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(key, "http://ENV_CANARY:secret@invalid.example:1")
    with HttpClient(HttpClientSettings(proxy=proxy, verify_tls=verify)) as client:
        client.send(HttpRequest(method="GET", url="https://example.com"))
    assert len(constructed) == (2 if proxy else 1)
    assert all(item["verify"] is verify and item["trust_env"] is False for item in constructed)
    configured_proxy = routed[0].get("proxy")
    assert (configured_proxy is not None) is (proxy is not None)
    if proxy:
        assert configured_proxy.url.host == "localhost"
        assert configured_proxy.url.scheme == proxy.split(":")[0]
    assert "ENV_CANARY" not in repr(constructed)


def test_tls_failure_is_normalized_without_retry_or_secret_logging(caplog):
    seen = []

    def fail(request):
        seen.append(request)
        raise httpx.ConnectError("certificate verification failed " + CANARY, request=request)

    caplog.set_level(logging.DEBUG)
    with HttpClient(
        HttpClientSettings(custom_headers=HEADERS), transport=httpx.MockTransport(fail)
    ) as client:
        with pytest.raises(HttpTransportError) as error:
            client.send(HttpRequest(method="GET", url="https://example.com"))
        assert client.settings.verify_tls is True
    assert len(seen) == 1
    assert CANARY not in str(error.value)
    assert CANARY not in caplog.text
