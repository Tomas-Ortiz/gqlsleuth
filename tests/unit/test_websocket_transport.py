"""Central WebSocket configuration and privacy without outbound connections."""

import logging
import ssl
from types import SimpleNamespace

import pytest
from websockets.exceptions import ConnectionClosedError
from websockets.frames import Close

from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.infrastructure import websocket
from gqlsleuth.infrastructure.http import DEFAULT_USER_AGENT, HttpClientSettings


@pytest.mark.parametrize("verify", [True, False])
@pytest.mark.parametrize("proxy", [None, "http://127.0.0.1:8888", "https://127.0.0.1:8888"])
def test_explicit_transport_settings_no_ambient_proxy(monkeypatch, caplog, verify, proxy):
    observed = {}
    monkeypatch.setenv("HTTPS_PROXY", "http://ENV_CANARY:secret@127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")

    class Dial:
        def __init__(self, url, **kwargs):
            observed.update(kwargs)
            observed["url"] = url

        def __enter__(self):
            observed["connects"] = observed.get("connects", 0) + 1
            return SimpleNamespace(
                socket=SimpleNamespace(
                    settimeout=lambda value: observed.update(write_timeout=value)
                ),
                close=lambda: observed.update(closed=True),
            )

    monkeypatch.setattr(websocket, "_NoRedirect", Dial)
    settings = HttpClientSettings(
        timeout_seconds=3,
        verify_tls=verify,
        proxy=proxy,
        custom_headers=(("Authorization", "Bearer PHASE30_TRANSPORT_CANARY"),),
    )
    with websocket.WebSocketClient("wss://example.com/graphql", settings):
        pass
    assert observed["connects"] == 1 and observed["closed"]
    assert observed["proxy"] == proxy and observed["open_timeout"] == 3
    assert observed["user_agent_header"] == DEFAULT_USER_AGENT
    assert observed["additional_headers"] == settings.custom_headers
    assert observed["ssl"].verify_mode == (ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)
    assert (observed["proxy_ssl"] is not None) == bool(proxy and proxy.startswith("https:"))
    assert observed["subprotocols"] == ["graphql-transport-ws", "graphql-ws"]
    assert observed["max_size"] <= 1024 * 1024 and observed["max_queue"] == 1
    assert observed["compression"] is None and observed["ping_interval"] is None
    assert observed["write_timeout"] == 11.0
    with caplog.at_level(logging.DEBUG):
        observed["logger"].error("PHASE30_TRANSPORT_CANARY")
    assert "CANARY" not in caplog.text


@pytest.mark.parametrize("name", ["Origin", "Sec-WebSocket-Protocol", "sec-websocket-key"])
def test_reserved_headers_rejected_before_connect(name):
    with pytest.raises(HttpConfigurationError) as error:
        websocket.WebSocketClient(
            "ws://127.0.0.1/graphql",
            HttpClientSettings(custom_headers=((name, "PRIVATE_CANARY"),)),
        )
    assert "PRIVATE_CANARY" not in str(error.value)


def test_redirect_hook_returns_exception_without_following():
    failure = RuntimeError("fixture")
    assert websocket._NoRedirect.process_redirect(None, failure) is failure


@pytest.mark.parametrize("code", [None, 1000, 4403])
def test_close_during_send_retains_received_code_without_private_reason(code):
    def send(text):
        close = Close(code, "PRIVATE_CLOSE_REASON") if code is not None else None
        raise ConnectionClosedError(close, close, True if close else None)

    client = websocket.WebSocketClient("ws://127.0.0.1/graphql", HttpClientSettings())
    client._connection = SimpleNamespace(send=send)
    with pytest.raises(websocket.WebSocketFailure) as error:
        client.send("{}")
    assert error.value.code == code and error.value.network == (code is None)
    assert "PRIVATE_CLOSE_REASON" not in str(error.value)
