"""One synchronous WebSocket connection, without redirects, retries or ambient proxies."""

import logging
import ssl
from types import TracebackType
from typing import Self

from websockets.exceptions import (
    ConnectionClosed,
    InvalidHandshake,
    InvalidStatus,
    WebSocketException,
)
from websockets.frames import Frame
from websockets.protocol import Event
from websockets.sync.client import ClientConnection, reconnect
from websockets.typing import Subprotocol

from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.subscriptions import (
    MAX_PHASE30_FRAME_BYTES,
    MAX_PHASE30_INBOUND_FRAMES,
    SubscriptionProtocol,
)
from gqlsleuth.infrastructure.http import DEFAULT_USER_AGENT, HttpClientSettings


class WebSocketFailure(Exception):
    """Normalized facts only; library exceptions/reasons can contain credentials."""

    def __init__(
        self, *, status: int | None = None, code: int | None = None, network: bool = False
    ) -> None:
        super().__init__("WebSocket transport or protocol failed.")
        self.status, self.code, self.network = status, code, network


class _NoRedirect(reconnect):
    def process_redirect(self, exc: Exception) -> Exception | str:
        return exc


class _BoundedConnection(ClientConnection):
    inbound_frames = 0

    def process_event(self, event: Event) -> None:
        if isinstance(event, Frame):
            self.inbound_frames = min(self.inbound_frames + 1, MAX_PHASE30_INBOUND_FRAMES + 1)
            if self.inbound_frames > MAX_PHASE30_INBOUND_FRAMES:
                with self.protocol_mutex:
                    self.protocol.fail(1008, "Inbound frame limit reached")
                    self.send_data()
                self.close_socket()
                return
        super().process_event(event)


def validate_websocket_settings(settings: HttpClientSettings) -> None:
    if any(
        name.lower() == "origin" or name.lower().startswith("sec-websocket-")
        for name, _ in settings.custom_headers
    ):
        raise HttpConfigurationError(
            "Origin and WebSocket negotiation headers are unsupported for Subscription review."
        )


class WebSocketClient:
    def __init__(self, url: str, settings: HttpClientSettings) -> None:
        validate_websocket_settings(settings)
        self._url, self._settings = url, settings
        self._connection: ClientConnection | None = None

    def __enter__(self) -> Self:
        context = ssl.create_default_context()
        if not self._settings.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        # Dedicated non-propagating logger avoids library wire/debug logs containing secrets.
        logger = logging.Logger("gqlsleuth.private_websocket", level=logging.CRITICAL + 1)
        logger.propagate = False
        logger.addHandler(logging.NullHandler())
        try:
            # Enter once; never use reconnect's iterator. Its redirect hook rejects redirects.
            self._connection = _NoRedirect(
                self._url,
                ssl=context if self._url.startswith("wss:") else None,
                proxy=self._settings.proxy,
                proxy_ssl=context if (self._settings.proxy or "").startswith("https:") else None,
                additional_headers=self._settings.custom_headers,
                user_agent_header=DEFAULT_USER_AGENT,
                subprotocols=[Subprotocol(p.value) for p in SubscriptionProtocol],
                open_timeout=min(self._settings.timeout_seconds, 10.0),
                close_timeout=1.0,
                ping_interval=None,
                compression=None,
                max_size=min(MAX_PHASE30_FRAME_BYTES, self._settings.max_response_body_bytes),
                max_queue=1,
                logger=logger,
                create_connection=_BoundedConnection,
            ).__enter__()
            # Socket writes remain finite. Leave one second beyond the application wait cap
            # so a silent peer is classified by the ACK/event deadline, not a receive-thread race.
            self._connection.socket.settimeout(11.0)
        except InvalidStatus as error:
            raise WebSocketFailure(status=error.response.status_code) from None
        except InvalidHandshake:
            raise WebSocketFailure() from None
        except (OSError, TimeoutError, WebSocketException):
            raise WebSocketFailure(network=True) from None
        return self

    @property
    def protocol(self) -> str | None:
        return self._connection.subprotocol if self._connection else None

    @property
    def frame_count(self) -> int:
        return (
            self._connection.inbound_frames
            if isinstance(self._connection, _BoundedConnection)
            else 0
        )

    @property
    def close_code(self) -> int | None:
        return self._connection.close_code if self._connection else None

    def send(self, text: str) -> None:
        assert self._connection is not None
        try:
            self._connection.send(text)
        except ConnectionClosed as error:
            raise self._closed_failure(error) from None
        except (OSError, WebSocketException):
            raise WebSocketFailure(network=True) from None

    def receive(self, timeout: float) -> str | bytes:
        assert self._connection is not None
        try:
            return self._connection.recv(timeout=timeout)
        except TimeoutError:
            raise
        except ConnectionClosed as error:
            raise self._closed_failure(error) from None
        except (OSError, WebSocketException):
            raise WebSocketFailure(network=True) from None

    def _closed_failure(self, error: ConnectionClosed) -> WebSocketFailure:
        if self.frame_count > MAX_PHASE30_INBOUND_FRAMES:
            return WebSocketFailure(code=1008)
        if error.sent and error.sent.code in (1002, 1007, 1009):
            # Locally rejected malformed/oversized frames are protocol outcomes,
            # even when the peer doesn't complete the close handshake.
            return WebSocketFailure(code=error.sent.code)
        code = error.rcvd.code if error.rcvd else None
        return WebSocketFailure(code=code, network=code is None or code == 1006)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._connection:
            self._connection.close()
