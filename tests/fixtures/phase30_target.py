"""Mock HTTP schema + real loopback WebSocket smoke; no external target or credentials."""

import argparse
import json
from threading import Thread
from unittest.mock import patch

import httpx
from graphql import build_schema, introspection_from_schema
from websockets.exceptions import ConnectionClosed
from websockets.sync.server import serve

from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY

SDL = """
type Query { health: String }
type Subscription {
  notificationCreated: Notification
  messageAdded(conversationId: ID!): Message
}
type Notification { id: ID! message: String }
type Message { id: ID! }
"""
SCHEMA = introspection_from_schema(build_schema(SDL))


def http_response(request):
    if request.method == "GET":
        return httpx.Response(200, json={"data": {"__typename": "Query"}})
    query = json.loads(request.content)["query"]
    if query == FULL_INTROSPECTION_QUERY:
        return httpx.Response(200, json={"data": SCHEMA})
    if query == MINIMAL_INTROSPECTION_QUERY:
        return httpx.Response(200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}})
    return httpx.Response(200, json={"data": {"health": "ok"}})


class LocalSubscriptionTarget:
    def __init__(self, scenario="event", protocol="graphql-transport-ws"):
        self.scenario, self.protocol = scenario, protocol
        self.connections, self.subscriptions = 0, 0
        self.messages = []
        self.headers = []

    def handshake(self, connection, request):
        self.connections += 1
        self.headers.append(dict(request.headers))
        if self.scenario in ("401", "403"):
            return connection.respond(int(self.scenario), "Denied")
        if self.scenario == "redirect":
            response = connection.respond(307, "Redirect")
            response.headers["Location"] = "ws://127.0.0.1:1/never-connect"
            return response
        return None

    def handler(self, connection):
        try:
            init = json.loads(connection.recv(timeout=1))
            self.messages.append(init)
            assert init["type"] == "connection_init"
            if self.scenario == "init-required":
                assert init["payload"] == {"Authorization": "Bearer PHASE30_INIT_SECRET"}
            if self.scenario in ("4401", "4403"):
                connection.close(int(self.scenario))
                return
            if self.scenario == "disconnect":
                connection.close_socket()
                return
            if self.scenario == "control-budget":
                for index in range(21):
                    connection.ping(str(index).encode())
                return
            connection.send('{"type":"connection_ack"}')
            message = json.loads(connection.recv(timeout=1))
            self.messages.append(message)
            assert message["id"] == "1" and message["type"] in ("subscribe", "start")
            self.subscriptions += 1
            modern = self.protocol == "graphql-transport-ws"
            if self.scenario == "complete":
                frame = {"type": "complete", "id": "1"}
            elif self.scenario == "denied":
                frame = {"type": "error", "id": "1", "payload": [{"message": "Forbidden"}]}
            elif self.scenario == "malformed":
                connection.send("not-json")
                frame = None
            elif self.scenario == "oversized":
                connection.send("x" * (1024 * 1024 + 1))
                frame = None
            elif self.scenario == "timeout":
                frame = None
            else:
                value = None if self.scenario == "null" else {"id": "fixture-event"}
                frame = {
                    "type": "next" if modern else "data",
                    "id": "1",
                    "payload": {"data": {"notificationCreated": value}},
                }
            if frame is not None:
                connection.send(json.dumps(frame))
            while True:
                cleanup = json.loads(connection.recv(timeout=1))
                self.messages.append(cleanup)
        except (ConnectionClosed, TimeoutError):
            pass

    def __enter__(self):
        self.server = serve(
            self.handler,
            "127.0.0.1",
            0,
            subprotocols=[self.protocol] if self.protocol else None,
            process_request=self.handshake,
            ping_interval=None,
            close_timeout=0.2,
        )
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.socket.getsockname()[1]
        self.target = f"http://127.0.0.1:{self.port}/graphql"
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.thread.join()


def smoke():
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.application.subscriptions import SubscriptionSecuritySession
    from gqlsleuth.cli import _run_subscription_stage
    from gqlsleuth.domain.models import ScanMode
    from gqlsleuth.infrastructure.http import HttpClientSettings

    for scenario, protocol, deny, outcome, findings in (
        ("event", "graphql-transport-ws", False, "event_returned", 0),
        ("event", "graphql-transport-ws", True, "event_returned", 1),
        ("event", "graphql-ws", True, "event_returned", 1),
        ("403", "graphql-transport-ws", True, "explicit_denial", 0),
        ("4403", "graphql-transport-ws", True, "explicit_denial", 0),
        ("denied", "graphql-transport-ws", True, "explicit_denial", 0),
        ("timeout", "graphql-transport-ws", True, "no_event_before_timeout", 0),
        ("complete", "graphql-transport-ws", True, "indeterminate", 0),
        ("null", "graphql-transport-ws", True, "indeterminate", 0),
        ("malformed", "graphql-transport-ws", True, "indeterminate", 0),
        ("event", None, True, "indeterminate", 0),
        ("disconnect", "graphql-transport-ws", True, "network_failure", 0),
        ("init-required", "graphql-transport-ws", True, "event_returned", 1),
    ):
        with LocalSubscriptionTarget(scenario, protocol) as target:
            with patch(
                "httpx._client.HTTPTransport",
                side_effect=lambda **kwargs: httpx.MockTransport(http_response),
            ):
                safe = run_safe_execution_scan(target.target, mode=ScanMode.ACTIVE)
            init = (
                {"Authorization": "Bearer PHASE30_INIT_SECRET"}
                if scenario == "init-required"
                else None
            )
            settings = HttpClientSettings(
                timeout_seconds=0.4,
                custom_headers=(("Authorization", "Bearer PHASE30_HEADER_SECRET"),) if init else (),
            )
            session = SubscriptionSecuritySession(
                safe, enabled=True, deny=deny, init_payload=init, http_settings=settings
            )
            index = next(
                i
                for i, c in enumerate(session.preview.candidates, 1)
                if c.field.name == "notificationCreated"
            )
            preview = session.select(index)
            result = session.execute(preview=preview, confirmed=True)
            assert len(result.attempts) == target.connections == 1
            attempt = result.attempts[0]
            assert attempt.outcome.value == outcome, (scenario, attempt)
            assert len(result.findings) == findings
            assert target.subscriptions == int(attempt.subscription_sent)
            assert attempt.application_event_count <= 1
            assert session.execute(preview=preview, confirmed=True) == result
            print(
                f"{scenario}/{protocol}: connections=1 subscriptions={target.subscriptions} "
                f"events={attempt.application_event_count} outcome={outcome} findings={findings}"
            )
            assert "PHASE30_INIT_SECRET" not in str(result)
    with LocalSubscriptionTarget() as target:
        with patch(
            "httpx._client.HTTPTransport",
            side_effect=lambda **kwargs: httpx.MockTransport(http_response),
        ):
            safe = run_safe_execution_scan(target.target, mode=ScanMode.ACTIVE)
        disabled = SubscriptionSecuritySession(safe)
        assert not disabled.execute(preview=disabled.preview, confirmed=True).attempts
        declined = SubscriptionSecuritySession(safe, enabled=True)
        assert not declined.execute(preview=declined.select(1), confirmed=False).attempts
        with patch("gqlsleuth.cli._interactive_stdin", return_value=False):
            assert not _run_subscription_stage(
                safe,
                deny=False,
                overrides=None,
                init_payload=None,
                ws_url=None,
                http_settings=HttpClientSettings(),
            ).attempts
        assert target.connections == 0
        print("disabled=0 declined=0 non-interactive=0 connections")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true", required=True)
    parser.parse_args()
    smoke()
