"""Loopback federation fixture: uv run python tests/fixtures/phase29_target.py --smoke."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from graphql import build_schema, introspection_from_schema

from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY

SDL = """
scalar _Any
scalar Custom
enum Kind { A B }
type _Service { sdl: String }
union _Entity = User | Product
type User {
  id: ID! username: String age: Int enabled: Boolean kind: Kind
  floatKey: Float custom: Custom nested: Product many: [String] argument(x: Int): String
}
type Product { upc: String! name: String }
type Query {
  health: Boolean
  _service: _Service
  _entities(representations: [_Any!]!): [_Entity]!
}
"""
SCHEMA = introspection_from_schema(build_schema(SDL))


def response_for(method, body, scenario="returned"):
    if method == "GET":
        return 200, {"data": {"__typename": "Query"}}
    payload = json.loads(body)
    query = payload["query"]
    if query == FULL_INTROSPECTION_QUERY:
        return 200, {"data": SCHEMA}
    if query == MINIMAL_INTROSPECTION_QUERY:
        return 200, {"data": {"__schema": {"queryType": {"name": "Query"}}}}
    if "sdl" not in query and "$representations" not in query:
        return 200, {"data": {"health": True}}
    root = "_service" if "sdl" in query else "_entities"
    if scenario == "denied":
        return 403, {"errors": [{"message": "Forbidden"}]}
    if scenario == "error":
        return 200, {"errors": [{"message": "Business input rejected"}]}
    if scenario == "null":
        return 200, {"data": {root: None}}
    if root == "_service":
        return 200, {"data": {root: {"sdl": "type Query { health: Boolean }"}}}
    representations = payload.get("variables", {}).get("representations")
    if (
        not isinstance(representations, list)
        or not representations
        or not isinstance(representations[0], dict)
    ):
        # Ordinary Phase 8 _Any placeholders are not controlled entity representations.
        return 200, {"data": {root: None}}
    entity = dict(payload["variables"]["representations"][0])
    if scenario == "wrong-key":
        entity["id"] = "different"
    if scenario == "wrong-type":
        entity["__typename"] = "Product"
    return 200, {"data": {root: [entity]}}


class Handler(BaseHTTPRequestHandler):
    scenario = "returned"
    requests = []
    recording = False

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond(b"")

    def do_POST(self):
        self.respond(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def respond(self, body):
        if self.recording:
            self.requests.append(json.loads(body))
            assert self.headers["Authorization"] == "Bearer PHASE29_FAKE_TOKEN"
            if self.scenario == "first-network" and len(self.requests) == 1:
                self.close_connection = True
                return
        status, result = response_for(self.command, body, self.scenario)
        data = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def smoke(target):
    from unittest.mock import patch

    from gqlsleuth.application.federation import FederationSecuritySession
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.cli import _run_federation_stage
    from gqlsleuth.domain.federation import FederationOutcome, FederationProbe
    from gqlsleuth.domain.models import ScanMode
    from gqlsleuth.infrastructure.http import HttpClientSettings

    settings = HttpClientSettings(custom_headers=(("Authorization", "Bearer PHASE29_FAKE_TOKEN"),))
    safe = run_safe_execution_scan(target, mode=ScanMode.ACTIVE, http_settings=settings)
    case = {"__typename": "User", "id": "123"}
    service, entity = FederationProbe.SERVICE, FederationProbe.ENTITY
    Handler.recording = True
    for scenario, probes, deny, enabled, confirmed, count, findings in (
        ("returned", (), False, False, True, 0, 0),
        ("returned", (service, entity), True, True, False, 0, 0),
        ("returned", (service,), False, True, True, 1, 0),
        ("returned", (service,), True, True, True, 1, 1),
        ("denied", (service,), True, True, True, 1, 0),
        ("returned", (entity,), False, True, True, 1, 1),
        ("denied", (entity,), False, True, True, 1, 0),
        ("wrong-key", (entity,), False, True, True, 1, 0),
        ("wrong-type", (entity,), False, True, True, 1, 0),
        ("null", (entity,), False, True, True, 1, 0),
        ("returned", (service, entity), True, True, True, 2, 2),
        ("first-network", (service, entity), True, True, True, 2, 1),
    ):
        Handler.scenario = scenario
        Handler.requests.clear()
        session = FederationSecuritySession(
            safe, enabled=enabled, entity_case=case, deny_sdl=deny, http_settings=settings
        )
        preview = session.preview
        if enabled:
            preview = session.select(preview.candidates[0].endpoint, probes)
        result = session.execute(preview=preview, confirmed=confirmed)
        assert len(Handler.requests) == len(result.attempts) == count, result.limitations
        assert len(result.findings) == findings
        assert session.execute(preview=preview, confirmed=True) == result
        if scenario == "first-network":
            assert result.attempts[0].outcome is FederationOutcome.NETWORK_FAILURE
        print(
            f"{scenario}; enabled={enabled}; confirmed={confirmed}; "
            f"probes={probes}: +{count}, findings={findings}"
        )
    Handler.requests.clear()
    with patch("gqlsleuth.cli._interactive_stdin", return_value=False):
        result = _run_federation_stage(
            safe, entity_case=case, deny_sdl=True, http_settings=settings
        )
    assert not Handler.requests and not result.attempts
    print("non-interactive: +0")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    target = f"http://127.0.0.1:{server.server_port}/graphql"
    if args.smoke:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            smoke(target)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
    else:
        print(target)
        try:
            server.serve_forever()
        finally:
            server.server_close()
