"""Controlled loopback repeats: uv run python tests/fixtures/phase27_target.py --smoke."""

import argparse
import json
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from graphql import build_schema, introspection_from_schema, parse

from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY

SDL = """
type Query { search(term: String!): [Result!]! }
type Result { id: ID! }
type Mutation {
  login(username: String!, password: String!): String
  requestPasswordReset(email: String!): Boolean
  deleteUser(id: ID!): Boolean
}
"""
INTROSPECTION = introspection_from_schema(build_schema(SDL))


def response_for(method, payload, *, scenario="none", attempt=0):
    if method == "GET":
        return 200, {"data": {"__typename": "Query"}}
    query = payload.get("query", "")
    if query == FULL_INTROSPECTION_QUERY:
        return 200, {"data": INTROSPECTION}
    if query == MINIMAL_INTROSPECTION_QUERY:
        return 200, {"data": {"__schema": {"queryType": {"name": "Query"}}}}
    operation = parse(query).definitions[0]
    root = operation.selection_set.selections[0].name.value
    assert "operationName" not in payload and root != "deleteUser"
    if scenario == "http429" and attempt == 3:
        return 429, {"message": "Too many requests"}
    code = {
        "rate": (3, "RATE_LIMITED"),
        "lockout": (3, "ACCOUNT_LOCKED"),
        "challenge": (2, "CAPTCHA_REQUIRED"),
    }.get(scenario)
    if code and attempt == code[0]:
        return 200, {
            "errors": [{"message": "Explicit fixture control", "extensions": {"code": code[1]}}]
        }
    if scenario == "server-error" and attempt == 2:
        return 500, {"error": "Fixture failure"}
    if root == "login":
        return 200, {"errors": [{"message": "Invalid credentials"}]}
    return 200, {"data": {root: [{"id": "1"}] if root == "search" else True}}


class Handler(BaseHTTPRequestHandler):
    scenario = "none"
    probing = False
    requests = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond({})

    def do_POST(self):
        self.respond(json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0")))))

    def respond(self, payload):
        self.requests.append(payload)
        attempt = len(self.requests) if self.probing else 0
        if self.scenario == "network" and attempt == 2:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        status, document = response_for(
            self.command, payload, scenario=self.scenario, attempt=attempt
        )
        body = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if status == 429:
            self.send_header("Retry-After", "60")
        self.end_headers()
        self.wfile.write(body)


def smoke(target):
    from unittest.mock import patch

    from gqlsleuth.application.abuse_controls import AbuseControlSession, prepare_abuse_controls
    from gqlsleuth.application.active_execution import (
        execute_selected_mutations,
        prepare_active_mutations,
    )
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.cli import _run_abuse_control_stage
    from gqlsleuth.domain.models import ScanMode
    from gqlsleuth.infrastructure.http import HttpClientSettings

    settings = HttpClientSettings(custom_headers=(("X-Fixture", "PHASE27_FAKE_HEADER"),))
    safe = run_safe_execution_scan(target, mode=ScanMode.ACTIVE, http_settings=settings)
    preview = prepare_active_mutations(safe)
    login_index = next(
        i
        for i, p in enumerate(preview.candidates, 1)
        if p.generated_mutation.operation_name == "login"
    )
    active = execute_selected_mutations(
        preview, selected_indices=(login_index,), confirmed=True, http_settings=settings
    )
    plan = prepare_abuse_controls(active, enabled=True)
    assert all(c.operation.name != "deleteUser" for c in plan.candidates)
    Handler.probing = True
    for kind, scenario, enabled, consent, count, policy in (
        ("query", "http429", True, True, 3, "satisfied"),
        ("query", "none", True, True, 5, "violated"),
        ("mutation", "rate", True, True, 3, "satisfied"),
        ("mutation", "none", True, True, 3, "violated"),
        ("mutation", "lockout", True, True, 3, "satisfied"),
        ("mutation", "challenge", True, True, 2, "satisfied"),
        ("query", "server-error", True, True, 2, "unresolved"),
        ("query", "network", True, True, 2, "unresolved"),
        ("query", "none", True, False, 0, "unresolved"),
        ("query", "none", False, True, 0, "unresolved"),
    ):
        Handler.requests.clear()
        Handler.scenario = scenario
        index = next(c.index for c in plan.candidates if c.operation.kind.value == kind)
        session = AbuseControlSession(
            active, http_settings=settings, enabled=enabled, selected_index=index
        )
        assert not Handler.requests
        result = session.execute(preview=session.preview, confirmed=consent)
        assert result.attempted_request_count == len(Handler.requests) == count
        assert result.policy_result.value == policy
        assert bool(result.findings) is (policy == "violated")
        assert session.execute(preview=session.preview, confirmed=True) == result
        assert len(Handler.requests) == count
        print(
            f"PASS {kind} {scenario}, enabled={enabled}, confirmed={consent}: "
            f"+{count} requests; {policy}"
        )
    Handler.requests.clear()
    with patch("gqlsleuth.cli._interactive_stdin", return_value=False):
        assert _run_abuse_control_stage(active, http_settings=settings).attempted_request_count == 0
    assert not Handler.requests
    print("PASS non-interactive: +0 requests; destructive Mutation ineligible")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    target = f"http://127.0.0.1:{server.server_port}/graphql"
    print("Loopback fixture:", target, flush=True)
    if not args.smoke:
        server.serve_forever()
        return
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        smoke(target)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
