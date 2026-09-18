"""Loopback-only fake Bearer target: uv run python tests/fixtures/phase26_target.py --smoke."""

import argparse
import base64
import hashlib
import hmac
import json
import socket
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from graphql import build_schema, introspection_from_schema

from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY

SDL = "type Query { currentUser(id: ID!): User } type User { id: ID! username: String! }"
INTROSPECTION = introspection_from_schema(build_schema(SDL))
FAKE_KEY = b"PHASE26_FIXTURE_ONLY_KEY"
CLAIM_CANARY = "PHASE26_CLAIM_CANARY"


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def fake_token(claims=None, header=None):
    header = header if header is not None else {"alg": "HS256", "typ": "JWT", "kid": CLAIM_CANARY}
    claims = claims if claims is not None else {"sub": CLAIM_CANARY, "iss": CLAIM_CANARY}
    parts = [
        encode(json.dumps(value, separators=(",", ":")).encode()) for value in (header, claims)
    ]
    signature = encode(hmac.new(FAKE_KEY, ".".join(parts).encode(), hashlib.sha256).digest())
    return ".".join((*parts, "" if header.get("alg") == "none" else signature))


def response_for(method, payload, authorization, *, original, scenario="protected"):
    if method == "GET":
        return 200, {"data": {"__typename": "Query"}}
    query = payload.get("query", "")
    if query == FULL_INTROSPECTION_QUERY:
        return 200, {"data": INTROSPECTION}
    if query == MINIMAL_INTROSPECTION_QUERY:
        return 200, {"data": {"__schema": {"queryType": {"name": "Query"}}}}
    assert query.startswith("query") and "operationName" not in payload
    assert payload.get("variables") == {"id": "1"}
    if authorization == "Bearer " + original or scenario == "open":
        return 200, {"data": {"currentUser": {"id": "1"}}}
    if not authorization:
        if scenario == "ambiguous":
            return 200, {"data": {"currentUser": None}}
        return 403, {"errors": [{"message": "Forbidden"}]}
    token = authorization.removeprefix("Bearer ")
    parts = token.split(".")
    if scenario == "signature-accepted" and parts[:2] == original.split(".")[:2]:
        return 200, {"data": {"currentUser": {"id": "1"}}}
    if scenario == "none-accepted" and len(parts) == 3 and parts[2] == "":
        return 200, {"data": {"currentUser": {"id": "1"}}}
    return 401, {"errors": [{"message": "Unauthorized"}]}


class Handler(BaseHTTPRequestHandler):
    original = fake_token()
    scenario = "protected"
    requests = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond({})

    def do_POST(self):
        self.respond(json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0")))))

    def respond(self, payload):
        authorization = self.headers.get("Authorization", "")
        self.requests.append((payload, authorization))
        if self.scenario == "network-control" and not authorization and self.command == "POST":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        status, document = response_for(
            self.command, payload, authorization, original=self.original, scenario=self.scenario
        )
        body = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def smoke(target):
    from gqlsleuth.application.authentication import AuthenticationSecuritySession
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.domain.authentication import AuthenticationProbe as Probe
    from gqlsleuth.domain.models import ScanMode
    from gqlsleuth.infrastructure.http import HttpClientSettings

    now = datetime.now(UTC).timestamp()
    both = (Probe.JWT_SIGNATURE_TAMPERED, Probe.JWT_ALG_NONE)
    cases = (
        ("protected", fake_token(), (), True, 1, ()),
        ("open", fake_token(), both, True, 1, ("authentication_enforcement_failure",)),
        (
            "signature-accepted",
            fake_token(),
            both[:1],
            True,
            2,
            ("jwt_signature_validation_failure",),
        ),
        ("protected", fake_token(), both[:1], True, 2, ()),
        ("none-accepted", fake_token(), both[1:], True, 2, ("jwt_none_algorithm_accepted",)),
        ("protected", fake_token(), both[1:], True, 2, ()),
        ("protected", fake_token({"exp": now - 3600}), (), True, 1, ("expired_jwt_accepted",)),
        (
            "protected",
            fake_token({"nbf": now + 3600}),
            (),
            True,
            1,
            ("not_yet_valid_jwt_accepted",),
        ),
        ("protected", "PHASE26_OPAQUE_FAKE", (), True, 1, ()),
        ("network-control", fake_token(), both, True, 1, ()),
        ("protected", fake_token(), both, False, 0, ()),
        ("protected", fake_token(), both, True, 3, ()),
        (
            "protected",
            fake_token(header={"alg": "none"}),
            (),
            True,
            1,
            ("jwt_none_algorithm_accepted",),
        ),
    )
    for scenario, token, probes, confirmed, count, kinds in cases:
        Handler.original, Handler.scenario = token, "protected"
        settings = HttpClientSettings(custom_headers=(("Authorization", "Bearer " + token),))
        safe = run_safe_execution_scan(target, mode=ScanMode.ACTIVE, http_settings=settings)
        Handler.scenario = scenario
        Handler.requests.clear()
        session = AuthenticationSecuritySession(
            safe, http_settings=settings, enabled=True, selected_index=1, selected_probes=probes
        )
        assert not Handler.requests
        result = session.execute(preview=session.preview, confirmed=confirmed)
        assert len(Handler.requests) == result.attempted_request_count == count
        assert tuple(item.finding_type.value for item in result.findings) == kinds
        print(
            f"PASS {scenario}: confirmed={confirmed}; {count} additional requests; findings={kinds}"
        )
    Handler.requests.clear()
    disabled = AuthenticationSecuritySession(safe, http_settings=settings, enabled=False)
    assert not disabled.execute(preview=disabled.preview, confirmed=True).evidence
    assert not Handler.requests
    print("PASS disabled: 0 additional requests")
    # Exercise actual CLI non-interactive gate without any other ACTIVE stage.
    from unittest.mock import patch

    from gqlsleuth.cli import _run_authentication_stage

    Handler.requests.clear()
    with patch("gqlsleuth.cli._interactive_stdin", return_value=False):
        result = _run_authentication_stage(safe, http_settings=settings)
    assert result.attempted_request_count == 0 and not Handler.requests
    print("PASS non-interactive: 0 additional requests")


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
