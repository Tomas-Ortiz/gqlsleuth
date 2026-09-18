"""Loopback sensitive-field fixture: uv run python tests/fixtures/phase24_target.py --smoke."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from graphql import GraphQLError, build_schema, graphql_sync

SDL = """
type Query { profile: User }
enum UserRole { USER ADMIN }
input UpdateUserInput {
  displayName: String!
  isStaff: Boolean
  role: UserRole
  accessLevel: Int
  ownerId: ID
  tenantId: String
  permissions: [String]
  profile: ProfileInput
  roleDescription: String
}
input ProfileInput { isAdmin: Boolean }
type User {
  id: ID!
  displayName: String
  isStaff: Boolean
  role: UserRole
  accessLevel: Int
  ownerId: ID
  tenantId: String
  permissions: [String]
  roleDescription: String
}
type Mutation {
  updateUser(id: ID!, input: UpdateUserInput!): User
  updateProfile(input: UpdateUserInput!): User
  deleteUser(id: ID!, input: UpdateUserInput!): User
}
"""
SCHEMA = build_schema(SDL)


def update(source, info, input, id="current"):
    if id == "deny":
        raise GraphQLError("Forbidden", extensions={"code": "FORBIDDEN"})
    if id == "business":
        raise GraphQLError("Business rule", extensions={"code": "BAD_USER_INPUT"})
    result = {**input, "id": "different" if id == "wrong-id" else id}
    if id == "wrong-value":
        result["isStaff"] = False
    return result


for name in ("updateUser", "updateProfile"):
    SCHEMA.mutation_type.fields[name].resolve = update
SCHEMA.query_type.fields["profile"].resolve = lambda source, info: {"id": "current"}


def response_for(method, payload=None):
    if method == "GET":
        return {"data": {"__typename": "Query"}}
    assert isinstance(payload, dict) and "operationName" not in payload
    return graphql_sync(
        SCHEMA, payload["query"], variable_values=payload.get("variables")
    ).formatted


class Handler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        self.respond(None)

    def do_POST(self):
        self.respond(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))

    def respond(self, payload):
        self.requests.append((payload, dict(self.headers)))
        body = json.dumps(response_for(self.command, payload)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def smoke(target):
    import io
    from dataclasses import replace
    from unittest.mock import patch

    import httpx
    from rich.console import Console

    from gqlsleuth.ai.context import build_ai_context
    from gqlsleuth.application import sensitive_input as application
    from gqlsleuth.application.active_execution import (
        execute_selected_mutations,
        prepare_active_mutations,
    )
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.application.sensitive_input_review import review_sensitive_inputs
    from gqlsleuth.domain.models import ScanMode
    from gqlsleuth.domain.sensitive_input import parse_sensitive_case
    from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
    from gqlsleuth.presentation.console import CONSOLE_THEME
    from gqlsleuth.presentation.sensitive_input import render_sensitive_validation
    from gqlsleuth.reporting.builder import build_report
    from gqlsleuth.reporting.models import ReportFormat
    from gqlsleuth.reporting.renderers import render_report

    secret = "PHASE24_FAKE_HEADER_SECRET"
    settings = HttpClientSettings(custom_headers=(("X-API-Key", secret),))
    safe = run_safe_execution_scan(target, mode=ScanMode.ACTIVE, http_settings=settings)
    count = len(Handler.requests)
    assert (
        review_sensitive_inputs(safe.query_generation.operation_analysis)
        == safe.query_generation.sensitive_input_review
    )
    assert len(Handler.requests) == count
    print("PASS local discovery: 0 additional requests")
    active = execute_selected_mutations(prepare_active_mutations(safe))
    for case, target_id, confirmed, policy, outcome, count in (
        ("updateUser:input.isStaff=true", "123", True, "violated", "target_value_returned", 1),
        ("updateUser:input.isStaff=true", "deny", True, "satisfied", "explicit_denial", 1),
        ("updateUser:input.isStaff=true", "business", True, "unresolved", "indeterminate", 1),
        ("updateUser:input.isStaff=true", "wrong-value", True, "unresolved", "indeterminate", 1),
        ("updateUser:input.isStaff=true", "wrong-id", True, "unresolved", "indeterminate", 1),
        ("updateUser:input.role=ADMIN", "123", True, "violated", "target_value_returned", 1),
        ("updateProfile:input.isStaff=true", None, True, "violated", "target_value_returned", 1),
        ("updateUser:input.isStaff=true", "123", False, "unresolved", None, 0),
        ("deleteUser:input.isStaff=true", "123", True, "unresolved", None, 0),
    ):
        Handler.requests.clear()
        session = application.SensitiveInputSession(
            safe,
            case=parse_sensitive_case([case], f"id={target_id}" if target_id else None),
            enabled=True,
            http_settings=settings,
        )
        preview = session.preview
        assert not Handler.requests
        result = session.execute(preview=preview, confirmed=confirmed)
        assert result.attempted_request_count == len(Handler.requests) == count
        assert result.evaluation.status.value == policy
        assert (result.execution.outcome.value if result.execution else None) == outcome
        if count:
            assert session.execute(preview=preview, confirmed=True) == result
            assert Handler.requests[0][0] == {
                "query": preview.probe.query,
                "variables": preview.probe.variables,
            }
            assert Handler.requests[0][1]["X-API-Key"] == secret
        output = io.StringIO()
        console = Console(file=output, width=100, theme=CONSOLE_THEME)
        render_sensitive_validation(console, preview, preview=True)
        render_sensitive_validation(console, result)
        assert secret not in output.getvalue() and secret not in repr(result)
        composed = replace(active, sensitive_input_validation=result)
        assert build_ai_context(composed) == build_ai_context(active)
        for format in ReportFormat:
            rendered = render_report(build_report(composed), format)
            assert secret not in rendered
            if format is not ReportFormat.JSON:
                assert rendered.count("Safety Notice") == 1
                assert rendered.index("Sensitive Input Validation") < rendered.index(
                    "Safety Notice"
                )
        assert len(Handler.requests) == count
        print(
            f"PASS {case}, target={target_id}, consent={confirmed}: "
            f"{policy.upper()}, {count} requests"
        )
    attempts = []

    def fail(request):
        attempts.append(request)
        raise httpx.ConnectError(secret, request=request)

    with patch.object(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(fail)),
    ):
        session = application.SensitiveInputSession(
            safe,
            case=parse_sensitive_case(["updateUser:input.isStaff=true"], "id=123"),
            enabled=True,
            http_settings=settings,
        )
        result = session.execute(preview=session.preview, confirmed=True)
        session.execute(preview=session.preview, confirmed=True)
    assert len(attempts) == result.attempted_request_count == 1
    assert (
        result.execution.outcome.value == "network_failure"
        and result.evaluation.status.value == "unresolved"
    )
    assert secret not in repr(result)
    print("PASS network failure: UNRESOLVED, 1 attempt; no retry, read-after-write or rollback")


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
