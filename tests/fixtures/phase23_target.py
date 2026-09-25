"""Test-only loopback Mutation fixture: uv run python tests/fixtures/phase23_target.py --smoke."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from graphql import GraphQLError, build_schema, graphql_sync

SDL = """
type Query { order(id: ID!): Order }
type Mutation {
  updateOrder(id: ID!, input: UpdateOrderInput!): Order
  deleteOrder(id: ID!): Order
}
input UpdateOrderInput { name: String! profile: ProfileInput! }
input ProfileInput { email: String! }
type Order { id: ID! name: String }
"""
SCHEMA = build_schema(SDL)


def update_order(source, info, id, input):
    if id == "456":
        raise GraphQLError("Forbidden", extensions={"code": "FORBIDDEN"})
    if id == "business":
        raise GraphQLError("Business input rejected", extensions={"code": "BAD_USER_INPUT"})
    return {"id": "124" if id == "mismatch" else id, "name": input["name"]}


SCHEMA.mutation_type.fields["updateOrder"].resolve = update_order
SCHEMA.query_type.fields["order"].resolve = lambda source, info, id: {"id": id}


def response_for(method, payload=None):
    if method == "GET":
        return {"data": {"__typename": "Query"}}
    assert isinstance(payload, dict), "No batching"
    assert "operationName" not in payload
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
    from gqlsleuth.application import mutation_authorization as application
    from gqlsleuth.application.active_execution import (
        execute_selected_mutations,
        prepare_active_mutations,
    )
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.domain.models import ScanMode
    from gqlsleuth.domain.mutation_authorization import parse_mutation_cases
    from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
    from gqlsleuth.presentation.console import CONSOLE_THEME
    from gqlsleuth.presentation.mutation_authorization import render_mutation_authorization
    from gqlsleuth.reporting.builder import build_report
    from gqlsleuth.reporting.models import ReportFormat
    from gqlsleuth.reporting.renderers import render_report

    secret = "PHASE23_FAKE_HEADER_SECRET"
    settings = HttpClientSettings(custom_headers=(("Authorization", secret),))
    safe = run_safe_execution_scan(target, mode=ScanMode.ACTIVE, http_settings=settings)
    active = execute_selected_mutations(prepare_active_mutations(safe))
    for case, confirmed, outcome, policy, count in (
        ("updateOrder:id=123", True, "target_mutation_returned", "violated", 1),
        ("updateOrder:id=456", True, "explicit_denial", "satisfied", 1),
        ("updateOrder:id=business", True, "indeterminate", "unresolved", 1),
        ("updateOrder:id=mismatch", True, "indeterminate", "unresolved", 1),
        ("updateOrder:id=123", False, None, "unresolved", 0),
        ("deleteOrder:id=123", True, None, "unresolved", 0),
    ):
        Handler.requests.clear()
        session = application.MutationAuthorizationSession(
            safe, cases=parse_mutation_cases([case]), enabled=True, http_settings=settings
        )
        preview = session.preview
        assert not Handler.requests
        result = session.execute(preview=preview, confirmed=confirmed)
        assert len(Handler.requests) == result.attempted_request_count == count
        assert (result.execution.outcome.value if result.execution else None) == outcome
        assert result.evaluation.status.value == policy
        assert all(headers["Authorization"] == secret for _, headers in Handler.requests)
        if count:
            assert session.execute(preview=preview, confirmed=True) == result
            assert len(Handler.requests) == 1
            assert Handler.requests[0][0] == {
                "query": preview.probe.query,
                "variables": preview.probe.variables,
            }
        output = io.StringIO()
        console = Console(file=output, width=100, theme=CONSOLE_THEME)
        render_mutation_authorization(console, preview, preview=True)
        render_mutation_authorization(console, result)
        assert secret not in output.getvalue() and secret not in repr(result)
        composed = replace(active, mutation_authorization=result)
        assert build_ai_context(composed).operations == build_ai_context(active).operations
        report = build_report(composed)
        for format in ReportFormat:
            rendered = render_report(report, format)
            assert secret not in rendered
            if format is not ReportFormat.JSON:
                assert rendered.count("Safety Notice") == 1
                assert rendered.index("Mutation Authorization Validation") < rendered.index(
                    "Safety Notice"
                )
        assert len(Handler.requests) == count
        print(
            f"PASS {case}, consent={confirmed}: {policy.upper()}, "
            f"{count} Mutation authorization requests"
        )
    attempts = []

    def failure(request):
        attempts.append(request)
        raise httpx.ConnectError("fake transport failure " + secret, request=request)

    with patch.object(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(failure)),
    ):
        session = application.MutationAuthorizationSession(
            safe,
            cases=parse_mutation_cases(["updateOrder:id=123"]),
            enabled=True,
            http_settings=settings,
        )
        result = session.execute(preview=session.preview, confirmed=True)
        session.execute(preview=session.preview, confirmed=True)
    assert len(attempts) == result.attempted_request_count == 1
    assert result.execution.outcome.value == "network_failure"
    assert result.evaluation.status.value == "unresolved"
    assert secret not in repr(result)
    print("PASS network failure: UNRESOLVED, 1 attempt, no retry")
    print("PASS fake header isolation, complete preview, reports, AI exclusion; no public target")


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
