"""Loopback fixture: uv run python tests/fixtures/phase22_target.py --smoke."""

import argparse
import json
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from unittest.mock import patch

from graphql import GraphQLError, OperationType, build_schema, graphql_sync, parse

SDL = """
type Query { order(id: ID!): Order }
type Order { id: ID! total: Float }
type Mutation { updateOrder(id: ID!): Order }
"""
SCHEMA = build_schema(SDL)


def order(source, info, id):
    if id in {"122", "200"}:
        return None
    if id in {"499", "501"}:
        raise GraphQLError("Forbidden", extensions={"code": "FORBIDDEN"})
    return {"id": id, "total": 42.0}


SCHEMA.query_type.fields["order"].resolve = order


def response_for(method, payload=None):
    if method == "GET":
        return {"data": {"__typename": "Query"}}
    assert isinstance(payload, dict), "No batching"
    document = parse(payload["query"])
    operations = [item for item in document.definitions if hasattr(item, "operation")]
    assert len(operations) == 1
    operation = operations[0]
    assert operation.operation is OperationType.QUERY
    assert len(operation.selection_set.selections) == 1
    assert not operation.selection_set.selections[0].alias
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
    import httpx

    from gqlsleuth.application import sequential_discovery as application
    from gqlsleuth.application.active_execution import (
        execute_selected_mutations,
        prepare_active_mutations,
    )
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.domain.models import ScanMode
    from gqlsleuth.domain.sequential_discovery import parse_discovery_seeds
    from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
    from gqlsleuth.reporting.builder import build_report
    from gqlsleuth.reporting.models import ReportFormat
    from gqlsleuth.reporting.renderers import render_report

    settings = HttpClientSettings(custom_headers=(("Authorization", "PHASE22_FAKE_TOKEN"),))
    safe = run_safe_execution_scan(target, mode=ScanMode.ACTIVE, http_settings=settings)
    for seed, confirmed, expected, candidates in (
        ("123", True, ["123", "122", "124"], 1),
        ("200", True, ["200"], 0),
        ("500", True, ["500", "499", "501"], 0),
        ("0", True, ["0", "1"], 1),
        ("123", False, [], 0),
    ):
        Handler.requests.clear()
        seeds = parse_discovery_seeds(["order:id=" + seed])
        preview = application.prepare_sequential_discovery(
            safe, seeds=seeds, enabled=True, http_settings=settings
        )
        assert not Handler.requests
        result = application.execute_sequential_discovery(
            safe,
            seeds=seeds,
            enabled=True,
            confirmed=confirmed,
            preview=preview,
            http_settings=settings,
        )
        ids = [payload["variables"]["id"] for payload, _ in Handler.requests]
        assert ids == expected
        assert result.attempted_request_count == len(expected)
        assert len(result.candidates) == candidates
        assert all(
            headers["Authorization"] == "PHASE22_FAKE_TOKEN" for _, headers in Handler.requests
        )
        active = replace(
            execute_selected_mutations(prepare_active_mutations(safe)),
            sequential_object_discovery=result,
        )
        report = build_report(active)
        for format in ReportFormat:
            rendered = render_report(report, format)
            assert "PHASE22_FAKE_TOKEN" not in rendered
            if format is not ReportFormat.JSON:
                assert rendered.count("Safety Notice") == 1
                assert rendered.index("Bounded Sequential Object Discovery") < rendered.index(
                    "Safety Notice"
                )
        assert [payload["variables"]["id"] for payload, _ in Handler.requests] == expected
        print(f"PASS seed={seed}, confirmed={confirmed}: {len(ids)} Phase 22 requests, IDs={ids}")
    attempts = []

    def failure(request):
        attempts.append(json.loads(request.content)["variables"]["id"])
        raise httpx.ConnectError("fake transport failure", request=request)

    with patch.object(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(failure)),
    ):
        result = application.execute_sequential_discovery(
            safe,
            seeds=parse_discovery_seeds(["order:id=123"]),
            enabled=True,
            confirmed=True,
        )
    assert attempts == ["123"] and result.attempted_request_count == 1 and not result.candidates
    print("PASS transport failure: 1 attempted request, IDs=['123']; zero neighbors")


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
