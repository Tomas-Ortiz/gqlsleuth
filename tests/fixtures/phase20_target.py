"""Loopback-only object review fixture: uv run python tests/fixtures/phase20_target.py --smoke."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

from graphql import GraphQLError, OperationType, build_schema, graphql_sync, parse

SDL = """
type Query { order(id: ID!): Order }
type Order { id: ID! total: Float description: String owner: Person }
type Person { id: ID! email: String }
type Mutation { deleteOrder(id: ID!): Boolean }
"""
SCHEMA = build_schema(SDL)


def order(source, info, id):
    if id == "999":
        return None
    if id == "456" and info.context != "clienteB":
        raise GraphQLError("Forbidden", extensions={"code": "FORBIDDEN"})
    return {
        "id": "different" if id == "mismatch" else id,
        "total": 42.0 if info.context == "clienteA" else 7.0,
        "description": "PHASE20_BUSINESS_VALUE",
        "owner": {"id": "not-a-new-case", "email": "fixture@example.com"},
    }


SCHEMA.query_type.fields["order"].resolve = order


def response_for(method, headers, payload=None):
    if method == "GET":
        return 200, {"data": {"__typename": "Query"}}
    assert isinstance(payload, dict), "No batching"
    document = parse(payload["query"])
    operations = [item for item in document.definitions if hasattr(item, "operation")]
    assert len(operations) == 1
    operation = operations[0]
    assert operation.operation is OperationType.QUERY
    assert len(operation.selection_set.selections) == 1
    assert not operation.selection_set.selections[0].alias
    return 200, graphql_sync(
        SCHEMA,
        payload["query"],
        variable_values=payload.get("variables"),
        context_value=headers.get("x-test-context", "public"),
    ).formatted


class Handler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        self.respond(None)

    def do_POST(self):
        self.respond(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))

    def respond(self, payload):
        headers = {key.lower(): value for key, value in self.headers.items()}
        self.requests.append((headers.get("x-test-context", "public"), payload))
        status, data = response_for(self.command, headers, payload)
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


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
        from typer.testing import CliRunner

        from gqlsleuth.cli import app

        configurations = [
            ([], ["order:id=100", "order:id=456", "order:id=mismatch"], 3, 0),
            (["--auth-context", "foo"], ["order:id=100"], 1, 0),
            (
                [
                    "--auth-context",
                    "clienteA=X-Test-Context: clienteA",
                    "--auth-context",
                    "clienteB=X-Test-Context: clienteB",
                    "--auth-context",
                    "public",
                ],
                ["clienteA:order:id=123", "clienteB:order:id=456", "clienteA:order:id=999"],
                7,
                0,
            ),
            (
                [
                    "--auth-context",
                    "clienteA=X-Test-Context: clienteA",
                    "--auth-context",
                    "clienteB=X-Test-Context: clienteB",
                    "--auth-context",
                    "public",
                    "--nested-auth-review",
                ],
                ["clienteA:order:id=123"],
                3,
                3,
            ),
        ]
        for options, cases, expected, nested_count in configurations:
            Handler.requests.clear()
            with TemporaryDirectory(prefix="gqlsleuth-phase20-") as directory:
                run = CliRunner().invoke(
                    app,
                    [
                        "scan",
                        target,
                        *options,
                        "--object-auth-review",
                        *[part for case in cases for part in ("--object-auth-case", case)],
                        "-f",
                        "json,markdown,html",
                        "-o",
                        directory,
                    ],
                )
                assert run.exit_code == 0, (run.exception, run.output)
                report = json.loads(next(Path(directory).glob("*.json")).read_text())
                review = report["object_authorization_review"]
                assert review["attempted_request_count"] == expected, review
                supplied = {case.partition("=")[2] for case in cases}
                probes = [
                    (context, payload)
                    for context, payload in Handler.requests
                    if payload and payload.get("variables", {}).get("id") in supplied
                ]
                assert len(probes) == expected
                assert all(payload["variables"]["id"] in supplied for _, payload in probes)
                assert {
                    payload["variables"]["id"]
                    for _, payload in Handler.requests
                    if payload and "id" in payload.get("variables", {})
                } <= supplied | {"1"}
                if expected == 7:
                    assert [context for context, _ in probes] == [
                        "clienteA",
                        "clienteB",
                        "public",
                        "clienteB",
                        "clienteA",
                        "public",
                        "clienteA",
                    ]
                    assert probes[0][1] == probes[1][1] == probes[2][1]
                    assert len(review["candidates"]) == 2
                    assert review["executions"][-1]["attempted"] is False
                if expected == 3 and not options:
                    assert [item["outcome"] for item in review["executions"]] == [
                        "target_returned",
                        "explicit_denial",
                        "indeterminate",
                    ]
                    assert len(review["candidates"]) == 1
                nested = report.get("nested_authorization_review")
                assert (
                    sum(item["attempted"] for item in nested["executions"]) == nested_count
                    if nested
                    else nested_count == 0
                )
                for extension in ("md", "html"):
                    human = next(Path(directory).glob(f"*.{extension}")).read_text(encoding="utf-8")
                    assert human.count("Safety Notice") == 1
                    assert human.index("Controlled Object Authorization Validation") < human.index(
                        "Safety Notice"
                    )
                print(
                    f"PASS: cases={len(cases)}, Phase 20={expected}, "
                    f"Phase 19={nested_count}; exact IDs only."
                )
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
