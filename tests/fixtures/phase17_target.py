"""Loopback-only manual target; the same handler also supports offline MockTransport tests.

Run: uv run python tests/fixtures/phase17_target.py --smoke
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from graphql import OperationType, build_schema, graphql_sync, parse

SDL = """
type Query { items(limit: Int, email: String!): [Item] }
type Item { id: ID! }
type Mutation { createItem(name: String!): Item }
"""
SCHEMA = build_schema(SDL)
SCHEMA.query_type.fields["items"].resolve = lambda source, info, **kwargs: [{"id": "1"}]


def response_for(method, path, payload=None):
    """Accepted, rejected and ambiguous shapes, with no real identities or credentials."""
    if method == "GET":
        return 200, {"data": {"__typename": "Query"}}
    if isinstance(payload, list):
        if path == "/rejected":
            return 400, {"errors": [{"message": "JSON-array batching is not supported"}]}
        if path == "/ambiguous":
            return 200, {"message": "Unexpected request"}
        return 200, [response_for("POST", path, item)[1] for item in payload]
    document = parse(payload["query"])
    operations = [item for item in document.definitions if hasattr(item, "operation")]
    assert all(item.operation is OperationType.QUERY for item in operations), (
        "Fixture forbids Mutations"
    )
    if any(
        getattr(field, "alias", None)
        for item in operations
        for field in item.selection_set.selections
    ):
        if path == "/rejected":
            return 400, {"errors": [{"message": "Aliases are not allowed"}]}
        if path == "/ambiguous":
            return 200, {"data": None}
    result = graphql_sync(SCHEMA, payload["query"], variable_values=payload.get("variables"))
    return 200, result.formatted


class Handler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        self.respond(None)

    def do_POST(self):
        self.respond(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))

    def respond(self, payload):
        self.requests.append((self.command, self.path, payload))
        status, data = response_for(self.command, self.path, payload)
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
    print(f"Local fixture: http://127.0.0.1:{server.server_port}/accepted", flush=True)
    if not args.smoke:
        server.serve_forever()
        return
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for path in ("accepted", "rejected", "ambiguous"):
            Handler.requests.clear()
            # A real stdin terminal is unnecessary: run the production interactive path
            # with deterministic tester input, and retain CLI assertions locally.
            from unittest.mock import patch

            from typer.testing import CliRunner

            from gqlsleuth import cli

            with patch.object(cli, "_interactive_stdin", return_value=True):
                run = CliRunner().invoke(
                    cli.app,
                    ["scan", f"http://127.0.0.1:{server.server_port}/{path}", "--mode", "active"],
                    input="1,2\ny\n\n",
                )
            assert run.exit_code == 0, run.exception
            probes = [
                payload
                for _, _, payload in Handler.requests
                if isinstance(payload, list)
                or isinstance(payload, dict)
                and "gqlsleuthAlias1" in payload.get("query", "")
            ]
            assert len(probes) == 2
            assert not any(
                isinstance(payload, dict) and payload.get("query", "").startswith("mutation")
                for _, _, payload in Handler.requests
            )
            expected = {
                "accepted": "ACCEPTED",
                "rejected": "REJECTED",
                "ambiguous": "INDETERMINATE",
            }[path]
            assert f"query items: {expected}" in run.output
            print(f"{path}: 2 probes; {expected}; zero Mutations.")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
