"""Loopback-only depth target. Run: uv run python tests/fixtures/phase18_target.py --smoke."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from unittest.mock import patch

from graphql import OperationType, build_schema, graphql_sync, parse

SDL = """
type Query { album(id: ID!): Album }
type Album { id: ID! user: User }
type User { id: ID! albums(limit: Int): [Album] }
type Mutation { createAlbum(name: String!): Album }
"""
SCHEMA = build_schema(SDL)
SCHEMA.query_type.fields["album"].resolve = lambda source, info, **kwargs: {"id": "1"}
SCHEMA.get_type("Album").fields["user"].resolve = lambda source, info: {"id": "2"}
SCHEMA.get_type("User").fields["albums"].resolve = lambda source, info, **kwargs: [{"id": "1"}]


def is_depth_probe(payload):
    if not isinstance(payload, dict):
        return False
    document = parse(payload["query"])
    for definition in document.definitions:
        if not hasattr(definition, "operation"):
            continue
        for field in definition.selection_set.selections:
            if field.name.value != "album" or field.alias:
                continue
            pending = [(field, 1)]
            while pending:
                node, depth = pending.pop()
                if depth > 2:
                    return True
                if node.selection_set:
                    pending.extend((child, depth + 1) for child in node.selection_set.selections)
    return False


def response_for(method, path, payload=None):
    if method == "GET":
        return 200, {"data": {"__typename": "Query"}}
    if isinstance(payload, list):
        return 200, [response_for("POST", path, item)[1] for item in payload]
    document = parse(payload["query"])
    operations = [item for item in document.definitions if hasattr(item, "operation")]
    assert all(item.operation is OperationType.QUERY for item in operations), "No fixture Mutations"
    if is_depth_probe(payload):
        if path == "/rejected":
            return 400, {"errors": [{"message": "Maximum query depth exceeded"}]}
        if path == "/indeterminate":
            return 200, {"errors": [{"message": "Object is unavailable"}]}
    return 200, graphql_sync(
        SCHEMA, payload["query"], variable_values=payload.get("variables")
    ).formatted


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
        from typer.testing import CliRunner

        from gqlsleuth import cli

        for scenario, selected in (
            ("accepted", True),
            ("rejected", True),
            ("indeterminate", True),
            ("accepted", False),
        ):
            Handler.requests.clear()
            with patch.object(cli, "_interactive_stdin", return_value=True):
                run = CliRunner().invoke(
                    cli.app,
                    [
                        "scan",
                        f"http://127.0.0.1:{server.server_port}/{scenario}",
                        "--mode",
                        "active",
                        "-v",
                    ],
                    input="\n1\ny\n\n" if selected else "\n\n\n",
                )
            assert run.exit_code == 0, (run.exception, run.output)
            probes = [payload for _, _, payload in Handler.requests if is_depth_probe(payload)]
            assert len(probes) == int(selected), run.output
            assert not any(
                isinstance(payload, list)
                or isinstance(payload, dict)
                and (
                    payload.get("query", "").startswith("mutation")
                    or "gqlsleuthAlias" in payload.get("query", "")
                )
                for _, _, payload in Handler.requests
            )
            if selected:
                assert f"query album: {scenario.upper()}" in run.output, run.output
            print(
                f"{scenario}: {len(probes)} depth requests; "
                "zero Multiplicity requests; zero Mutations."
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
