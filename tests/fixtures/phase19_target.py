"""Loopback fixture. Run: uv run python tests/fixtures/phase19_target.py --smoke."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

from graphql import GraphQLError, OperationType, build_schema, graphql_sync, parse

SDL = """
type Query { project(id: ID!): Project }
type Project { id: ID! owner: User members(limit: Int): [User] settings: Settings }
type User { id: ID! email: String }
type Settings { id: ID! secret: String }
type Mutation { createProject(name: String!): Project }
"""
SCHEMA = build_schema(SDL)
HIDDEN = build_schema(SDL.replace("email: String", "label: String"))


def is_nested(payload):
    if not isinstance(payload, dict):
        return False
    operation = parse(payload["query"]).definitions[0]
    field = operation.selection_set.selections[0]
    return field.name.value == "project" and any(
        item.selection_set for item in field.selection_set.selections
    )


def protected(source, info):
    if info.context == "beta":
        raise GraphQLError("Forbidden", extensions={"code": "FORBIDDEN"})
    return None if info.context == "gamma" else "PHASE19_RETURNED_BUSINESS_VALUE"


for schema in (SCHEMA, HIDDEN):
    schema.query_type.fields["project"].resolve = lambda source, info, **kwargs: {"id": "1"}
    schema.get_type("Project").fields["owner"].resolve = lambda source, info: {"id": "2"}
    schema.get_type("Project").fields["members"].resolve = lambda source, info, **kwargs: (
        [] if info.context == "gamma" else [{"id": "2"}]
    )
    schema.get_type("Project").fields["settings"].resolve = lambda source, info: {"id": "3"}
    schema.get_type("Settings").fields["secret"].resolve = protected
SCHEMA.get_type("User").fields["email"].resolve = protected


def response_for(method, path, headers, payload=None):
    if method == "GET":
        return 200, {"data": {"__typename": "Query"}}
    assert isinstance(payload, dict), "No batching"
    document = parse(payload["query"])
    for node in document.definitions:
        if hasattr(node, "operation"):
            assert node.operation is OperationType.QUERY, "No Mutations or Subscriptions"
            assert not any(field.alias for field in node.selection_set.selections), "No aliases"
    context = headers.get("x-test-context", "alpha")
    schema = HIDDEN if context == "hidden" else SCHEMA
    return 200, graphql_sync(
        schema, payload["query"], variable_values=payload.get("variables"), context_value=context
    ).formatted


class Handler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        self.respond(None)

    def do_POST(self):
        self.respond(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))

    def respond(self, payload):
        headers = {key.lower(): value for key, value in self.headers.items()}
        self.requests.append((headers.get("x-test-context"), payload))
        status, data = response_for(self.command, self.path, headers, payload)
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
    print("Local fixture:", target, flush=True)
    if not args.smoke:
        server.serve_forever()
        return
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        from typer.testing import CliRunner

        from gqlsleuth import cli

        options = [
            value
            for label in ("alpha", "beta", "gamma")
            for value in ("--auth-context", f"{label}=X-Test-Context: {label}")
        ]
        without = CliRunner().invoke(cli.app, ["scan", target, *options])
        assert without.exit_code == 0, without.exception
        baseline = list(Handler.requests)
        assert not any(is_nested(payload) for _, payload in baseline)
        Handler.requests.clear()
        with TemporaryDirectory(prefix="gqlsleuth-phase19-") as directory:
            run = CliRunner().invoke(
                cli.app,
                [
                    "scan",
                    target,
                    *options,
                    "--nested-auth-review",
                    "-f",
                    "json,markdown,html",
                    "-o",
                    directory,
                ],
            )
            assert run.exit_code == 0, (run.exception, run.output)
            probes = [
                (context, payload) for context, payload in Handler.requests if is_nested(payload)
            ]
            assert len(probes) == 9
            assert Handler.requests[: len(baseline)] == baseline
            for offset in range(0, 9, 3):
                assert [context for context, _ in probes[offset : offset + 3]] == [
                    "alpha",
                    "beta",
                    "gamma",
                ]
                assert probes[offset][1] == probes[offset + 1][1] == probes[offset + 2][1]
            report = json.loads(next(Path(directory).glob("*.json")).read_text())
            nested = report["nested_authorization_review"]
            assert len(nested["pairs"]) == 3
            assert {item["outcome"] for item in nested["executions"]} == {
                "returned",
                "explicit_denial",
                "indeterminate",
            }
            for extension in ("md", "html"):
                text = next(Path(directory).glob("*." + extension)).read_text(encoding="utf-8")
                assert text.count("Safety Notice") == 1
                assert "PHASE19_RETURNED_BUSINESS_VALUE" not in text
            print(
                "Opt-in: 3 paths, 9 identical-per-context requests, 3 review pairs; "
                "JSON/Markdown/HTML passed."
            )
            print(
                "Without flag: baseline sequence unchanged, zero nested requests. "
                "Zero Mutations or public targets."
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
