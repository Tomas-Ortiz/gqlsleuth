"""Test-only controlled target. Run directly to serve locally, or use --smoke."""

import argparse
import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from graphql import OperationType, build_schema, graphql_sync, parse

BASE_SDL = """
type Query { profile(id: ID!): String account: String readAndBurn: String }
type Mutation { createPaste: String }
"""
SCHEMAS = {
    "empleado": build_schema(BASE_SDL),
    "soporte": build_schema(
        BASE_SDL.replace("account: String", "account: String internalUsers: String").replace(
            "createPaste: String", "createPaste: String updatePaste: String"
        )
    ),
}


def response_for(method, path, headers, payload=None):
    """Same fixture logic for MockTransport and the loopback-only manual server."""
    context = headers.get("x-test-context", "public")
    if path != "/graphql" or context == "closed":
        return 404, "Not available"
    if method == "GET":
        return 200, {"data": {"__typename": "Query"}}
    query = payload.get("query", "")
    operation = parse(query).definitions[0]
    if operation.operation is not OperationType.QUERY:
        raise AssertionError("The Phase 15 fixture must never receive a Mutation.")
    if "__schema" in query:
        if context not in SCHEMAS:
            return 403, "Introspection not available"
        return 200, graphql_sync(SCHEMAS[context], query).formatted
    field = operation.selection_set.selections[0].name.value
    if field == "readAndBurn":
        raise AssertionError("The existing SAFE skip must remain enforced.")
    if field == "profile" and context == "empleado":
        return 403, "Request denied"
    if field == "account" and context == "empleado":
        return 200, {"errors": [{"message": "Application input was not accepted"}]}
    return 200, {"data": {field: None}}


class LocalTarget(BaseHTTPRequestHandler):
    requests_seen = 0
    mutations_seen = 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        type(self).requests_seen += 1
        payload = (
            json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            if self.command == "POST"
            else None
        )
        if payload and payload.get("query", "").lstrip().startswith("mutation"):
            type(self).mutations_seen += 1
        status, body = response_for(
            self.command,
            self.path,
            {key.lower(): value for key, value in self.headers.items()},
            payload,
        )
        content = json.dumps(body).encode() if isinstance(body, dict) else body.encode()
        self.send_response(status)
        self.send_header(
            "Content-Type", "application/json" if isinstance(body, dict) else "text/plain"
        )
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("reports/phase15-smoke"))
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 0 if args.smoke else args.port), LocalTarget)
    target = f"http://127.0.0.1:{server.server_port}/graphql"
    if args.smoke:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "gqlsleuth",
                    "scan",
                    target,
                    "--auth-context",
                    "public",
                    "--auth-context",
                    "empleado=X-Test-Context: empleado",
                    "--auth-context",
                    "soporte=X-Test-Context: soporte",
                    "-f",
                    "json,markdown,html",
                    "-o",
                    str(args.output),
                    "-v",
                ],
                check=True,
            )
            assert LocalTarget.mutations_seen == 0
            print(f"Local smoke: {LocalTarget.requests_seen} target requests; zero Mutations.")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    else:
        print(f"Test-only Phase 15 target: {target}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
