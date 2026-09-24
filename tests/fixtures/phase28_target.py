"""Loopback-only multipart fixture: uv run python tests/fixtures/phase28_target.py --smoke."""

import argparse
import base64
import json
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

from graphql import build_schema, introspection_from_schema

from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
)
SDL = """
scalar Upload
input AvatarInput { file: Upload!, email: String!, description: String }
type UploadResult { id: ID!, filename: String! }
type Query { health: Boolean }
type Mutation { uploadAvatar(input: AvatarInput!): UploadResult }
"""
SCHEMA = introspection_from_schema(build_schema(SDL))


def multipart_parts(content_type, body):
    message = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    parts = {
        part.get_param("name", header="content-disposition"): part for part in message.iter_parts()
    }
    assert set(parts) == {"operations", "map", "0"}
    return {
        "operations": json.loads(parts["operations"].get_payload(decode=True)),
        "map": json.loads(parts["map"].get_payload(decode=True)),
        "filename": parts["0"].get_filename(),
        "mime": parts["0"].get_content_type(),
        "bytes": parts["0"].get_payload(decode=True),
    }


def response_for(method, content_type, body, scenario="accept"):
    if method == "GET":
        return 200, {"data": {"__typename": "Query"}}
    if not content_type.startswith("multipart/"):
        payload = json.loads(body)
        if payload["query"] == FULL_INTROSPECTION_QUERY:
            return 200, {"data": SCHEMA}
        if payload["query"] == MINIMAL_INTROSPECTION_QUERY:
            return 200, {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        assert payload["query"].startswith("query")
        return 200, {"data": {"health": True}}
    parts = multipart_parts(content_type, body)
    assert parts["map"] == {"0": ["variables.input.file"]}
    assert parts["operations"]["variables"] == {
        "input": {"file": None, "email": "test@example.com"}
    }
    assert "operationName" not in parts["operations"]
    baseline = (
        parts["bytes"] == PNG and parts["mime"] == "image/png" and parts["filename"] == "avatar.png"
    )
    if scenario == "baseline-reject" or (scenario == "reject" and not baseline):
        return 415, {"error": "Unsupported media type"}
    if scenario == "null" or (scenario == "ambiguous" and not baseline):
        return 200, {
            "data": {"uploadAvatar": None},
            "errors": [{"message": "Business validation failed"}],
        }
    return 200, {
        "data": {"uploadAvatar": {"id": "fixture-id", "url": "https://never-fetch.example/file"}}
    }


class Handler(BaseHTTPRequestHandler):
    scenario = "accept"
    uploads = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond(b"")

    def do_POST(self):
        self.respond(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def respond(self, body):
        mime = self.headers.get("Content-Type", "")
        if mime.startswith("multipart/"):
            self.uploads.append(multipart_parts(mime, body))
            assert self.headers["Authorization"] == "Bearer PHASE28_FAKE_TOKEN"
        status, result = response_for(self.command, mime, body, self.scenario)
        data = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def smoke(target):
    from unittest.mock import patch

    from gqlsleuth.application.file_upload import FileUploadSecuritySession
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.cli import _run_file_upload_stage
    from gqlsleuth.domain.exceptions import HttpConfigurationError
    from gqlsleuth.domain.file_upload import UPLOAD_VARIANTS, parse_upload_case
    from gqlsleuth.domain.models import ScanMode
    from gqlsleuth.infrastructure.http import HttpClientSettings

    settings = HttpClientSettings(custom_headers=(("Authorization", "Bearer PHASE28_FAKE_TOKEN"),))
    safe = run_safe_execution_scan(target, mode=ScanMode.ACTIVE, http_settings=settings)
    case = parse_upload_case(["uploadAvatar:input.file"])
    with TemporaryDirectory() as temporary:
        file = Path(temporary) / "avatar.png"
        file.write_bytes(PNG)
        for scenario, probes, confirmed, enabled, count, findings in (
            ("accept", (), True, True, 1, 0),
            ("baseline-reject", UPLOAD_VARIANTS, True, True, 1, 0),
            ("null", UPLOAD_VARIANTS, True, True, 1, 0),
            *(("accept", (probe,), True, True, 2, 1) for probe in UPLOAD_VARIANTS),
            ("reject", UPLOAD_VARIANTS, True, True, 4, 0),
            ("accept", UPLOAD_VARIANTS, True, True, 4, 3),
            ("ambiguous", UPLOAD_VARIANTS, True, True, 4, 0),
            ("accept", UPLOAD_VARIANTS, False, True, 0, 0),
            ("accept", UPLOAD_VARIANTS, True, False, 0, 0),
        ):
            Handler.scenario = scenario
            Handler.uploads.clear()
            session = FileUploadSecuritySession(
                safe, case=case, file_path=file, enabled=enabled, http_settings=settings
            )
            preview = session.select_variants(probes)
            result = session.execute(preview=preview, confirmed=confirmed)
            assert len(Handler.uploads) == result.attempted_request_count == count, (
                result.limitations
            )
            assert len(result.findings) == findings
            assert session.execute(preview=preview, confirmed=True) == result
            assert len(Handler.uploads) == count
            print(
                f"PASS {scenario}, {len(probes)} variants, confirmed={confirmed}, "
                f"enabled={enabled}: +{count}; {findings} findings"
            )
        Handler.uploads.clear()
        with patch("gqlsleuth.cli._interactive_stdin", return_value=False):
            _run_file_upload_stage(
                safe, case=case, file_path=file, content_type=None, http_settings=settings
            )
        assert not Handler.uploads
        session = FileUploadSecuritySession(
            safe, case=case, file_path=file, enabled=True, http_settings=settings
        )
        file.write_bytes(b"changed")
        assert session.execute(preview=session.preview, confirmed=True).attempted_request_count == 0
        assert not Handler.uploads
        print("PASS non-interactive and changed file: +0")
        file.write_bytes(b"x" * (1024 * 1024 + 1))
        try:
            FileUploadSecuritySession(safe, case=case, file_path=file, enabled=True)
        except HttpConfigurationError:
            pass
        else:
            raise AssertionError("Oversized file was not rejected locally")
        assert not Handler.uploads
        print("PASS oversized file: +0")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    target = f"http://127.0.0.1:{server.server_port}/graphql"
    print(target, flush=True)
    if args.smoke:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            smoke(target)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
    else:
        server.serve_forever()


if __name__ == "__main__":
    main()
