"""Loopback IDOR fixture: uv run python tests/fixtures/phase25_target.py --smoke."""

import argparse
import json
import socket
from http.server import HTTPServer
from threading import Thread

try:
    from fixtures.phase22_target import Handler as BaseHandler
    from fixtures.phase22_target import response_for as base_response
except ModuleNotFoundError:
    from phase22_target import Handler as BaseHandler
    from phase22_target import response_for as base_response


def response_for(method, payload=None, *, scenario="open", authenticated=False):
    identifier = payload.get("variables", {}).get("id") if isinstance(payload, dict) else None
    if identifier is None:
        return base_response(method, payload)
    # Validate the same one-Query shape through the existing local fixture.
    base_response(method, payload)
    if scenario == "denied" or (identifier in {"122", "124"} and scenario == "protected"):
        return {"errors": [{"message": "Forbidden", "extensions": {"code": "FORBIDDEN"}}]}
    if scenario == "unusable" and identifier == "123":
        return {"data": {"order": None}}
    if identifier == "122":
        return {"errors": [{"message": "Forbidden", "extensions": {"code": "FORBIDDEN"}}]}
    returned = "125" if scenario == "mismatch" and identifier == "124" else identifier
    # Scenario depends on explicit fixture configuration, never on production context labels.
    return {"data": {"order": {"id": returned, "total": 42 if authenticated else 7}}}


class Handler(BaseHandler):
    scenario = "open"
    requests = []

    def respond(self, payload):
        self.requests.append((payload, dict(self.headers)))
        identifier = payload.get("variables", {}).get("id") if payload else None
        if (self.scenario == "network-baseline" and identifier == "123") or (
            self.scenario == "network-neighbor" and identifier == "122"
        ):
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        body = json.dumps(
            response_for(
                self.command,
                payload,
                scenario=self.scenario,
                authenticated=bool(self.headers.get("Authorization")),
            )
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def smoke(target):
    from gqlsleuth.application.idor import IdorSession
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.domain.models import ScanMode
    from gqlsleuth.domain.sequential_discovery import parse_discovery_seeds
    from gqlsleuth.infrastructure.http import HttpClientSettings

    for authenticated in (False, True):
        settings = HttpClientSettings(
            custom_headers=(("Authorization", "Bearer PHASE25_FAKE_TOKEN"),)
            if authenticated
            else ()
        )
        Handler.scenario = "open"
        safe = run_safe_execution_scan(target, mode=ScanMode.ACTIVE, http_settings=settings)
        for scenario, seed, enabled, confirmed, ids, findings in (
            ("open", "123", False, True, [], 0),
            ("open", "123", True, False, [], 0),
            ("open", "123", True, True, ["123", "122", "124"], 1 if authenticated else 2),
            ("denied", "123", True, True, ["123"], 0),
            ("protected", "123", True, True, ["123", "122", "124"], 0 if authenticated else 1),
            ("unusable", "123", True, True, ["123"], 0),
            ("mismatch", "123", True, True, ["123", "122", "124"], 0 if authenticated else 1),
            ("network-baseline", "123", True, True, ["123"], 0),
            (
                "network-neighbor",
                "123",
                True,
                True,
                ["123", "122", "124"],
                1 if authenticated else 2,
            ),
            ("open", "0", True, True, ["0", "1"], 1 if authenticated else 2),
        ):
            Handler.scenario = scenario
            Handler.requests.clear()
            session = IdorSession(
                safe,
                seeds=parse_discovery_seeds(["order:id=" + seed]),
                enabled=enabled,
                http_settings=settings,
                context_label="usuario" if authenticated else None,
            )
            assert not Handler.requests
            preview = session.preview
            result = session.execute(preview=preview, confirmed=confirmed)
            assert result.attempted_request_count == len(ids)
            assert len(result.findings) == findings
            assert [payload["variables"]["id"] for payload, _ in Handler.requests] == ids
            if ids:
                assert session.execute(preview=preview, confirmed=True) == result
                assert len(Handler.requests) == len(ids)
            print(
                f"PASS {'authenticated' if authenticated else 'anonymous'} {scenario}, "
                f"enabled={enabled}, confirmed={confirmed}: {len(ids)} requests, "
                f"IDs={ids}, findings={findings}"
            )


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
