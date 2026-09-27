"""Run a SAFE scan against a temporary fake loopback fixture, optionally writing HTML."""

import argparse
import runpy
import sys
from http.server import HTTPServer
from pathlib import Path
from socketserver import TCPServer
from threading import Thread


def guard_network(event: str, args: tuple[object, ...]) -> None:
    """Restrict this demonstration process, never the installed scanner, to IPv4 loopback."""
    if event in {"socket.connect", "socket.bind"}:
        address = args[1]
        if not isinstance(address, tuple) or address[0] != "127.0.0.1":
            raise RuntimeError("Local demo permits loopback networking only.")
    elif event == "socket.getaddrinfo":
        if args[0] != "127.0.0.1":
            raise RuntimeError("Local demo forbids external DNS lookups.")
    elif event in {"socket.gethostbyname", "socket.gethostbyaddr", "socket.sendto"}:
        raise RuntimeError("Local demo forbids external DNS/UDP activity.")


class LoopbackServer(HTTPServer):
    def server_bind(self) -> None:
        # HTTPServer normally reverse-resolves its name. This fixed demo needs no DNS.
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional directory for an HTML report")
    parser.add_argument("--verbose", action="store_true", help="Show technical scan details")
    args = parser.parse_args()
    sys.addaudithook(guard_network)

    # Reuse the existing small Query-only fixture; do not add another demo application.
    fixture_path = Path(__file__).resolve().parents[1] / "tests/fixtures/phase18_target.py"
    if not fixture_path.is_file():
        parser.error("Run this helper from a complete source checkout, including test fixtures.")
    fixture = runpy.run_path(str(fixture_path))
    handler = fixture["Handler"]
    server = LoopbackServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/graphql"
    print(f"Local SAFE demonstration (fake data): {target}", flush=True)
    try:
        from gqlsleuth.cli import app

        options = ["scan", target, "--mode", "safe"]
        if args.output is not None:
            options += ["--format", "html", "--output", str(args.output)]
        if args.verbose:
            options.append("--verbose")
        app(args=options, prog_name="gqlsleuth", standalone_mode=False)
        assert len(handler.requests) == 4, "Unexpected local demo request count"
        print(
            "Demo complete: 4 loopback requests, 1 safe Query, zero Mutations or external requests."
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
