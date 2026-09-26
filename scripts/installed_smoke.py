"""Run with the installed interpreter outside the checkout; runtime dependencies only."""

import argparse
import importlib.metadata
import importlib.util
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

# Also loaded by actual console-launcher subprocesses through an external sitecustomize.
NETWORK_GUARD = """import sys
def deny_network(event, args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
                 "socket.gethostbyaddr", "socket.sendto", "socket.bind"}:
        raise RuntimeError("Installed smoke forbids real network activity")
sys.addaudithook(deny_network)
sys._gqlsleuth_smoke_guard = True
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    exec(NETWORK_GUARD, {})  # Fixed local guard code, never target/model input.

    import httpx
    from graphql import build_schema, introspection_from_schema

    import gqlsleuth
    from gqlsleuth.application.safe_execution import run_safe_execution_scan
    from gqlsleuth.graphql.introspection import (
        FULL_INTROSPECTION_QUERY,
        MINIMAL_INTROSPECTION_QUERY,
    )
    from gqlsleuth.reporting.builder import build_report
    from gqlsleuth.reporting.models import ReportFormat
    from gqlsleuth.reporting.output import write_reports
    from gqlsleuth.rules.loader import load_bundled_rules

    checkout = args.checkout.resolve()
    package = Path(gqlsleuth.__file__).resolve()
    assert not Path.cwd().resolve().is_relative_to(checkout)
    assert not package.is_relative_to(checkout), package
    assert package.is_relative_to(Path(sys.prefix).resolve()), package
    assert gqlsleuth.__version__ == importlib.metadata.version("gqlsleuth") == args.version
    assert all(importlib.util.find_spec(name) is None for name in ("pytest", "ruff", "mypy"))
    assert load_bundled_rules().rules

    # Prove the in-process guard works before exercising installed functionality.
    try:
        socket.getaddrinfo("127.0.0.1", 9)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Network guard did not block DNS")

    guard_dir = Path.cwd() / "guard"
    guard_dir.mkdir()
    (guard_dir / "sitecustomize.py").write_text(NETWORK_GUARD, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(guard_dir), "PYTHONNOUSERSITE": "1"}
    env.pop("PYTHONHOME", None)
    subprocess.run(
        [sys.executable, "-c", "import sys; assert sys._gqlsleuth_smoke_guard"],
        env=env,
        check=True,
    )
    scripts = Path(sys.executable).parent
    executable = scripts / ("gqlsleuth.exe" if os.name == "nt" else "gqlsleuth")
    for options in (("--help",), ("scan", "--help"), ("version",)):
        completed = subprocess.run(
            [str(executable), *options],
            env=env,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert "GQLSleuth" in completed.stdout or "GraphQL" in completed.stdout
        if options == ("version",):
            assert completed.stdout.strip() == f"GQLSleuth {args.version}"
        print("Installed CLI passed:", " ".join(options))

    schema = introspection_from_schema(build_schema("type Query { greeting: String }"))
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.host == "127.0.0.1"
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        query = json.loads(request.content)["query"]
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": {"__schema": {}}})
        if query == FULL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": schema})
        assert query.strip().startswith("query") and "greeting" in query
        return httpx.Response(200, json={"data": {"greeting": "local fixture"}})

    # Replace the shared adapter's constructor for ALL pipeline clients, not one stage.
    with patch(
        "httpx._client.HTTPTransport", side_effect=lambda **kw: httpx.MockTransport(respond)
    ):
        result = run_safe_execution_scan("http://127.0.0.1:9/graphql")
        assert len(requests) == 4
        assert len(result.executions) == 1 and result.executions[0].status.value == "success"
        report = build_report(result)
        paths = write_reports(report, tuple(ReportFormat), Path.cwd() / "reports")
        assert len(paths) == 3 and len(requests) == 4
        for path in paths:
            content = path.read_text(encoding="utf-8")
            if path.suffix == ".json":
                data = json.loads(content)
                assert data["gqlsleuth_version"] == args.version
                assert data["evidence"]
            else:
                assert content.count("Safety Notice") == 1
                assert "<h" not in content.split("Safety Notice", 1)[1]
                assert "\n##" not in content.split("Safety Notice", 1)[1]
    print(
        "Installed resources/reports passed; 4 mocked requests, 1 safe Query, 0 real network calls."
    )
    print("Version:", gqlsleuth.__version__, "Package:", package)


if __name__ == "__main__":
    main()
