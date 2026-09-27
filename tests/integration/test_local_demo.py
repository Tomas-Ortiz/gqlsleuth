"""User onboarding runs only fake loopback data, without altering scanner behavior."""

import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "examples/local_demo.py"


def test_demo_guard_rejects_external_socket_and_dns_events():
    guard = runpy.run_path(str(DEMO))["guard_network"]
    for event, args in (
        ("socket.connect", (None, ("192.0.2.1", 80))),
        ("socket.bind", (None, ("0.0.0.0", 80))),
        ("socket.getaddrinfo", ("external.invalid", 80)),
        ("socket.gethostbyname", ("external.invalid",)),
        ("socket.gethostbyaddr", ("192.0.2.1",)),
        ("socket.sendto", (None, ("192.0.2.1", 80))),
    ):
        # Call the audit boundary directly: even a broken guard cannot contact a public host.
        with pytest.raises(RuntimeError, match="Local demo"):
            guard(event, args)
    guard("socket.connect", (None, ("127.0.0.1", 12345)))
    guard("socket.bind", (None, ("127.0.0.1", 0)))
    guard("socket.getaddrinfo", ("127.0.0.1", 12345))


@pytest.mark.parametrize("report", [False, True])
def test_demo_safe_workflow_and_optional_html(tmp_path, report):
    output = tmp_path / "reports"
    options = ["--output", str(output), "--verbose"] if report else []
    completed = subprocess.run(
        [sys.executable, str(DEMO), *options],
        cwd=tmp_path,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        capture_output=True,
        encoding="utf-8",
        check=True,
        timeout=30,
    )
    assert "fake data" in completed.stdout
    assert "http://127.0.0.1:" in completed.stdout
    assert "Mode: SAFE" in completed.stdout
    assert (
        "4 loopback requests, 1 safe Query, zero Mutations or external requests" in completed.stdout
    )
    assert "Execute these" not in completed.stdout
    assert "Phase " not in completed.stdout
    if report:
        paths = list(output.glob("*.html"))
        assert len(paths) == 1
        content = paths[0].read_text(encoding="utf-8")
        assert "query album" in content
        assert content.count("Safety Notice") == 1
        assert "<h" not in content.split("Safety Notice")[1]
    else:
        assert not output.exists()
