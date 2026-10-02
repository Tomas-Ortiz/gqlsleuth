"""The optional acceptance fixture and guard remain testable without real Ollama."""

import runpy
from pathlib import Path

import pytest

from gqlsleuth.ai.context import build_ai_context


@pytest.fixture
def acceptance():
    return runpy.run_path(str(Path(__file__).parents[2] / "scripts" / "check_ollama.py"))


def test_manual_acceptance_fixture_is_mocked_safe_and_populates_references(acceptance):
    scan = acceptance["fixture_scan"]()
    context = build_ai_context(scan)
    assert context.mode.value == "safe"
    assert context.counts["mutation_requests"] == 0
    assert context.counts["query_requests"] == 3
    assert context.operations and context.security_facts


def test_manual_acceptance_network_guard_allows_only_fixed_local_ollama(acceptance):
    guard = acceptance["local_only"]
    guard("socket.connect", (None, ("127.0.0.1", 11434)))
    guard("socket.getaddrinfo", ("127.0.0.1", 11434))
    for event, args in (
        ("socket.connect", (None, ("127.0.0.1", 9))),
        ("socket.connect", (None, ("192.0.2.1", 11434))),
        ("socket.getaddrinfo", ("example.com", 443)),
        ("socket.gethostbyname", ("example.com",)),
        ("socket.sendto", ()),
        ("socket.bind", ()),
    ):
        with pytest.raises(RuntimeError, match="only local Ollama"):
            guard(event, args)
