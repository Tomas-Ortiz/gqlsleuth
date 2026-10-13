"""The optional acceptance fixture and guard remain testable without real Ollama."""

import json
import runpy
from pathlib import Path

import pytest

from fixtures.ai_response import security_answer_fields
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AIValidationError
from gqlsleuth.ai.prompt import execution_summary


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


@pytest.mark.parametrize(
    "text,code",
    [
        ("The target appears secure.", "unsupported_security_assurance"),
        ("The supplied observations require further", "incomplete_security_summary"),
    ],
)
def test_fixture_diagnostics_preserve_rejections_and_show_exact_prose(
    acceptance, capsys, text, code
):
    context = build_ai_context(acceptance["fixture_scan"]())
    answer = {
        **security_answer_fields(context),
        "scan_summary": {"text": execution_summary(context), "operations": []},
        "operation_review": [],
        "limitations": [],
    }
    answer["security_summary"]["text"] = text
    with pytest.raises(AIValidationError, match=code):
        acceptance["validate_fixture_reply"](json.dumps(answer), context)
    output = capsys.readouterr().out
    assert "NOT an accepted interpretation" in output and text in output
    assert f"Rejected summary length: {len(text)}" in output


def test_fixture_diagnostics_do_not_dump_unstructured_replies(acceptance, capsys):
    context = build_ai_context(acceptance["fixture_scan"]())
    with pytest.raises(AIValidationError, match="invalid_json"):
        acceptance["validate_fixture_reply"]("not JSON: FAKE_MODEL_OUTPUT", context)
    assert capsys.readouterr().out == ""
