"""Offline CLI sequencing and AI fallback without altering completed scan behavior."""

import json
from copy import deepcopy

import httpx
import pytest
from typer.testing import CliRunner

import gqlsleuth.cli as cli
from gqlsleuth.ai.models import AIContext
from gqlsleuth.ai.prompt import execution_summary
from gqlsleuth.application.active_execution import execute_selected_mutations
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient


@pytest.fixture
def ai_cli(phase_ten_scan, monkeypatch, tmp_path):
    # Durations are now visible; compare presentation with deterministic transport timing.
    monkeypatch.setattr("gqlsleuth.infrastructure.http.perf_counter", lambda: 1.0)
    scans = {mode: phase_ten_scan(mode=mode)[0] for mode in ScanMode}
    events = []
    target_requests = []
    ai_requests = []
    results = []
    behavior = {"fail": False}

    def scan(target, *, mode=ScanMode.SAFE, http_settings=None):
        events.append("safe")
        return scans[mode]

    def target_handler(request):
        target_requests.append(json.loads(request.content))
        return httpx.Response(200, json={"data": None})

    def execute(preview, *, selected_indices=(), confirmed=False, http_settings=None):
        with HttpClient(http_settings, transport=httpx.MockTransport(target_handler)) as client:
            result = execute_selected_mutations(
                preview, selected_indices=selected_indices, confirmed=confirmed, client=client
            )
        results.append(result)
        events.append("active_complete")
        return result

    def ollama_handler(request):
        ai_requests.append(json.loads(request.content))
        if behavior["fail"]:
            raise httpx.ConnectError("Private error detail", request=request)
        context = AIContext.model_validate_json(ai_requests[-1]["messages"][1]["content"])
        payload = {
            "scan_summary": {"text": execution_summary(context), "operations": []},
            "operation_review": [],
            "limitations": [],
        }
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(payload),
                    "thinking": "HIDDEN_REASONING_CANARY",
                },
            },
        )

    def interpret(result):
        events.append("ai")
        before = deepcopy(result)
        output = interpret_completed_scan(
            result, client=OllamaClient(transport=httpx.MockTransport(ollama_handler))
        )
        assert result == before
        return output

    monkeypatch.setattr(cli, "run_safe_execution_scan", scan)
    monkeypatch.setattr(cli, "execute_selected_mutations", execute)
    monkeypatch.setattr(cli, "interpret_completed_scan", interpret)
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    monkeypatch.chdir(tmp_path)
    return events, target_requests, ai_requests, results, behavior


def invoke(mode, *, ai=False, reports=False, input="\n", verbose=False):
    options = ["scan", "https://example.com", "--mode", mode]
    if ai:
        options.append("--ai")
    if verbose:
        options.append("--verbose")
    if reports:
        for format in ("json", "markdown", "html"):
            options.extend(["--format", format])
    return CliRunner().invoke(cli.app, options, input=input)


@pytest.mark.parametrize("mode", ["safe", "active"])
def test_disabled_ai_makes_no_inference_or_ai_report_section(ai_cli, tmp_path, mode, monkeypatch):
    monkeypatch.setattr(
        cli, "interpret_completed_scan", lambda *args: pytest.fail("AI was enabled without --ai")
    )
    result = invoke(mode, reports=True)
    assert result.exit_code == 0
    assert "AI-Assisted Interpretation" not in result.stdout
    assert ai_cli[2] == []
    report = json.loads(
        next((tmp_path / "gqlsleuth-reports").glob("*.json")).read_text(encoding="utf-8")
    )
    assert "ai_interpretation" not in report


@pytest.mark.parametrize(
    "mode,selection,mutation_count",
    [("safe", "\n", 0), ("active", "\n", 0), ("active", "1\ny\n", 1)],
)
@pytest.mark.parametrize("verbose", [False, True])
def test_one_ai_inference_follows_completed_safe_and_active_behavior(
    ai_cli, mode, selection, mutation_count, verbose
):
    baseline = invoke(mode, input=selection, verbose=verbose)
    events, target_requests, ai_requests, results, _ = ai_cli
    before_requests = list(target_requests)
    events.clear()
    result = invoke(mode, ai=True, input=selection, verbose=verbose)
    assert result.exit_code == baseline.exit_code == 0
    assert result.stdout.split("AI assistance: interpreting")[0] == baseline.stdout
    assert events == (["safe", "active_complete", "ai"] if mode == "active" else ["safe", "ai"])
    assert len(ai_requests) == 1
    assert len(target_requests) == mutation_count * 2
    assert target_requests == before_requests + before_requests
    context = json.loads(ai_requests[0]["messages"][1]["content"])
    assert context["counts"]["mutation_requests"] == mutation_count
    prompt = ai_requests[0]["messages"][0]["content"]
    assert f"{mutation_count} Mutation requests" in prompt
    assert ("ZERO Mutations were attempted" in prompt) is (mutation_count == 0)
    if mode == "active":
        assert results[-1].selected_indices == ((1,) if mutation_count else ())
        assert results[-1].confirmed is bool(mutation_count)
    assert "AI-Assisted Interpretation" in result.stdout
    assert "Model-generated interpretation" in result.stdout
    assert "HIDDEN_REASONING_CANARY" not in result.stdout


@pytest.mark.parametrize("fail", [False, True])
def test_optional_ai_reports_preserve_deterministic_data_even_on_failure(ai_cli, tmp_path, fail):
    ai_cli[-1]["fail"] = fail
    result = invoke("active", ai=True, reports=True)
    assert result.exit_code == 0
    assert len(ai_cli[2]) == 1
    assert ai_cli[1] == []
    paths = tuple((tmp_path / "gqlsleuth-reports").iterdir())
    assert len(paths) == 3
    report = json.loads(
        next(path for path in paths if path.suffix == ".json").read_text(encoding="utf-8")
    )
    assert report["ai_interpretation"]["status"] == ("unavailable" if fail else "success")
    assert report["summary"]["mutation_execution_count"] == 0
    assert report["active"]["confirmed"] is False
    assert not any(item["evidence_type"].startswith("ai") for item in report["evidence"])
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "HIDDEN_REASONING_CANARY" not in text
        assert "Private error detail" not in text
        if path.suffix != ".json":
            assert "AI-Assisted Interpretation" in text
    if fail:
        assert "AI assistance unavailable" in result.stdout
        assert "Deterministic scan completed normally" in result.stdout
        assert "Traceback" not in result.output
