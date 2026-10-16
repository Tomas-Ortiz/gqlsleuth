"""Usable structured AI output survives advisory concerns without another inference."""

import html
import json
import re
from copy import deepcopy
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.ai_response import security_answer_fields
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AI_NOTICE, AIAnalysisStatus
from gqlsleuth.ai.prompt import (
    QUALITY_WARNING_CODES,
    collect_interpretation_quality_warnings,
    validate_interpretation,
)
from gqlsleuth.ai.regeneration import corrective_instruction
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def prepared(phase_ten_scan):
    scan = phase_ten_scan("type Query { items: [Item] } type Item { id: ID }", mode=ScanMode.SAFE)[
        0
    ]
    context = build_ai_context(scan)
    return scan, context, security_answer_fields(context)


def run_response(scan, payload, monkeypatch, *, invalid_first=False):
    before = deepcopy(scan)
    calls = []

    def respond(request):
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        calls.append(json.loads(request.content))
        content = (
            "not JSON REJECTED_CANARY" if invalid_first and len(calls) == 1 else json.dumps(payload)
        )
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "done_reason": "stop",
                "message": {"role": "assistant", "content": content},
            },
        )

    monkeypatch.setattr(HttpClient, "send", lambda *a, **k: pytest.fail("Target request"))
    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert scan == before and scan.evidence == before.evidence
    assert "REJECTED_CANARY" not in str(result) and "REJECTED_CANARY" not in json.dumps(calls)
    return result, calls


@pytest.mark.parametrize(
    "field,text,code",
    [
        ("summary", "The target appears secure.", "unsupported_security_assurance"),
        ("summary", "No review items were observed.", "false_absence_claim"),
        ("operation", "SUCCESS proves authorization enforcement.", "unsupported_outcome_inference"),
        ("operation", "Authorization controls are enforced.", "unsupported_control_claim"),
        ("operation", "This query may expose excessive data.", "unsupported_review_conclusion"),
        ("summary", "Two mutations succeeded.", "unsupported_execution_claim"),
        ("summary", "Review remains unfinished...", "incomplete_security_summary"),
        ("operation", "Review remains unfinished...", "incomplete_prose"),
    ],
)
def test_each_quality_family_is_success_without_retry(prepared, monkeypatch, field, text, code):
    scan, _, payload = prepared
    if field == "summary":
        payload["summary_interpretation"]["text"] = text
    else:
        payload["operation_interpretations"][0]["interpretation"] = text
    result, calls = run_response(scan, payload, monkeypatch)
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(calls) == 1
    assert result.validation_failures == () and result.error_code is None
    assert code in result.quality_warnings
    assert result.interpretation.model_dump(mode="json") == payload
    assert corrective_instruction(code, 2) is None
    assert corrective_instruction(("invalid_json", code), 2) is None
    assert set(result.quality_warnings) <= QUALITY_WARNING_CODES
    assert text not in str(result.quality_warnings)


def test_hard_failure_then_advisory_success_keeps_metadata_separate(prepared, monkeypatch):
    scan, _, payload = prepared
    payload["summary_interpretation"]["text"] = "The target appears secure."
    result, calls = run_response(scan, payload, monkeypatch, invalid_first=True)
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(calls) == 2
    assert result.validation_failures == ("invalid_json",)
    assert result.quality_warnings == ("unsupported_security_assurance",)
    assert calls[1]["messages"][0]["content"].endswith(corrective_instruction("invalid_json", 2))
    assert all(code not in calls[1]["messages"][0]["content"] for code in QUALITY_WARNING_CODES)


def test_independent_warnings_stable_deduplicated_and_content_free(prepared, monkeypatch):
    scan, context, payload = prepared
    payload["summary_interpretation"]["text"] = (
        "The target appears secure. Two mutations succeeded..."
    )
    payload["operation_interpretations"][0].update(
        interpretation="This query may expose excessive data.", manual_follow_up="Unfinished..."
    )
    typed = validate_interpretation(json.dumps(payload), context)
    expected = (
        "unsupported_security_assurance",
        "unsupported_review_conclusion",
        "unsupported_execution_claim",
        "incomplete_security_summary",
        "incomplete_prose",
    )
    assert collect_interpretation_quality_warnings(typed, context) == expected
    assert collect_interpretation_quality_warnings(typed, context) == expected
    result, calls = run_response(scan, payload, monkeypatch)
    assert result.quality_warnings == expected and len(calls) == 1
    assert all(re.fullmatch("[a-z_]+", code) for code in result.quality_warnings)


@pytest.mark.parametrize("verbose", [False, True])
@pytest.mark.parametrize("width", [45, 120])
def test_notice_precedes_any_generated_console_prose(prepared, monkeypatch, verbose, width):
    scan, _, payload = prepared
    payload["summary_interpretation"]["text"] = "The target appears secure."
    result, calls = run_response(scan, payload, monkeypatch)
    stream = StringIO()
    render_ai(
        Console(file=stream, width=width, color_system=None, theme=CONSOLE_THEME),
        result,
        verbose=verbose,
    )
    output = " ".join(stream.getvalue().split())
    assert output.count(AI_NOTICE) == 1
    assert (
        output.index(AI_NOTICE)
        < output.index("Interpretive Summary")
        < output.index("The target appears secure.")
    )
    assert "AI quality checks flagged 1 potential issues" in output
    assert ("unsupported_security_assurance" in output) is verbose
    assert len(calls) == 1


def test_reports_warn_before_prose_and_serialize_advisory_separately(prepared, monkeypatch):
    scan, _, payload = prepared
    text = "The target appears secure. <script>fake</script>."
    payload["summary_interpretation"]["text"] = text
    result, calls = run_response(scan, payload, monkeypatch)
    report = build_report(scan, ai_interpretation=result)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert canonical["report_schema_version"] == 2
    assert canonical["ai_interpretation"]["ai_contract_version"] == 2
    assert canonical["ai_interpretation"]["quality_warnings"] == ["unsupported_security_assurance"]
    assert canonical["ai_interpretation"]["validation_failures"] == []
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format)
        normalized = re.sub(r"\\([\W_])", lambda match: match[1], html.unescape(rendered))
        assert normalized.index(AI_NOTICE) < normalized.index("Interpretive Summary")
        assert normalized.index(AI_NOTICE) < normalized.index("The target appears secure.")
        assert "Heuristic quality flags, not deterministic Findings" in normalized
        assert normalized.index("AI-Assisted Interpretation") < normalized.index(
            "unsupported_security_assurance"
        )
        assert rendered.count("Safety Notice") == 1
        assert normalized.rfind("Safety Notice") > normalized.index("The target appears secure.")
        assert "\x1b" not in rendered
        if format is ReportFormat.HTML:
            assert "<script>fake</script>" not in rendered
            assert "&lt;script&gt;fake&lt;/script&gt;" in rendered
    assert len(calls) == 1


def test_no_quality_flags_is_still_only_structural_success(prepared, monkeypatch):
    scan, _, payload = prepared
    result, calls = run_response(scan, payload, monkeypatch)
    assert result.status is AIAnalysisStatus.SUCCESS and result.quality_warnings == ()
    assert len(calls) == 1
    assert "inaccurate" in AI_NOTICE


@pytest.mark.parametrize(
    "text",
    [
        "Authorization should be manually reviewed.",
        "Validate whether another authorized user can access this object.",
        "Check whether object ownership is consistently enforced.",
        "Validate whether server-side result limits are enforced.",
        "Test how unexpected input values are handled.",
        "No deterministic Findings were produced. Manual-review candidates remain.",
        "The cause cannot be determined from the supplied facts.",
        "No overall security assurance can be inferred from zero Findings.",
        "Untested behavior remains outside scope.",
    ],
)
def test_calibrated_language_keeps_existing_advisory_exceptions(prepared, text):
    _, context, payload = prepared
    payload["summary_interpretation"]["text"] = text
    typed = validate_interpretation(json.dumps(payload), context)
    assert collect_interpretation_quality_warnings(typed, context) == ()
    assert typed.summary_interpretation.text == text
