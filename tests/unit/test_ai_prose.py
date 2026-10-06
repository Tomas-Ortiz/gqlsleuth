"""Reject unsupported overall assurance and clipped summaries without model retries."""

import json
import runpy
from copy import deepcopy
from pathlib import Path

import httpx
import pytest

from fixtures.ai_response import security_answer_fields
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import MAX_AI_SUMMARY_CHARACTERS, AIAnalysisStatus, AIValidationError
from gqlsleuth.ai.prompt import (
    build_response_schema,
    build_system_prompt,
    execution_summary,
    validate_interpretation,
)
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.ollama import OllamaClient


@pytest.fixture
def completed(phase_ten_scan):
    return phase_ten_scan("type Query { items: [Item] } type Item { id: ID }", mode=ScanMode.SAFE)[
        0
    ]


def answer(context, text):
    payload = {
        **security_answer_fields(context),
        "scan_summary": {"text": execution_summary(context), "operations": []},
        "operation_review": [],
        "limitations": [],
    }
    payload["security_summary"]["text"] = text
    return payload


@pytest.mark.parametrize(
    "text",
    [
        "No findings were produced, suggesting that the system may be secure.",
        "With zero findings, the target appears secure.",
        "No vulnerabilities appear to exist.",
        "Queries succeeded; the target is safe.",
        "The application is not vulnerable.",
        "No meaningful vulnerabilities exist.",
        "There are no meaningful vulnerabilities.",
        "The system has no security vulnerabilities.",
        "The security controls are generally effective.",
        "Controls appear generally effective.",
        "The assessment provides overall security assurance.",
        "This does not establish that the target is secure. However, the system may be safe.",
        "This does not show failures and the target is secure.",
        "The TARGET appears\nSECURE.",
    ],
)
def test_reject_overall_assurance_with_zero_findings_and_successful_queries(completed, text):
    context = build_ai_context(completed)
    assert context.metadata.deterministic_findings == 0
    assert context.counts["query_success"] == 1
    with pytest.raises(AIValidationError) as caught:
        validate_interpretation(json.dumps(answer(context, text)), context)
    assert (caught.value.stage, caught.value.code) == ("facts", "unsupported_security_assurance")
    assert text not in str(caught.value)


@pytest.mark.parametrize(
    "text",
    [
        "No deterministic Findings were produced by the executed checks. "
        "This does not establish overall target security.",
        "The tested operations produced no deterministic findings. Untested behavior remains "
        "outside the assessment.",
        "Successful Queries do not prove that the target is safe. Review untested behavior.",
        "No vulnerabilities were observed by the executed checks. This does not mean the "
        "system is not vulnerable.",
        "These checks cannot provide overall security assurance. Further scoped review is needed.",
        "Safe Query execution completed. This does not imply that security controls are effective.",
        "The tested control rejected this exact request. Broader enforcement remains untested.",
    ],
)
def test_accept_calibrated_scope_without_rewriting(completed, text):
    context = build_ai_context(completed)
    result = validate_interpretation(json.dumps(answer(context, text)), context)
    assert result.security_summary.text == text


@pytest.mark.parametrize(
    "section,key",
    [
        ("security_fact_reviews", "interpretation"),
        ("security_fact_reviews", "manual_follow_up"),
        ("operation_review", "explanation"),
        ("limitations", "text"),
    ],
)
def test_other_prose_sections_cannot_hide_assurance(completed, section, key):
    context = build_ai_context(completed)
    payload = answer(context, "The observed outcomes require scoped manual review.")
    if section == "security_fact_reviews":
        entry = {
            "security_fact_ref": context.security_facts[0].security_fact_ref,
            "interpretation": "Review scoped facts.",
            "manual_follow_up": "Review manually.",
        }
    elif section == "operation_review":
        entry = {"operation": context.operations[0].operation}
    else:
        entry = {"operations": []}
    entry[key] = "The target appears secure."
    payload[section] = [entry]
    with pytest.raises(AIValidationError, match="unsupported_security_assurance"):
        validate_interpretation(json.dumps(payload), context)


@pytest.mark.parametrize("ending", ["The scan also did not cover", "..."])
def test_previous_boundary_length_truncation_is_rejected(completed, ending):
    context = build_ai_context(completed)
    prefix = "The checks cover only supplied facts. "
    text = (prefix * 30)[: MAX_AI_SUMMARY_CHARACTERS - len(ending)] + ending
    assert len(text) == MAX_AI_SUMMARY_CHARACTERS
    with pytest.raises(AIValidationError, match="incomplete_security_summary"):
        validate_interpretation(json.dumps(answer(context, text)), context)


@pytest.mark.parametrize("text", ["Scope is limited and", "Scope remains untested...", "Untested…"])
def test_incomplete_short_summaries_are_also_rejected(completed, text):
    context = build_ai_context(completed)
    with pytest.raises(AIValidationError, match="incomplete_security_summary"):
        validate_interpretation(json.dumps(answer(context, text)), context)


def test_summary_schema_ceiling_and_requested_headroom(completed):
    context = build_ai_context(completed)
    field = build_response_schema(context)["$defs"]["AISecuritySummary"]["properties"]["text"]
    assert field["maxLength"] == MAX_AI_SUMMARY_CHARACTERS == 800
    assert "180–350" in field["description"] and "180–350" in build_system_prompt(context)
    text = "No deterministic Findings were produced by the executed checks. Untested behavior "
    text += "remains outside scope; these observations do not establish overall target security."
    assert len(text) < MAX_AI_SUMMARY_CHARACTERS / 2
    result = validate_interpretation(json.dumps(answer(context, text)), context)
    assert json.loads(result.model_dump_json())["security_summary"]["text"] == text
    with pytest.raises(AIValidationError, match="invalid_schema"):
        validate_interpretation(json.dumps(answer(context, "x" * 801)), context)


@pytest.mark.parametrize(
    "text,code",
    [
        ("The target appears secure.", "unsupported_security_assurance"),
        ("The scan also did not cover", "incomplete_security_summary"),
        ("No security facts were observed.", "false_absence_claim"),
    ],
)
def test_prose_failure_is_nonfatal_single_inference_and_preserves_scan(completed, text, code):
    before = deepcopy(completed)
    context = build_ai_context(completed)
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "message": {"role": "assistant", "content": json.dumps(answer(context, text))},
            },
        )

    result = interpret_completed_scan(
        completed, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.INVALID_RESPONSE and result.error_code == code
    assert result.interpretation is None and len(calls) == 1
    assert completed == before and completed.evidence == before.evidence
    assert text not in result.error_message


@pytest.fixture
def acceptance_context():
    fixture = runpy.run_path(str(Path(__file__).parents[2] / "scripts" / "check_ollama.py"))
    return build_ai_context(fixture["fixture_scan"]())


@pytest.mark.parametrize(
    "text",
    [
        "No security facts were observed.",
        "There were no security-relevant observations.",
        "Nothing noteworthy was identified.",
        "No review items were present.",
        "No manual-review candidates were identified.",
        "No relevant issues were observed.",
        "No security-relevant information was supplied.",
        "No security facts or policy violations observed.",
        "No security facts or policy violations identified.",
        "NO SECURITY FACTS were\nobserved.",
    ],
)
def test_absence_contradicts_real_acceptance_review_facts(acceptance_context, text):
    context = acceptance_context
    assert context.metadata.deterministic_findings == 0
    assert {fact.candidate_type for fact in context.security_facts} == {
        "file_upload_surface",
        "subscription_surface",
        "object_lookup_review",
        "list_bounding_review",
        "recursive_graph_review",
        "ownership_control",
        "privilege_control",
    }
    assert all(fact.category == "review_candidate" for fact in context.security_facts)
    with pytest.raises(AIValidationError) as caught:
        validate_interpretation(json.dumps(answer(context, text)), context)
    assert (caught.value.stage, caught.value.code) == ("facts", "false_absence_claim")
    assert text not in str(caught.value)


@pytest.mark.parametrize(
    "text",
    [
        "No deterministic Findings were produced, but manual-review candidates remain.",
        "No confirmed Findings were recorded; review-interest observations remain.",
        "The executed checks produced no Findings, while manual-review items are still present.",
        "No review items were executed. Schema review candidates remain unvalidated.",
        "Zero Findings does not mean no security facts were observed. Manual review remains.",
    ],
)
def test_absence_preserves_finding_review_distinction(acceptance_context, text):
    result = validate_interpretation(
        json.dumps(answer(acceptance_context, text)), acceptance_context
    )
    assert result.security_summary.text == text


def test_accurate_bounded_absence_without_security_review_facts(phase_ten_scan):
    context = build_ai_context(
        phase_ten_scan("type Query { greeting: String }", mode=ScanMode.SAFE)[0]
    )
    assert not context.security_facts
    assert context.metadata.deterministic_findings == 0
    assert all(operation.interest_score == 0 for operation in context.operations)
    text = (
        "No review items were observed in the supplied checks. "
        "Untested behavior remains outside scope."
    )
    assert (
        validate_interpretation(json.dumps(answer(context, text)), context).security_summary.text
        == text
    )


def test_review_interest_without_structural_facts_still_contradicts_absence(phase_ten_scan):
    context = build_ai_context(
        phase_ten_scan("type Query { login: String }", mode=ScanMode.SAFE)[0]
    )
    assert not context.security_facts and context.operations[0].interest_score > 0
    with pytest.raises(AIValidationError, match="false_absence_claim"):
        validate_interpretation(
            json.dumps(answer(context, "Nothing noteworthy was identified.")), context
        )


@pytest.mark.parametrize("section", ["operation_review", "limitations", "security_fact_reviews"])
def test_false_absence_guard_covers_other_prose(acceptance_context, section):
    context = acceptance_context
    payload = answer(context, "Review candidates remain outside the executed checks.")
    text = "No security facts were observed."
    if section == "operation_review":
        payload[section] = [{"operation": context.operations[0].operation, "explanation": text}]
    elif section == "limitations":
        payload[section] = [{"text": text, "operations": []}]
    else:
        payload[section] = [
            {
                "security_fact_ref": context.security_facts[0].security_fact_ref,
                "interpretation": text,
                "manual_follow_up": "Review manually.",
            }
        ]
    with pytest.raises(AIValidationError, match="false_absence_claim"):
        validate_interpretation(json.dumps(payload), context)
