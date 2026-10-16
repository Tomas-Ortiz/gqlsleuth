"""Reject unsupported overall assurance and clipped summaries without model retries."""

import json
import runpy
from copy import deepcopy
from pathlib import Path

import httpx
import pytest

from fixtures.ai_response import reference_items, security_answer_fields
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import MAX_AI_SUMMARY_CHARACTERS, AIAnalysisStatus, AIValidationError
from gqlsleuth.ai.prompt import (
    build_response_schema,
    build_system_prompt,
    collect_interpretation_quality_warnings,
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


def answer(context, text="Review the supplied facts manually."):
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = text
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
    typed = validate_interpretation(json.dumps(answer(context, text)), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_security_assurance" in warnings


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
    assert result.summary_interpretation.text == text


def test_real_qwen_passive_denial_does_not_offer_assurance(completed):
    context = build_ai_context(completed)
    text = (
        "No overall security assurance can be inferred from zero Findings "
        "or successful Queries alone."
    )
    result = validate_interpretation(json.dumps(answer(context, text)), context)
    assert result.summary_interpretation.text == text


@pytest.mark.parametrize(
    "claim",
    [
        "Overall security assurance can be inferred from zero Findings.",
        "No failures occurred, so overall security assurance can be inferred.",
        "No overall security assurance can be inferred, but the target appears secure.",
        "No overall security assurance can be inferred; no meaningful vulnerabilities exist.",
    ],
)
def test_passive_denial_does_not_exempt_a_positive_assurance_claim(completed, claim):
    context = build_ai_context(completed)
    typed = validate_interpretation(json.dumps(answer(context, claim)), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_security_assurance" in warnings


def test_real_qwen_repeated_limitations_still_fail_summary_completion(completed):
    context = build_ai_context(completed)
    text = (
        "Limited runtime assessment due to unexecuted capability probes. No deterministic Findings "
        "observed. Review candidates exist but require manual follow-up without escalating to "
        "vulnerabilities. Scope limitations apply to all observations and interpretations. "
        "No overall security assurance can be inferred from zero Findings or successful Queries "
        "alone. Untested behavior remains outside the scope of this scan. The absence of Findings "
        "does not imply security, safety, or effective controls. Manual review of supplied "
        "candidates is required without assuming vulnerabilities or business impact. No policy "
        "violations or "
        "unresolved observations were upgraded beyond their supplied category. The scan did not "
        "test authorization, authentication, or abuse controls, and no evidence of runtime "
        "behavior was ob-"
    )
    assert len(text) == 800
    typed = validate_interpretation(json.dumps(answer(context, text)), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "incomplete_security_summary" in warnings


def test_schema_descriptions_steer_concise_grounded_prose_without_changing_bounds(completed):
    context = build_ai_context(completed)
    definitions = build_response_schema(context)["$defs"]
    for name, field, maximum, guidance in (
        ("AISummaryInterpretation", "text", 800, "Finish naturally well before"),
        ("AIOperationInterpretation", "interpretation", 300, "Interest is not risk/severity"),
    ):
        description = definitions[name]["properties"][field]
        assert description["maxLength"] == maximum
        assert guidance in description["description"]
    prompt = build_system_prompt(context)
    assert "Do not repeat disclaimers" in prompt
    assert "180-350 characters total" in prompt


@pytest.mark.parametrize(
    "section,key",
    [
        ("review_insights", "interpretation"),
        ("review_insights", "manual_follow_up"),
        ("operation_interpretations", "interpretation"),
        ("limitations", "text"),
    ],
)
def test_other_prose_sections_cannot_hide_assurance(completed, section, key):
    context = build_ai_context(completed)
    payload = answer(context)
    if section == "operation_interpretations":
        payload[section][0][key] = "The target appears secure."
    elif section == "review_insights":
        payload[section] = [
            {
                "references": reference_items(
                    [o.operation for o in context.operations[:2]],
                    [context.security_facts[0].security_fact_ref],
                ),
                "interpretation": "Review related roles.",
                "manual_follow_up": "Review manually.",
            }
        ]
        payload[section][0][key] = "The target appears secure."
    else:
        payload[section] = [
            {"text": "The target appears secure.", "references": reference_items([], [])}
        ]
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_security_assurance" in warnings


@pytest.mark.parametrize("ending", ["The scan also did not cover", "..."])
def test_previous_boundary_length_truncation_is_rejected(completed, ending):
    context = build_ai_context(completed)
    prefix = "The checks cover only supplied facts. "
    text = (prefix * 30)[: MAX_AI_SUMMARY_CHARACTERS - len(ending)] + ending
    assert len(text) == MAX_AI_SUMMARY_CHARACTERS
    typed = validate_interpretation(json.dumps(answer(context, text)), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "incomplete_security_summary" in warnings


@pytest.mark.parametrize("text", ["Scope is limited and", "Scope remains untested...", "Untested…"])
def test_incomplete_short_summaries_are_also_rejected(completed, text):
    context = build_ai_context(completed)
    typed = validate_interpretation(json.dumps(answer(context, text)), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "incomplete_security_summary" in warnings


def test_summary_schema_ceiling_and_requested_headroom(completed):
    context = build_ai_context(completed)
    field = build_response_schema(context)["$defs"]["AISummaryInterpretation"]["properties"]["text"]
    assert field["maxLength"] == MAX_AI_SUMMARY_CHARACTERS == 800
    assert "180-350" in field["description"] and "180-350" in build_system_prompt(context)
    assert "2-4" in field["description"] and "2-4" in build_system_prompt(context)
    text = "No deterministic Findings were produced by the executed checks. Untested behavior "
    text += "remains outside scope; these observations do not establish overall target security."
    assert len(text) < MAX_AI_SUMMARY_CHARACTERS / 2
    result = validate_interpretation(json.dumps(answer(context, text)), context)
    assert json.loads(result.model_dump_json())["summary_interpretation"]["text"] == text
    with pytest.raises(AIValidationError, match="invalid_schema"):
        validate_interpretation(json.dumps(answer(context, "x" * 801)), context)


def test_four_complete_short_sentences_are_a_generation_preference_not_a_parser(completed):
    context = build_ai_context(completed)
    text = (
        "The executed checks produced no deterministic Findings. Manual-review candidates remain. "
        "Untested authorization behavior is outside this assessment. "
        "These observations do not establish overall target security."
    )
    assert 180 <= len(text) <= 350
    result = validate_interpretation(json.dumps(answer(context, text)), context)
    assert result.summary_interpretation.text == text


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
    assert result.status is AIAnalysisStatus.SUCCESS and result.error_code is None
    assert code in result.quality_warnings
    assert result.validation_failures == ()
    assert result.interpretation.summary_interpretation.text == text and len(calls) == 1
    assert completed == before and completed.evidence == before.evidence
    assert text not in str(result.quality_warnings)


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
    typed = validate_interpretation(json.dumps(answer(context, text)), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "false_absence_claim" in warnings


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
    assert result.summary_interpretation.text == text


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
        validate_interpretation(
            json.dumps(answer(context, text)), context
        ).summary_interpretation.text
        == text
    )


def test_review_interest_without_structural_facts_still_contradicts_absence(phase_ten_scan):
    context = build_ai_context(
        phase_ten_scan("type Query { login: String }", mode=ScanMode.SAFE)[0]
    )
    assert not context.security_facts and context.operations[0].interest_score > 0
    typed = validate_interpretation(
        json.dumps(answer(context, "Nothing noteworthy was identified.")), context
    )
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "false_absence_claim" in warnings


@pytest.mark.parametrize("section", ["operation_interpretations", "limitations", "review_insights"])
def test_false_absence_guard_covers_other_prose(acceptance_context, section):
    context = acceptance_context
    payload = answer(context)
    text = "No security facts were observed."
    if section == "operation_interpretations":
        payload[section][0]["interpretation"] = text
    elif section == "limitations":
        payload[section] = [{"text": text, "references": reference_items([], [])}]
    else:
        payload[section] = [
            {
                "references": reference_items([o.operation for o in context.operations[:2]], []),
                "interpretation": text,
                "manual_follow_up": "Review manually.",
            }
        ]
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "false_absence_claim" in warnings
