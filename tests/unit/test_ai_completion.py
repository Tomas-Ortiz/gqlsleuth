"""All free prose has visible completion checks; canonical facts remain exact text."""

import json
from copy import deepcopy

import httpx
import pytest

from fixtures.ai_response import reference_items, security_answer_fields
from fixtures.whole_scan_ai import SDL, assemble
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AIAnalysisStatus, AIInterpretation, AIValidationError
from gqlsleuth.ai.prompt import (
    build_response_schema,
    collect_interpretation_quality_warnings,
    validate_interpretation,
)
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.infrastructure.ollama import OllamaClient

FIELDS = (
    ("review_insights", "interpretation", "AIReviewInsight", 350),
    ("review_insights", "manual_follow_up", "AIReviewInsight", 220),
    ("operation_interpretations", "interpretation", "AIOperationInterpretation", 300),
    ("operation_interpretations", "manual_follow_up", "AIOperationInterpretation", 220),
    ("limitations", "text", "AIInterpretiveLimitation", 500),
)


@pytest.fixture
def prepared(phase_ten_scan):
    scan = assemble(phase_ten_scan(SDL)[0])
    context = build_ai_context(scan)
    payload = security_answer_fields(context)
    payload["review_insights"] = [
        {
            "references": reference_items(
                [], [f.security_fact_ref for f in context.security_facts[:2]]
            ),
            "interpretation": "Review the related observations manually.",
            "manual_follow_up": "Review the intended policy manually.",
        }
    ]
    payload["limitations"] = [
        {"text": "Untested behavior remains outside scope.", "references": reference_items([], [])}
    ]
    return scan, context, payload


@pytest.mark.parametrize("section,key,model,ceiling", FIELDS)
@pytest.mark.parametrize(
    "ending", ["unfinished", "...", "…", ". . .", "….", "unfinished-", "unfinished—"]
)
def test_all_free_prose_rejects_incomplete_endings(prepared, section, key, model, ceiling, ending):
    _, context, payload = prepared
    payload[section][0][key] = "Manual review remains " + ending
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "incomplete_prose" in warnings


@pytest.mark.parametrize("section,key,model,ceiling", FIELDS)
def test_complete_prose_at_ceiling_is_not_rejected_for_length(
    prepared, section, key, model, ceiling
):
    _, context, payload = prepared
    sentence = "Review the supplied facts manually. "
    text = sentence * (ceiling // len(sentence) - 1) + "Review scope."
    text = text.replace("Review scope.", "Review" + " " * (ceiling - len(text) + 1) + "scope.")
    assert len(text) == ceiling
    payload[section][0][key] = text
    typed = validate_interpretation(json.dumps(payload), context)
    assert getattr(getattr(typed, section)[0], key) == text
    for schema in (AIInterpretation.model_json_schema(), build_response_schema(context)):
        assert schema["$defs"][model]["properties"][key]["maxLength"] == ceiling
    payload[section][0][key] += "x"
    with pytest.raises(AIValidationError, match="invalid_schema"):
        validate_interpretation(json.dumps(payload), context)


@pytest.mark.parametrize("ending", [".", "!", "?", '."', ".”", ".)", ".]"])
def test_complete_quoted_prose_is_preserved(prepared, ending):
    _, context, payload = prepared
    text = "Manually review the supplied facts" + ending
    payload["limitations"][0]["text"] = text
    assert validate_interpretation(json.dumps(payload), context).limitations[0].text == text


def test_old_500_character_limitation_is_retained_with_advisory_warning(prepared):
    scan, context, payload = prepared
    before = deepcopy(scan)
    bad = deepcopy(payload)
    prefix = "Untested behavior remains outside scope. "
    bad_text = (prefix * 20)[: 500 - len("Manual")] + "Manual"
    bad["limitations"][0]["text"] = bad_text
    assert len(bad_text) == 500
    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        reply = bad if len(requests) == 1 else payload
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "message": {"role": "assistant", "content": json.dumps(reply)},
            },
        )

    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.validation_failures == ()
    assert result.quality_warnings == ("incomplete_prose",)
    assert result.attempt_count == len(requests) == 1
    assert result.interpretation.limitations[0].text == bad_text
    assert scan == before and scan.evidence == before.evidence
