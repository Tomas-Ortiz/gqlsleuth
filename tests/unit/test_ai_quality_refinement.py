"""Phase 2B: speculative effects, useful guidance and content-free field accounting."""

import html
import json
import re
from collections import Counter
from copy import deepcopy
from dataclasses import replace
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.ai_response import reference_items, security_answer_fields
from gqlsleuth.ai import quality
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import DEFAULT_AI_MODEL, AIAnalysisStatus, AISecurityFact
from gqlsleuth.ai.prompt import build_response_schema, build_system_prompt, validate_interpretation
from gqlsleuth.ai.prose_entries import prose_entries
from gqlsleuth.ai.quality import WITHHELD_PROSE, enforce_interpretation_grounding
from gqlsleuth.ai.sections import quality_summary_lines
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
    scan, _ = phase_ten_scan(
        "type Query { user(id: ID!): Item } type Item { id: ID } "
        "type Mutation { updateUser: Item deleteUser: Item createComment: Item "
        "updateAlbum: Item updateComment: Item createUser: Item createAlbum(userId: ID!): Item }",
        mode=ScanMode.SAFE,
    )
    return scan, build_ai_context(scan)


def interpret_mock(scan, context, payload, monkeypatch, *, timeout=600):
    requests = []
    before = deepcopy(scan)

    def respond(request):
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        requests.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": DEFAULT_AI_MODEL,
                "done": True,
                "done_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(payload)},
            },
        )

    monkeypatch.setattr(HttpClient, "send", lambda *a, **kw: pytest.fail("Target request"))
    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond), timeout_seconds=timeout)
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(requests) == 1
    assert result.validation_failures == ()
    assert requests[0]["messages"][1]["content"] == serialize_context(context)
    assert scan == before and scan.evidence == before.evidence
    return result


@pytest.mark.parametrize(
    "name,text",
    [
        ("updateUser", "updateUser may allow unauthorized modifications."),
        ("deleteUser", "deleteUser may allow unauthorized deletion."),
        ("createComment", "createComment could enable unauthorized content creation."),
        ("updateAlbum", "updateAlbum might permit unauthorized ownership changes."),
        ("updateComment", "updateComment potentially allows unauthorized edits."),
        ("createUser", "createUser may permit account creation without authorization."),
        ("updateUser", "This mutation could permit the unauthorised modification of records."),
        ("deleteUser", "This mutation may allow users to delete records without authorization."),
    ],
)
@pytest.mark.parametrize("field", ["interpretation", "manual_follow_up"])
def test_speculative_effects_withheld_without_repair_calls(
    prepared, monkeypatch, name, text, field
):
    scan, context = prepared
    payload = security_answer_fields(context)
    item = next(
        i for i in payload["operation_interpretations"] if i["operation"].endswith("/" + name)
    )
    operation = next(o for o in context.operations if o.name == name)
    assert not operation.attempted
    item[field] = text
    result = interpret_mock(scan, context, payload, monkeypatch)
    assert result.quality_warnings == ("unsupported_review_conclusion",)
    assert text not in str(result)
    assert len(result.withheld_fields) == 1
    retained = next(
        i
        for i in result.interpretation.operation_interpretations
        if i.operation == item["operation"]
    )
    assert getattr(retained, field) == WITHHELD_PROSE
    sibling = "manual_follow_up" if field == "interpretation" else "interpretation"
    assert getattr(retained, sibling) == item[sibling]


@pytest.mark.parametrize(
    "text",
    [
        "Review whether updateUser restricts modifications to authorized users.",
        "Validate whether deleteUser requires authorization for the selected target.",
        "The createAlbum mutation accepts a userId input.",
        "Review whether ownership assignments are authorized.",
        "The user Query accepts an identifier.",
        "Object-level authorization should be reviewed using separate identities.",
        "Runtime authorization was not assessed.",
        "Review whether the operation could expose records outside the caller's permitted scope.",
        "Potential authorization risks should be assessed using different user identities.",
        "The schema exposes a mutation capable of updating user-related objects.",
        "This operation may warrant manual review for unauthorized modifications.",
        "The supplied evidence does not establish that the operation "
        "may allow unauthorized deletion.",
    ],
)
def test_review_hypotheses_and_structural_descriptions_preserved(prepared, text):
    _, context = prepared
    payload = security_answer_fields(context)
    # A supplied structural fact, not a new context attribute or private request input.
    fact = AISecurityFact(
        capability="structural_review",
        category="review_candidate",
        endpoint="endpoint_1",
        kind="mutation",
        name="createAlbum",
        argument="userId",
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload["summary_interpretation"]["references"] = reference_items([], [fact.security_fact_ref])
    item = next(
        i for i in payload["operation_interpretations"] if i["operation"].endswith("/createAlbum")
    )
    item["interpretation"] = text
    original = validate_interpretation(json.dumps(payload), context)
    assert enforce_interpretation_grounding(original, context) == (original, (), ())


@pytest.mark.parametrize(
    "status,attempted,valid",
    [
        ("success", True, True),
        ("graphql_error", True, False),
        ("network_failure", True, False),
        (None, False, False),
    ],
)
def test_completed_without_error_is_exact_execution_fact(prepared, status, attempted, valid):
    _, context = prepared
    context = context.model_copy(
        update={
            "operations": tuple(
                o.model_copy(
                    update={
                        "execution_status": status,
                        "attempted": attempted,
                        "http_status": 200 if status in {"success", "graphql_error"} else None,
                    }
                )
                if o.name == "user"
                else o
                for o in context.operations
            )
        }
    )
    payload = security_answer_fields(context)
    item = next(i for i in payload["operation_interpretations"] if i["operation"].endswith("/user"))
    item["interpretation"] = (
        "The recorded Query completed without a classified execution error. "
        "Object-level authorization remains untested."
    )
    original = validate_interpretation(json.dumps(payload), context)
    filtered, warnings, withheld = enforce_interpretation_grounding(original, context)
    if valid:
        assert filtered == original and warnings == withheld == ()
    else:
        assert "unsupported_execution_claim" in warnings and len(withheld) == 1


def test_each_real_prose_field_checked_once_with_no_global_recheck(prepared, monkeypatch):
    _, context = prepared
    payload = security_answer_fields(context)
    payload["operation_interpretations"][0]["interpretation"] = (
        "The operation may allow unauthorized modifications."
    )
    original = validate_interpretation(json.dumps(payload), context)
    expected = Counter(text for text, _, _ in prose_entries(original))
    checked = Counter()
    collect = quality.collect_interpretation_quality_warnings

    def record(probe, supplied):
        checked.update(text for text, _, _ in prose_entries(probe) if text in expected)
        return collect(probe, supplied)

    monkeypatch.setattr(quality, "collect_interpretation_quality_warnings", record)
    _, _, withheld = enforce_interpretation_grounding(original, context)
    assert checked == expected
    assert len(withheld) == len(set(withheld)) == 1


@pytest.mark.parametrize("extra_follow_up", [False, True])
@pytest.mark.parametrize("timeout", [600, 1200])
def test_twelve_operation_accounting_and_all_output_surfaces(
    phase_ten_scan, monkeypatch, extra_follow_up, timeout
):
    scan, _ = phase_ten_scan(
        "type Query { " + " ".join(f"item{i}: String" for i in range(32)) + " }"
    )
    context = build_ai_context(scan)
    assert (context.metadata.operations_included, context.metadata.operations_omitted) == (12, 20)
    payload = security_answer_fields(context)
    bad = "The operation may allow unauthorized modifications. REJECTED_2B_CANARY."
    for item in payload["operation_interpretations"][:7]:
        item["interpretation"] = bad
    if extra_follow_up:
        payload["operation_interpretations"][0]["manual_follow_up"] = bad
    payload["review_insights"] = [
        {
            "references": reference_items([o.operation for o in context.operations[:2]]),
            "interpretation": bad,
            "manual_follow_up": "Review the intended authorization policy.",
        }
    ]
    result = interpret_mock(scan, context, payload, monkeypatch, timeout=timeout)
    assert result.quality_warnings == ("unsupported_review_conclusion",)
    assert len(result.withheld_fields) == 8 + extra_follow_up
    lines = quality_summary_lines(result)
    assert f"1 warning category; {8 + extra_follow_up} text fields withheld" in lines[0]
    assert "5 retained / 12 supplied; 7 withheld; 7 operations affected" in lines[1]
    assert (
        f"{int(extra_follow_up)} operation "
        f"{'follow-up' if extra_follow_up else 'follow-ups'}; "
        "0 summary; 1 cross-operation; 0 limitations" in lines[2]
    )
    # Duplicate paths and presentation text cannot inflate structured accounting.
    duplicate = replace(result, withheld_fields=result.withheld_fields * 2)
    assert quality_summary_lines(duplicate) == lines
    altered = result.interpretation.model_copy(
        update={
            "summary_interpretation": result.interpretation.summary_interpretation.model_copy(
                update={"text": WITHHELD_PROSE}
            )
        }
    )
    assert quality_summary_lines(replace(result, interpretation=altered)) == lines
    for verbose in (False, True):
        for width in (45, 120):
            stream = StringIO()
            render_ai(
                Console(file=stream, width=width, no_color=True, theme=CONSOLE_THEME),
                result,
                verbose=verbose,
            )
            normalized = " ".join(stream.getvalue().split())
            assert "REJECTED_2B_CANARY" not in normalized
            for line in quality_summary_lines(result, compact=not verbose):
                assert line in normalized
    report = build_report(scan, ai_interpretation=result)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    ai_json = canonical["ai_interpretation"]
    assert canonical["report_schema_version"] == ai_json["ai_contract_version"] == 2
    assert "withheld_fields" not in ai_json
    assert "quality_summary" not in ai_json
    assert ai_json["context_metadata"]["operations_omitted"] == 20
    assert (
        ai_json["context_metadata"]["security_facts_omitted"]
        == context.metadata.security_facts_omitted
    )
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format)
        normalized = re.sub(r"\\([\W_])", lambda m: m[1], html.unescape(rendered))
        assert "REJECTED_2B_CANARY" not in rendered
        assert "AI Quality Summary" in normalized
        assert all(line in normalized for line in lines)
        assert rendered.count("Safety Notice") == 1
        assert normalized.rfind("Safety Notice") > normalized.index("AI Quality Summary")


def test_prompt_and_schema_guide_grounded_concise_roles_without_budget_change(prepared):
    _, context = prepared
    prompt = build_system_prompt(context)
    assert "Start each interpretation with a supplied structural fact" in prompt
    assert "May allow/could enable/potential risk are legitimate conditional analysis" in prompt
    assert "do not repeat one checklist" in prompt
    schema = build_response_schema(context)
    operation = schema["$defs"]["AIOperationInterpretation"]["properties"]
    assert operation["interpretation"]["maxLength"] == 300
    assert operation["manual_follow_up"]["maxLength"] == 220
    assert "One to three concise" in operation["interpretation"]["description"]


def test_scoped_confirmed_finding_survives_without_generalization(prepared):
    _, context = prepared
    fact = AISecurityFact(
        capability="idor_bola",
        category="finding",
        endpoint="endpoint_1",
        kind="query",
        name="user",
        expected="deny",
        finding_type="object_level_authorization_failure",
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"] = {
        "references": reference_items([], [fact.security_fact_ref]),
        "text": "The tested object probe recorded unauthorized object access.",
    }
    original = validate_interpretation(json.dumps(payload), context)
    assert enforce_interpretation_grounding(original, context) == (original, (), ())
    payload["summary_interpretation"]["text"] = "The API may allow unauthorized modifications."
    filtered, warnings, withheld = enforce_interpretation_grounding(
        validate_interpretation(json.dumps(payload), context), context
    )
    assert filtered.summary_interpretation.text == WITHHELD_PROSE
    assert warnings == ("unsupported_review_conclusion",) and len(withheld) == 1


def test_quality_categories_fields_and_affected_operations_are_distinct(prepared, monkeypatch):
    scan, context = prepared
    payload = security_answer_fields(context)
    bad = "The target appears secure. The operation may allow unauthorized modifications."
    payload["summary_interpretation"]["text"] = bad
    payload["limitations"] = [{"references": [], "text": bad}]
    payload["operation_interpretations"][0]["manual_follow_up"] = bad
    result = interpret_mock(scan, context, payload, monkeypatch)
    assert result.quality_warnings == (
        "unsupported_security_assurance",
        "unsupported_review_conclusion",
    )
    assert len(result.withheld_fields) == 3
    lines = quality_summary_lines(result)
    assert "2 warning categories; 3 text fields withheld" in lines[0]
    count = len(context.operations)
    assert f"{count} retained / {count} supplied; 0 withheld; 1 operation affected" in lines[1]
    assert "1 operation follow-up; 1 summary; 0 cross-operation; 1 limitation" in lines[2]


def test_mixed_claim_field_withheld_while_independent_guidance_remains(prepared, monkeypatch):
    scan, context = prepared
    payload = security_answer_fields(context)
    item = payload["operation_interpretations"][0]
    item["interpretation"] = "The schema exposes this operation. It may allow unauthorized edits."
    item["manual_follow_up"] = "Review whether permitted field changes are enforced."
    result = interpret_mock(scan, context, payload, monkeypatch)
    assert result.interpretation.operation_interpretations[0].interpretation == WITHHELD_PROSE
    assert (
        result.interpretation.operation_interpretations[0].manual_follow_up
        == item["manual_follow_up"]
    )
    assert len(result.withheld_fields) == 1
