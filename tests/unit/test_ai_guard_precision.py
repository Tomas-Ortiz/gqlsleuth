"""Final Phase 2 audit regressions: qualified propositions and content-free decisions."""

import json
from copy import deepcopy
from dataclasses import asdict, replace

import httpx
import pytest

from fixtures.ai_response import reference_items, security_answer_fields
from gqlsleuth.ai import quality
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIAnalysisStatus
from gqlsleuth.ai.prompt import QUALITY_WARNING_ORDER, validate_interpretation
from gqlsleuth.ai.quality import WITHHELD_PROSE, enforce_interpretation_grounding
from gqlsleuth.ai.sections import quality_summary_lines
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def prepared(phase_ten_scan):
    scan, _ = phase_ten_scan(
        """
        type Query { user(id: ID!): User users: [User] }
        type User { id: ID friends: [User] }
        input AlbumInput { userId: ID! title: String }
        type Mutation {
            createUser: User updateUser(userId: ID!): User
            createAlbum(input: AlbumInput!): User
        }
        """,
        mode=ScanMode.SAFE,
    )
    return scan, build_ai_context(scan)


def payload_for(context, name, text):
    payload = security_answer_fields(context)
    item = next(
        i for i in payload["operation_interpretations"] if i["operation"].endswith("/" + name)
    )
    item["interpretation"] = text
    return payload


def enforce(context, payload):
    return enforce_interpretation_grounding(
        validate_interpretation(json.dumps(payload), context), context
    )


@pytest.mark.parametrize(
    "name,text",
    [
        (
            "createUser",
            "If authorization is insufficient, createUser could allow unauthorized account "
            "creation.",
        ),
        (
            "createUser",
            "createUser could allow unauthorized account creation if authorization is "
            "insufficient.",
        ),
        (
            "createUser",
            "createUser, if authorization is insufficient, could allow unauthorized "
            "account creation.",
        ),
        (
            "createAlbum",
            "If ownership validation is insufficient, createAlbum could allow unauthorized "
            "ownership changes.",
        ),
        (
            "createAlbum",
            "createAlbum could allow unauthorized ownership changes if ownership "
            "validation is insufficient.",
        ),
        (
            "createAlbum",
            "createAlbum, if ownership validation is insufficient, could allow "
            "unauthorized ownership changes.",
        ),
        (
            "updateUser",
            "Without adequate object-level authorization, updateUser may permit "
            "modifications outside the caller's scope.",
        ),
        (
            "updateUser",
            "Unauthorized modifications may be possible if the server does not enforce "
            "target ownership.",
        ),
        (
            "users",
            "Recursive relationships could increase query cost if the server does not "
            "adequately enforce complexity or depth constraints.",
        ),
        ("user", "The user Query accepts an ID argument."),
        ("user", "The user Query accepts an identifier argument."),
        ("user", "The user Query accepts an id argument."),
        ("users", "The users Query returns a list of objects."),
        ("users", "The users Query returns a list of records."),
        ("users", "The users Query returns a list of User objects."),
        ("users", "The users Query returns a list of `User` objects."),
        ("createUser", "This operation appears to create accounts."),
        ("user", "The schema suggests this Query returns user data."),
        ("createUser", "The createUser mutation appears to expose user-creation functionality."),
        ("createAlbum", "The createAlbum mutation accepts an input.userId field."),
        ("user", "The user Query accepts an Int argument."),
        ("user", "The user Query accepts a String argument."),
    ],
)
def test_qualified_and_generic_descriptions_are_preserved(prepared, name, text):
    _, context = prepared
    payload = payload_for(context, name, text)
    filtered, warnings, decisions = enforce(context, payload)
    assert warnings == decisions == ()
    assert filtered.model_dump(mode="json") == payload


@pytest.mark.parametrize(
    "name,text,code",
    [
        ("user", "The user Query accepts a password argument.", "unsupported_review_conclusion"),
        ("user", "The user Query accepts an `ID` argument.", "unsupported_review_conclusion"),
        (
            "user",
            "The user Query accepts an `identifier` argument.",
            "unsupported_review_conclusion",
        ),
        (
            "users",
            "The users Query returns a list of Country objects.",
            "unsupported_review_conclusion",
        ),
        ("users", "The users Query returns a list of `objects`.", "unsupported_review_conclusion"),
        ("user", "The user Query returns a list of objects.", "unsupported_review_conclusion"),
        (
            "createAlbum",
            "The createAlbum mutation accepts an input.password field.",
            "unsupported_review_conclusion",
        ),
        (
            "createUser",
            "The createUser mutation successfully created an account.",
            "unsupported_execution_claim",
        ),
        (
            "createUser",
            "The createUser mutation allows any caller to create arbitrary accounts.",
            "unsupported_review_conclusion",
        ),
        (
            "createUser",
            "createUser could allow unauthorized account creation.",
            "unsupported_review_conclusion",
        ),
        (
            "createUser",
            "createUser could allow unauthorized account creation if ownership validation "
            "is insufficient.",
            "unsupported_review_conclusion",
        ),
        (
            "users",
            "If authorization is insufficient, this Query could allow unauthorized access "
            "and returns a list of Country objects.",
            "unsupported_review_conclusion",
        ),
        (
            "user",
            "If authorization is insufficient, this operation could allow unauthorized "
            "access and accepts a password argument.",
            "unsupported_review_conclusion",
        ),
        (
            "user",
            "Review whether authentication is enforced, and the target has no "
            "authorization controls.",
            "unsupported_control_claim",
        ),
        (
            "createAlbum",
            "If ownership validation is insufficient, createAlbum could permit "
            "unauthorized owner assignments, and the mutation was successfully executed.",
            "unsupported_execution_claim",
        ),
        (
            "users",
            "If authorization is insufficient, this Query could allow unauthorized access "
            "and is a confirmed vulnerability.",
            "unsupported_review_conclusion",
        ),
        (
            "user",
            "Review whether this Query accepts an identifier argument, and accepts a "
            "password argument.",
            "unsupported_review_conclusion",
        ),
        (
            "user",
            "The Query returned private data to an unauthorized caller.",
            "unsupported_review_conclusion",
        ),
        (
            "users",
            "Review whether this Query returns a list of objects, and returns a list of "
            "Country objects.",
            "unsupported_review_conclusion",
        ),
        (
            "users",
            "If authorization is insufficient, this Query could allow unauthorized access "
            "and the Query returns [Country!]!.",
            "unsupported_review_conclusion",
        ),
        (
            "createUser",
            "If authorization is insufficient, createUser could allow unauthorized account "
            "creation and has no rate limits.",
            "unsupported_control_claim",
        ),
    ],
)
def test_independent_contradictions_withhold_only_the_field(prepared, name, text, code):
    _, context = prepared
    payload = payload_for(context, name, text)
    expected = deepcopy(payload)
    index = next(
        i
        for i, entry in enumerate(expected["operation_interpretations"])
        if entry["operation"].endswith("/" + name)
    )
    expected["operation_interpretations"][index]["interpretation"] = WITHHELD_PROSE
    filtered, warnings, decisions = enforce(context, payload)
    assert code in warnings
    assert filtered.model_dump(mode="json") == expected
    assert len(decisions) == 1
    assert decisions[0].index == index
    assert code in decisions[0].rule_codes


@pytest.mark.parametrize(
    "section", ["summary_interpretation", "review_insights", "limitations", "manual_follow_up"]
)
def test_assertion_scope_applies_to_every_prose_section(prepared, section):
    _, context = prepared
    payload = security_answer_fields(context)
    refs = reference_items([o.operation for o in context.operations if o.kind == "query"])
    text = (
        "Review whether authentication is enforced, and the target has no authorization controls."
    )
    if section == "summary_interpretation":
        payload[section] = {"text": text, "references": refs}
    elif section == "review_insights":
        payload[section] = [
            {
                "interpretation": text,
                "manual_follow_up": "Inspect intended access requirements.",
                "references": refs,
            }
        ]
    elif section == "limitations":
        payload[section] = [{"text": text, "references": refs}]
    else:
        payload["operation_interpretations"][0][section] = text
    _, warnings, decisions = enforce(context, payload)
    assert "unsupported_control_claim" in warnings
    assert len(decisions) == 1


def test_truncated_input_inventory_does_not_prove_absence(prepared):
    _, context = prepared
    context = context.model_copy(
        update={
            "operations": tuple(
                o.model_copy(
                    update={
                        "schema_structure": o.schema_structure.model_copy(
                            update={"inputs_truncated": True}
                        )
                    }
                )
                if o.name == "user"
                else o
                for o in context.operations
            )
        }
    )
    payload = payload_for(context, "user", "The user Query accepts a password argument.")
    filtered, warnings, decisions = enforce(context, payload)
    assert warnings == decisions == ()
    assert filtered.model_dump(mode="json") == payload


def test_qualified_role_must_match_referenced_operation(phase_ten_scan):
    scan, _ = phase_ten_scan(
        "type Query { country(code: ID!): Country } type Country { code: ID }",
        mode=ScanMode.SAFE,
    )
    context = build_ai_context(scan)
    payload = payload_for(context, "country", "The schema suggests this Query returns user data.")
    _, warnings, decisions = enforce(context, payload)
    assert "unsupported_review_conclusion" in warnings
    assert len(decisions) == 1


def test_diagnostics_use_one_pass_and_remain_internal(prepared, monkeypatch):
    scan, context = prepared
    before = deepcopy(scan)
    payload = payload_for(
        context,
        "createUser",
        "The mutation executed successfully and has no authorization controls.",
    )
    calls = []
    original = quality.collect_interpretation_quality_warnings

    def collect(probe, supplied):
        calls.append(probe)
        return original(probe, supplied)

    monkeypatch.setattr(quality, "collect_interpretation_quality_warnings", collect)
    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "done_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(payload)},
            },
        )

    monkeypatch.setattr(HttpClient, "send", lambda *a, **kw: pytest.fail("Target request"))
    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(requests) == 1
    assert len(calls) == 1 + 2 * len(context.operations)
    assert requests[0]["messages"][1]["content"] == serialize_context(context)
    assert scan == before and scan.evidence == before.evidence
    assert len(result.withheld_fields) == 1
    decision = result.withheld_fields[0]
    assert decision.rule_codes == tuple(
        code
        for code in QUALITY_WARNING_ORDER
        if code in {"unsupported_control_claim", "unsupported_execution_claim"}
    )
    assert set(asdict(decision)) == {"section", "index", "field", "rule_codes"}
    assert decision == replace(decision, rule_codes=())
    assert len(set((decision, replace(decision, rule_codes=())))) == 1
    assert result.interpretation.operation_interpretations[decision.index].operation.endswith(
        "/createUser"
    )
    assert quality_summary_lines(result)
    report = build_report(scan, ai_interpretation=result)
    for format in ReportFormat:
        rendered = render_report(report, format)
        assert "rule_codes" not in rendered and "withheld_fields" not in rendered
        assert (
            payload["operation_interpretations"][decision.index]["interpretation"] not in rendered
        )
