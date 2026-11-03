"""Offline shared-result enforcement: no renderer can revive withheld model assertions."""

import json
import re
from copy import deepcopy
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.ai_response import reference_items, security_answer_fields
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AIAnalysisStatus, AIInterpretation, AISecurityFact
from gqlsleuth.ai.prompt import validate_interpretation
from gqlsleuth.ai.quality import WITHHELD_PROSE, enforce_interpretation_grounding
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def prepared(phase_ten_scan):
    scan, _ = phase_ten_scan(
        "type Query { user(id: ID!): User } type User { id: ID } "
        "type Mutation { createUser: User createAlbum(userId: ID!): User }",
        mode=ScanMode.SAFE,
    )
    context = build_ai_context(scan)
    return scan, context


def operation_reply(context, text, *, name="createUser", field="interpretation"):
    payload = security_answer_fields(context)
    item = next(i for i in payload["operation_interpretations"] if i["operation"].endswith(name))
    item[field] = text
    return payload


@pytest.mark.parametrize(
    "text",
    [
        "This mutation lacks authorization checks.",
        "This mutation lacks input validation.",
        "This operation lacks ownership validation.",
        "The API allows unauthorized access.",
        "Users can modify other users' records.",
        "The endpoint is vulnerable to IDOR.",
        "There are no rate limits.",
        "The server has no query-depth controls.",
        "The server accepts unlimited alias batching.",
        "The server accepts unrestricted query depth.",
        "Batching is universally prevented.",
        "The mutation bypasses authorization.",
        "The business logic succeeded.",
        "The changes were persisted.",
        "The mutation executed successfully.",
        "The mutation was rejected by server validation.",
    ],
)
@pytest.mark.parametrize("field", ["interpretation", "manual_follow_up"])
def test_unsupported_field_withheld_siblings_preserved(prepared, text, field):
    scan, context = prepared
    before = deepcopy(scan)
    payload = operation_reply(context, text, field=field)
    original = validate_interpretation(json.dumps(payload), context)
    filtered, warnings, _ = enforce_interpretation_grounding(original, context)
    assert warnings
    assert text not in filtered.model_dump_json()
    changed = next(
        i for i in filtered.operation_interpretations if i.operation.endswith("createUser")
    )
    assert getattr(changed, field) == WITHHELD_PROSE
    sibling = "manual_follow_up" if field == "interpretation" else "interpretation"
    other = next(i for i in original.operation_interpretations if i.operation == changed.operation)
    assert getattr(changed, sibling) == getattr(other, sibling)
    assert filtered.summary_interpretation == original.summary_interpretation
    assert tuple(
        i for i in filtered.operation_interpretations if i.operation != changed.operation
    ) == tuple(i for i in original.operation_interpretations if i.operation != changed.operation)
    assert scan == before
    assert AIInterpretation.model_validate_json(filtered.model_dump_json(), strict=True) == filtered


@pytest.mark.parametrize(
    "text",
    [
        "Review whether createUser enforces server-side authorization.",
        "Validate ownership checks for input.userId.",
        "Consider testing object-level authorization with separate identities.",
        "The schema exposes a Query accepting an ID argument.",
        "Manual validation is needed to determine whether the server enforces result limits.",
        "Review whether authorization is missing.",
        "Review whether this operation lacks ownership validation.",
        "The createAlbum mutation accepts a userId input. Review whether server-side authorization "
        "prevents the caller from assigning an unauthorized owner.",
        "Authorization and ownership behavior were not assessed.",
        "Acceptance does not establish unlimited aliases.",
    ],
)
def test_hypotheses_and_schema_descriptions_unchanged(prepared, text):
    _, context = prepared
    # An explicit declared-input statement belongs to its actual operation.
    name = "createAlbum" if text.startswith("The createAlbum mutation accepts") else "createUser"
    original = validate_interpretation(
        json.dumps(operation_reply(context, text, name=name)), context
    )
    filtered, warnings, _ = enforce_interpretation_grounding(original, context)
    assert filtered == original
    assert warnings == ()


@pytest.mark.parametrize("section", ["summary", "operation", "follow_up", "insight", "limitation"])
def test_mocked_application_all_renderers_never_retain_rejected_prose(prepared, section):
    scan, context = prepared
    before = deepcopy(scan)
    text = "This mutation lacks ownership validation. REJECTED_TEXT_CANARY."
    payload = security_answer_fields(context)
    refs = reference_items([o.operation for o in context.operations[:2]])
    if section == "summary":
        payload["summary_interpretation"]["text"] = text
    elif section in {"operation", "follow_up"}:
        field = "interpretation" if section == "operation" else "manual_follow_up"
        payload["operation_interpretations"][0][field] = text
    elif section == "insight":
        payload["review_insights"] = [
            {
                "references": refs,
                "interpretation": text,
                "manual_follow_up": "Review intended access requirements.",
            }
        ]
    else:
        payload["limitations"] = [{"references": refs, "text": text}]
    calls = []

    def respond(request):
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        calls.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "done_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(payload)},
            },
        )

    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert len(calls) == result.attempt_count == 1
    assert result.validation_failures == ()
    assert "unsupported_control_claim" in result.quality_warnings
    assert "REJECTED_TEXT_CANARY" not in str(result)
    assert scan == before and scan.evidence == before.evidence
    for verbose in (False, True):
        stream = StringIO()
        render_ai(
            Console(file=stream, no_color=True, width=120, theme=CONSOLE_THEME),
            result,
            verbose=verbose,
        )
        assert "REJECTED_TEXT_CANARY" not in stream.getvalue()
        if verbose or section == "summary":
            assert "AI text withheld:" in " ".join(stream.getvalue().split())
    report = build_report(scan, ai_interpretation=result)
    for format in ReportFormat:
        rendered = render_report(report, format)
        assert "REJECTED_TEXT_CANARY" not in rendered
        normalized = re.sub(r"\\([\W_])", lambda match: match[1], rendered)
        assert WITHHELD_PROSE in normalized
        if format is not ReportFormat.JSON:
            assert normalized.rfind("Safety Notice") > normalized.find(WITHHELD_PROSE)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert (
        canonical["report_schema_version"]
        == canonical["ai_interpretation"]["ai_contract_version"]
        == 2
    )


@pytest.mark.parametrize("partial", [False, True])
def test_bounded_context_is_not_complete_ai_review(phase_ten_scan, partial):
    scan, _ = phase_ten_scan(
        "type Query { " + " ".join(f"item{i}: String" for i in range(32)) + " }"
    )
    context = build_ai_context(scan)
    assert (context.metadata.operations_included, context.metadata.operations_omitted) == (12, 20)
    if partial:
        context = context.model_copy(
            update={
                "schemas": tuple(
                    s.model_copy(update={"schema_retrieval": "partial"}) for s in context.schemas
                )
            }
        )
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = "All 32 operations were analyzed by AI."
    filtered, warnings, _ = enforce_interpretation_grounding(
        validate_interpretation(json.dumps(payload), context), context
    )
    assert filtered.summary_interpretation.text == WITHHELD_PROSE
    assert "unsupported_review_conclusion" in warnings
    payload["summary_interpretation"]["text"] = (
        "Only the 12 supplied operations are considered; "
        "20 omitted operations remain outside this interpretation."
    )
    original = validate_interpretation(json.dumps(payload), context)
    assert enforce_interpretation_grounding(original, context) == (original, (), ())


def test_full_schema_remains_full_despite_bounded_ai_input(prepared):
    _, context = prepared
    context = context.model_copy(
        update={
            "metadata": context.metadata.model_copy(
                update={
                    "operations_total": 32,
                    "operations_included": 12,
                    "operations_omitted": 20,
                    "context_truncated": True,
                }
            )
        }
    )
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = (
        "Schema coverage is complete. AI interpretation covers only the supplied subset."
    )
    original = validate_interpretation(json.dumps(payload), context)
    assert enforce_interpretation_grounding(original, context) == (original, (), ())


def test_matching_control_fact_does_not_prove_universal_protection(prepared):
    _, context = prepared
    fact = AISecurityFact(
        capability="authorization_policy",
        category="policy_satisfied",
        expected="deny",
        evaluation="satisfied",
        control_observed=True,
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = "Authorization is enforced for all users."
    filtered, warnings, _ = enforce_interpretation_grounding(
        validate_interpretation(json.dumps(payload), context), context
    )
    assert filtered.summary_interpretation.text == WITHHELD_PROSE
    assert "unsupported_control_claim" in warnings


def test_scoped_probe_inside_insight_uses_probe_not_ordinary_outcome(prepared):
    _, context = prepared
    operation = next(o for o in context.operations if o.name == "user")
    fact = AISecurityFact(
        endpoint="endpoint_1",
        kind="query",
        name="user",
        capability="multiplicity",
        category="security_observation",
        outcome="accepted",
        probe="alias_multiplicity",
        multiplicity=3,
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload = security_answer_fields(context)
    payload["review_insights"] = [
        {
            "references": reference_items([operation.operation], [fact.security_fact_ref]),
            "interpretation": "The tested request containing three aliases was accepted.",
            "manual_follow_up": "Review the intended server policy for this bounded probe.",
        }
    ]
    original = validate_interpretation(json.dumps(payload), context)
    assert enforce_interpretation_grounding(original, context) == (original, (), ())


@pytest.mark.parametrize(
    "capability,probe,count_field,count,scope",
    [
        ("multiplicity", "alias_multiplicity", "multiplicity", 3, "three aliases"),
        ("query_depth", None, "probe_depth", 5, "depth five"),
    ],
)
def test_scoped_probe_observation_remains_usable(
    prepared, capability, probe, count_field, count, scope
):
    _, context = prepared
    fact = AISecurityFact(
        capability=capability,
        category="security_observation",
        outcome="accepted",
        probe=probe,
        **{count_field: count},
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = (
        f"The tested request containing {scope} was accepted. "
        "This does not establish the server's maximum supported threshold."
    )
    original = validate_interpretation(json.dumps(payload), context)
    assert enforce_interpretation_grounding(original, context) == (original, (), ())


@pytest.mark.parametrize("quantity,outcome", [(4, "accepted"), (3, "rejected")])
def test_probe_fact_does_not_support_other_quantity_or_outcome(prepared, quantity, outcome):
    _, context = prepared
    fact = AISecurityFact(
        capability="multiplicity",
        category="security_observation",
        outcome="accepted",
        probe="alias_multiplicity",
        multiplicity=3,
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = (
        f"The tested request containing {quantity} aliases was {outcome}."
    )
    filtered, warnings, _ = enforce_interpretation_grounding(
        validate_interpretation(json.dumps(payload), context), context
    )
    assert filtered.summary_interpretation.text == WITHHELD_PROSE
    assert "unsupported_execution_claim" in warnings


@pytest.mark.parametrize(
    "state,attempted,http,text,valid",
    [
        (None, False, None, "The mutation was accepted.", False),
        (None, False, None, "Runtime behavior was not observed for the mutation.", True),
        (
            "success",
            True,
            200,
            "The mutation returned a successful execution classification.",
            True,
        ),
        ("success", True, 200, "The mutation persisted changes.", False),
        ("success", True, 200, "No GraphQL error was observed in this test.", True),
        ("graphql_error", True, 200, "The mutation succeeded.", False),
        ("graphql_error", True, 200, "The mutation returned a GraphQL error.", True),
        ("network_failure", True, None, "The server rejected the mutation.", False),
        ("network_failure", True, None, "NETWORK_FAILURE was recorded.", True),
        ("skipped_safety", False, None, "The server blocked the mutation.", False),
    ],
)
def test_operation_execution_grounding_is_enforced(prepared, state, attempted, http, text, valid):
    _, context = prepared
    context = context.model_copy(
        update={
            "operations": tuple(
                o.model_copy(
                    update={"execution_status": state, "attempted": attempted, "http_status": http}
                )
                if o.name == "createUser"
                else o
                for o in context.operations
            )
        }
    )
    original = validate_interpretation(json.dumps(operation_reply(context, text)), context)
    filtered, warnings, _ = enforce_interpretation_grounding(original, context)
    if valid:
        assert filtered == original and warnings == ()
    else:
        assert text not in filtered.model_dump_json() and warnings


def test_finding_is_not_blanket_authorization_for_unrelated_conclusions(prepared):
    _, context = prepared
    fact = AISecurityFact(
        capability="idor_bola",
        category="finding",
        expected="deny",
        finding_type="object_level_authorization_failure",
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = (
        "The tested object probe observed unauthorized object access."
    )
    original = validate_interpretation(json.dumps(payload), context)
    assert enforce_interpretation_grounding(original, context) == (original, (), ())
    payload["summary_interpretation"]["text"] = "The endpoint is vulnerable to IDOR."
    filtered, _, _ = enforce_interpretation_grounding(
        validate_interpretation(json.dumps(payload), context), context
    )
    assert filtered.summary_interpretation.text == WITHHELD_PROSE


@pytest.mark.parametrize("partial", [True, False])
def test_partial_or_unavailable_schema_is_not_zero_or_complete_coverage(prepared, partial):
    _, context = prepared
    context = context.model_copy(
        update={
            "schemas": tuple(
                s.model_copy(update={"schema_retrieval": "partial"}) for s in context.schemas
            )
            if partial
            else ()
        }
    )
    for text in ("Schema coverage is complete.", "The schema exposes no queries."):
        payload = security_answer_fields(context)
        payload["summary_interpretation"]["text"] = text
        filtered, warnings, _ = enforce_interpretation_grounding(
            validate_interpretation(json.dumps(payload), context), context
        )
        assert filtered.summary_interpretation.text == WITHHELD_PROSE
        assert "unsupported_review_conclusion" in warnings
