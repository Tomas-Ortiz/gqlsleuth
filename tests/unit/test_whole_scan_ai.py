"""Whole-scan projection, privacy, bounded priorities and exact AI reference contracts."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import ValidationError

from fixtures.ai_response import security_answer_fields
from fixtures.whole_scan_ai import CANARIES, RAW, SDL, assemble
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import MAX_AI_OPERATIONS, MAX_CONTEXT_BYTES, AIAnalysisStatus, AIContext
from gqlsleuth.ai.prompt import execution_summary, validate_interpretation
from gqlsleuth.ai.security_context import ordered_security_context
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.infrastructure.websocket import WebSocketClient
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def whole(phase_ten_scan):
    return assemble(phase_ten_scan(SDL)[0])


def answer(context):
    payload = {
        **security_answer_fields(context),
        "scan_summary": {
            "text": execution_summary(context),
            "operations": [],
            "security_facts": [],
        },
        "operation_review": [],
        "limitations": [],
    }
    facts = context.security_facts
    if facts:
        payload["security_fact_reviews"] = [
            {
                "security_fact_ref": facts[0].security_fact_ref,
                "interpretation": "The recorded policy result warrants scoped manual validation.",
                "manual_follow_up": "Review the intended policy and retained evidence manually.",
            }
        ]
    return payload


def test_all_supported_capabilities_read_named_semantic_fields(whole):
    before = deepcopy(whole)
    facts, coverage = ordered_security_context(whole.safe_execution, whole)
    by_cap = {}
    for fact in facts:
        by_cap.setdefault(fact.capability.value, []).append(fact)
    assert set(by_cap) == {c.capability.value for c in coverage}
    assert by_cap["multiplicity"][0].multiplicity == 3
    assert by_cap["query_depth"][0].probe_depth == 4
    assert by_cap["query_depth"][0].control_observed
    assert any(f.category == "policy_violation" for f in by_cap["authorization_policy"])
    assert any(f.category == "policy_violation" for f in by_cap["mutation_authorization"])
    assert any(f.category == "policy_violation" for f in by_cap["sensitive_input_validation"])
    assert any(
        f.seed_count == 1 and f.review_candidate_count == 1 for f in by_cap["sequential_discovery"]
    )
    assert any(f.finding_type == "object_level_authorization_failure" for f in by_cap["idor_bola"])
    token = next(f.token for f in by_cap["authentication"] if f.token)
    assert token.algorithm == "HS256" and token.temporal_states == (("exp", "expired"),)
    assert any(f.planned_attempts == 5 for f in by_cap["abuse_controls"])
    assert all(f.path == ("file",) for f in by_cap["file_upload"])
    assert any(f.type_name == "Item" and f.path == ("id",) for f in by_cap["federation"])
    assert any(
        f.acknowledged and f.application_event_count == 1 and f.init_payload_supplied
        for f in by_cap["subscriptions"]
    )
    assert all(f.category == "review_candidate" for f in by_cap["structural_review"])
    assert any(c.state == "partial" for c in coverage)
    assert whole == before


def test_exact_request_privacy_one_inference_no_scanner_actions(whole, monkeypatch):
    before = deepcopy(whole)
    context = build_ai_context(whole)
    requests = []
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("AI triggered target HTTP"))
    monkeypatch.setattr(
        WebSocketClient, "__enter__", lambda *args: pytest.fail("AI opened WebSocket")
    )

    def respond(request):
        requests.append(request)
        outgoing = request.content.decode()
        assert all(
            value not in outgoing for value in (*CANARIES, "example.com", "PRIVATE_WS_URL_CANARY")
        )
        assert all(str(e.evidence_id) not in outgoing for e in whole.evidence)
        payload = json.loads(outgoing)
        assert payload["messages"][1]["content"] == serialize_context(context)
        assert (
            payload["model"] == "qwen3:8b"
            and payload["stream"] is False
            and payload["think"] is False
        )
        assert payload["options"] == {"temperature": 0, "num_ctx": 8192, "num_predict": 2048}
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        assert AIContext.model_validate_json(payload["messages"][1]["content"]) == context
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "message": {"role": "assistant", "content": json.dumps(answer(context))},
            },
        )

    result = interpret_completed_scan(
        whole, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.SUCCESS and len(requests) == 1
    assert whole == before and whole.evidence == before.evidence
    assert context.metadata.deterministic_findings == 6
    assert context.metadata.policy_violations == 9
    assert context.metadata.serialized_bytes == len(serialize_context(context).encode())
    assert context.metadata.serialized_bytes <= MAX_CONTEXT_BYTES


def test_oversized_findings_take_capacity_before_candidates_and_operations(whole):
    auth = whole.authentication_token_security
    auth = replace(
        auth, findings=tuple(replace(auth.findings[0], operation=f"lookup{i}") for i in range(200))
    )
    oversized = replace(whole, authentication_token_security=auth)
    first = build_ai_context(oversized)
    assert serialize_context(first) == serialize_context(build_ai_context(oversized))
    assert not first.operations and all(f.category == "finding" for f in first.security_facts)
    assert first.metadata.security_facts_omitted > 0 and first.metadata.context_truncated
    assert (
        first.metadata.security_facts_total
        == first.metadata.security_facts_included + first.metadata.security_facts_omitted
    )
    assert (
        len(serialize_context(first).encode())
        == first.metadata.serialized_bytes
        <= MAX_CONTEXT_BYTES
    )
    assert MAX_AI_OPERATIONS == 12 and MAX_CONTEXT_BYTES == 12_000


@pytest.mark.parametrize(
    "change",
    [
        "unknown_summary",
        "unknown_review",
        "unknown_control",
        "unknown_cross",
        "duplicate_cross",
        "one_cross",
        "missing_ref",
        "extra",
        "oversized",
        "same_capability",
        "not_a_control",
        "duplicate_review",
        "empty_summary_refs",
        "long_limitation",
        "unknown_limitation",
    ],
)
def test_invalid_security_reference_or_structure_rejects_entire_answer(whole, change):
    context = build_ai_context(whole)
    payload = answer(context)
    refs = [f.security_fact_ref for f in context.security_facts]
    if change == "unknown_summary":
        payload["security_summary"]["security_facts"] = ["SF99999"]
    elif change == "unknown_review":
        payload["security_fact_reviews"][0]["security_fact_ref"] = "SF99999"
    elif change == "unknown_control":
        payload["control_observations"] = [{"security_fact_ref": "SF99999", "text": "Scoped."}]
    elif change in {"unknown_cross", "duplicate_cross", "one_cross", "same_capability"}:
        selected = (
            [refs[0], "SF99999"]
            if change == "unknown_cross"
            else [refs[0], refs[0]]
            if change == "duplicate_cross"
            else [refs[0]]
        )
        if change == "same_capability":
            group = next(
                [f.security_fact_ref for f in context.security_facts if f.capability == cap]
                for cap in {f.capability for f in context.security_facts}
                if sum(f.capability == cap for f in context.security_facts) >= 2
            )
            selected = group[:2]
        payload["cross_capability_insights"] = [
            {"security_facts": selected, "text": "May warrant joint review."}
        ]
    elif change == "missing_ref":
        del payload["security_fact_reviews"][0]["security_fact_ref"]
    elif change == "extra":
        payload["finding"] = "Invented vulnerability"
    elif change == "not_a_control":
        payload["control_observations"] = [{"security_fact_ref": refs[0], "text": "Scoped."}]
    elif change == "duplicate_review":
        payload["security_fact_reviews"] *= 2
    elif change == "empty_summary_refs":
        payload["security_summary"]["security_facts"] = []
    elif change in {"long_limitation", "unknown_limitation"}:
        payload["limitations"] = [
            {
                "text": "x" * 501 if change == "long_limitation" else "Unknown scope.",
                "operations": [],
                "security_facts": [] if change == "long_limitation" else ["SF99999"],
            }
        ]
    else:
        payload["security_summary"]["text"] = "x" * 801
    with pytest.raises((ValueError, ValidationError)):
        validate_interpretation(json.dumps(payload), context)


def test_valid_correlation_and_scoped_control_are_only_interpretation(whole):
    context = build_ai_context(whole)
    payload = answer(context)
    first = context.security_facts[0]
    second = next(f for f in context.security_facts if f.capability != first.capability)
    control = next(f for f in context.security_facts if f.control_observed)
    payload["cross_capability_insights"] = [
        {
            "security_facts": [first.security_fact_ref, second.security_fact_ref],
            "text": "These observations may warrant joint manual review.",
        }
    ]
    payload["control_observations"] = [
        {
            "security_fact_ref": control.security_fact_ref,
            "text": "The exact bounded probe encountered a scoped control.",
        }
    ]
    output = validate_interpretation(json.dumps(payload), context)
    assert len(output.cross_capability_insights) == 1
    assert not hasattr(output, "findings") and not hasattr(output, "evidence")


def test_human_ai_sections_escape_prose_and_preserve_deterministic_reports(whole):
    context = build_ai_context(whole)
    payload = answer(context)
    payload["security_summary"]["text"] = '<script>alert("test")</script> Model interpretation.'
    client = OllamaClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "model": "qwen3:8b",
                    "done": True,
                    "message": {"role": "assistant", "content": json.dumps(payload)},
                },
            )
        )
    )
    interpretation = interpret_completed_scan(whole, client=client)
    timestamp = datetime(2026, 9, 25, tzinfo=UTC)
    before = build_report(whole, generated_at=timestamp)
    after = build_report(whole, generated_at=timestamp, ai_interpretation=interpretation)
    raw = json.loads(render_report(after, ReportFormat.JSON))
    ai = raw.pop("ai_interpretation")
    assert raw == json.loads(render_report(before, ReportFormat.JSON))
    assert "security_fact_reviews" in ai["interpretation"] and "security_facts" not in ai
    for kind in (ReportFormat.HTML, ReportFormat.MARKDOWN):
        text = render_report(after, kind)
        for title in (
            "Security Summary",
            "Security Fact Reviews",
            "Security Controls Observed",
            "Cross-Capability Analysis",
        ):
            assert title in text.replace("\\-", "-")
        assert "<script>alert" not in text
        assert text.count("Safety Notice") == 1 and text.rfind("Safety Notice") > text.rfind(
            "AI-Assisted Interpretation"
        )


def test_projection_failure_is_controlled_without_inference(whole, monkeypatch):
    altered = replace(
        whole.authentication_token_security,
        token_review=replace(whole.authentication_token_security.token_review, algorithm=RAW),
    )
    monkeypatch.setattr(OllamaClient, "interpret", lambda *args: pytest.fail("Unsafe context sent"))
    result = interpret_completed_scan(replace(whole, authentication_token_security=altered))
    assert (
        result.status is AIAnalysisStatus.INVALID_RESPONSE
        and result.error_code == "invalid_context"
    )
    assert RAW not in str(result)


def test_coverage_distinguishes_disabled_prepared_and_local_only(whole):
    safe = build_ai_context(whole.safe_execution)
    assert (
        next(c for c in safe.capability_coverage if c.capability == "subscriptions").state
        == "not_enabled"
    )
    assert (
        next(c for c in safe.capability_coverage if c.capability == "structural_review").state
        == "local_only"
    )
    prepared = replace(
        whole, subscription_security=replace(whole.subscription_security, attempts=(), findings=())
    )
    context = build_ai_context(prepared)
    assert (
        next(c for c in context.capability_coverage if c.capability == "subscriptions").state
        == "prepared"
    )
    assert context.metadata.differential_ai_supported is False


def test_all_nine_structural_candidates_are_safe_enums(phase_ten_scan):
    from fixtures.phase16_smoke import SDL as REVIEW_SDL
    from gqlsleuth.domain.security_review import SecurityCandidateType

    safe, _ = phase_ten_scan(REVIEW_SDL)
    facts, _ = ordered_security_context(safe, None)
    structural = [f for f in facts if f.capability == "structural_review"]
    assert {f.candidate_type for f in structural} == set(SecurityCandidateType)
    assert all(f.category == "review_candidate" and f.finding_type is None for f in structural)


def test_fact_order_is_stable_and_complete_counts_survive_truncation(whole):
    facts, _ = ordered_security_context(whole.safe_execution, whole)

    def tier(f):
        if f.category == "finding":
            return 0
        if f.category == "policy_violation":
            return 1
        if f.category == "policy_satisfied" or f.control_observed:
            return 2
        return 4 if f.category == "review_candidate" else 3

    assert [tier(f) for f in facts] == sorted(tier(f) for f in facts)
    assert [f.security_fact_ref for f in facts] == [f"SF{i}" for i in range(1, len(facts) + 1)]
    assert facts == ordered_security_context(whole.safe_execution, whole)[0]
    context = build_ai_context(whole)
    assert context.metadata.security_facts_total == len(facts)
    assert context.counts["policy_violations"] == sum(f.evaluation == "violated" for f in facts)


@pytest.mark.parametrize(
    "outcome,expected",
    [
        ("no_event_before_timeout", "observe"),
        ("explicit_denial", "deny"),
        ("network_failure", "deny"),
    ],
)
def test_subscription_outcomes_preserve_scoped_semantics(whole, outcome, expected):
    from gqlsleuth.domain.authorization_policy import PolicyStatus
    from gqlsleuth.domain.subscriptions import SubscriptionOutcome, SubscriptionPolicy

    result = whole.subscription_security
    attempt = result.attempts[0]
    evaluation = (
        None
        if expected == "observe"
        else (PolicyStatus.SATISFIED if outcome == "explicit_denial" else PolicyStatus.UNRESOLVED)
    )
    plan = replace(attempt.plan, policy=SubscriptionPolicy(expected))
    attempt = attempt.model_copy(
        update={
            "plan": plan,
            "outcome": SubscriptionOutcome(outcome),
            "evaluation": evaluation,
            "application_event_count": 0,
        }
    )
    result = replace(result, plan=plan, attempts=(attempt,), findings=())
    context = build_ai_context(replace(whole, subscription_security=result))
    facts = [f for f in context.security_facts if f.capability == "subscriptions"]
    assert len(facts) == 1
    fact = facts[0]
    assert fact.outcome == outcome and fact.expected == expected and fact.evaluation == evaluation
    assert fact.control_observed is (outcome == "explicit_denial")
    assert fact.category != "finding"


def test_safe_identifiers_and_unsupported_differential_fail_closed(phase_ten_scan, monkeypatch):
    from gqlsleuth.ai.identifiers import identifier, identifier_path
    from gqlsleuth.application.differential_review import ContextScanResult, compare_context_scans
    from gqlsleuth.domain.models import ScanMode

    for value in ("https://private.test", "lookup;ignore", "x" * 129, "\nprivate"):
        assert identifier(value) is None and identifier_path(("input", value)) == ()
    safe, _ = phase_ten_scan(SDL, mode=ScanMode.SAFE)
    discovery = (
        safe.query_generation.operation_analysis.schema_scan.introspection.detection.discovery
    )
    differential = compare_context_scans(
        discovery.target,
        (
            ContextScanResult("one", safe),
            ContextScanResult("two", safe),
        ),
    )
    monkeypatch.setattr(
        OllamaClient, "interpret", lambda *args: pytest.fail("Differential inference")
    )
    result = interpret_completed_scan(differential)
    assert result.status is AIAnalysisStatus.INVALID_RESPONSE


def test_whole_scan_prompt_keeps_ordinary_totals_scoped(whole):
    from gqlsleuth.ai.prompt import build_system_prompt

    context = build_ai_context(whole)
    assert context.counts["mutation_requests"] == 0
    assert any(f.capability == "file_upload" for f in context.security_facts)
    prompt = build_system_prompt(context)
    assert "ZERO ordinary Phase 10 Mutations" in prompt
    assert "Separately consented capability probes may have executed Mutations" in prompt
    assert "NO_EVENT_BEFORE_TIMEOUT != authorization enforcement" in prompt
    assert "Correlation is model interpretation" in prompt
