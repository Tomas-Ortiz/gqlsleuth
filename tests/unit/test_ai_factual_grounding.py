"""Offline coverage eligibility and advisory grounding of exact deterministic subjects."""

import json
from copy import deepcopy
from dataclasses import replace
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.ai_response import reference_items, security_answer_fields
from fixtures.whole_scan_ai import CANARIES, SDL, assemble
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import MAX_CONTEXT_BYTES, AIAnalysisStatus, AISecurityFact
from gqlsleuth.ai.prompt import collect_interpretation_quality_warnings, validate_interpretation
from gqlsleuth.application import ai_assistance
from gqlsleuth.application.graphql_detection import discover_and_detect_graphql
from gqlsleuth.application.introspection import introspect_detected_endpoints
from gqlsleuth.application.operation_analysis import analyze_schema_results
from gqlsleuth.application.query_generation import generate_analyzed_queries
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.application.schema_parsing import parse_introspection_schemas
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.graphql.introspection import SchemaRetrievalStatus
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.rules.loader import load_bundled_rules


def no_schema_scan(available):
    def respond(request):
        if not available:
            return httpx.Response(200, text="Not a GraphQL service")
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        return httpx.Response(200, json={"errors": [{"message": "Introspection disabled"}]})

    with HttpClient(transport=httpx.MockTransport(respond)) as client:
        detection = discover_and_detect_graphql(
            Target.parse("http://127.0.0.1/graphql"), mode=ScanMode.SAFE, client=client
        )
        introspection = introspect_detected_endpoints(detection, client=client)
        parsed = parse_introspection_schemas(introspection)
        analyzed = analyze_schema_results(parsed, load_bundled_rules())
        return execute_generated_queries(generate_analyzed_queries(analyzed), client=client)


@pytest.mark.parametrize("available", [False, True])
def test_insufficient_context_skips_before_provider_construction(monkeypatch, available):
    scan = no_schema_scan(available)
    before = deepcopy(scan)
    context = build_ai_context(scan)
    assert not (context.schemas or context.operations or context.security_facts)
    monkeypatch.setattr(
        ai_assistance, "OllamaClient", lambda **kw: pytest.fail("Provider constructed")
    )
    monkeypatch.setattr(HttpClient, "send", lambda *a, **kw: pytest.fail("Target request"))
    calls = []

    class Provider:
        def interpret(self, *args, **kwargs):
            calls.append(args)
            pytest.fail("Provider invoked for insufficient context")

    result = ai_assistance.interpret_completed_scan(scan)
    assert ai_assistance.interpret_completed_scan(scan, client=Provider()).status == result.status
    assert result.status is AIAnalysisStatus.NOT_RUN
    assert result.error_code == "insufficient_deterministic_context"
    assert "insufficient deterministic facts" in result.error_message
    assert result.attempt_count == len(calls) == 0
    assert result.attempts == result.quality_warnings == result.validation_failures == ()
    assert result.interpretation is None and scan == before

    for verbose in (False, True):
        output = StringIO()
        console = Console(file=output, width=100, theme=CONSOLE_THEME)
        render_ai(console, result, verbose=verbose)
        assert "not_run" in output.getvalue()
        assert "insufficient deterministic facts" in output.getvalue()
        assert "No validated interpretation" not in output.getvalue()
    report = build_report(scan, ai_interpretation=result)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert canonical["report_schema_version"] == 2
    assert canonical["ai_interpretation"]["status"] == "not_run"
    assert canonical["ai_interpretation"]["attempt_count"] == 0
    for format_ in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format_)
        assert (
            "NOT_RUN" in rendered.replace("\\", "")
            and "insufficient deterministic facts" in rendered
        )
        assert rendered.count("Safety Notice") == 1


@pytest.mark.parametrize("operations", [True, False])
def test_zero_findings_with_useful_facts_still_invokes_once(phase_ten_scan, operations):
    scan = phase_ten_scan("type Query { items: [Item] } type Item { id: ID }", ScanMode.SAFE)[0]
    if not operations:
        generation = scan.query_generation
        scan = replace(
            scan,
            query_generation=replace(
                generation, operation_analysis=replace(generation.operation_analysis, endpoints=())
            ),
        )
    context = build_ai_context(scan)
    assert context.metadata.deterministic_findings == 0
    assert context.schemas and context.security_facts
    assert bool(context.operations) is operations
    calls = []

    def respond(request):
        calls.append(request)
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "done_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": json.dumps(security_answer_fields(context)),
                },
            },
        )

    before = deepcopy(scan)
    result = ai_assistance.interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(calls) == 1
    assert scan == before


@pytest.fixture
def context(phase_ten_scan):
    return build_ai_context(
        phase_ten_scan(
            "type Query { login(token: String!): String systemDiagnostics: String }", ScanMode.SAFE
        )[0]
    )


def warnings(context, text, operations=(), facts=()):
    payload = security_answer_fields(context)
    payload["limitations"] = [{"text": text, "references": reference_items(operations, facts)}]
    typed = validate_interpretation(json.dumps(payload), context)
    return collect_interpretation_quality_warnings(typed, context)


@pytest.mark.parametrize(
    "text",
    [
        "No rate limiting is present.",
        "Rate limiting is absent.",
        "Authentication controls are absent.",
        "Authorization was not implemented.",
        "No complexity controls exist.",
        "Depth controls are missing.",
        "The endpoint has no complexity controls.",
        "No runtime protections exist.",
        "No input validation exists.",
    ],
)
def test_control_absence_is_advisory(context, text):
    assert "unsupported_control_claim" in warnings(context, text)


@pytest.mark.parametrize(
    "text",
    [
        "GQLSleuth did not establish whether rate limiting is present.",
        "GQLSleuth did not establish whether authentication is present.",
        "GQLSleuth did not establish whether authorization is present.",
        "GQLSleuth did not establish whether complexity controls are present.",
        "GQLSleuth did not establish whether depth controls are present.",
        "No deterministic evidence in the supplied context establishes an authorization control "
        "for this operation.",
        "Runtime enforcement was not tested by this capability.",
        "No schema-visible bounding input was observed; runtime limits may still exist.",
        "Do not assume that rate limiting is absent.",
    ],
)
def test_uncertainty_does_not_claim_absent_controls(context, text):
    assert "unsupported_control_claim" not in warnings(context, text)
    assert "false_absence_claim" not in warnings(context, text)


@pytest.mark.parametrize(
    "retrieval", [SchemaRetrievalStatus.RETRIEVED, SchemaRetrievalStatus.PARTIAL]
)
def test_schema_completeness_is_independent_of_operation_truncation(phase_ten_scan, retrieval):
    scan = phase_ten_scan(
        "type Query { " + " ".join(f"field{i}: String" for i in range(19)) + " }", ScanMode.SAFE
    )[0]
    generation = scan.query_generation
    analysis = generation.operation_analysis
    schemas = replace(
        analysis.schema_scan,
        schemas=tuple(
            replace(item, schema_retrieval_status=retrieval)
            for item in analysis.schema_scan.schemas
        ),
    )
    scan = replace(
        scan,
        query_generation=replace(
            generation, operation_analysis=replace(analysis, schema_scan=schemas)
        ),
    )
    context = build_ai_context(scan)
    assert context.schemas[0].schema_retrieval == retrieval.value.lower()
    assert (
        context.metadata.operations_total,
        context.metadata.operations_included,
        context.metadata.operations_omitted,
    ) == (19, 12, 7)
    assert context.metadata.context_truncated
    assert len(serialize_context(context).encode()) <= MAX_CONTEXT_BYTES
    for text in (
        "Schema retrieval was partial.",
        "Only part of the schema was retrieved.",
        "Introspection returned incomplete schema data.",
        "Schema coverage was partial.",
    ):
        assert ("unsupported_review_conclusion" in warnings(context, text)) is (
            retrieval is SchemaRetrievalStatus.RETRIEVED
        )
    if retrieval is SchemaRetrievalStatus.RETRIEVED:
        assert not warnings(
            context,
            "Full schema retrieval succeeded, but AI interpretation uses "
            "a bounded operation subset.",
        )


def scoped_facts(context):
    return context.model_copy(
        update={
            "security_facts": (
                AISecurityFact(
                    security_fact_ref="SF1",
                    endpoint="endpoint_1",
                    kind="query",
                    name="login",
                    argument="token",
                    capability="authentication",
                    category="security_observation",
                ),
                AISecurityFact(
                    security_fact_ref="SF2",
                    endpoint="endpoint_1",
                    kind="query",
                    name="systemDiagnostics",
                    capability="abuse_controls",
                    category="security_observation",
                    control_observed=True,
                ),
            )
        }
    )


@pytest.mark.parametrize(
    "name,fact,text",
    [
        ("login", "SF2", "Rate limiting is present for this tested probe."),
        ("systemDiagnostics", "SF1", "Review the token argument for this operation."),
    ],
)
def test_cross_operation_fact_borrowing_is_advisory(context, name, fact, text):
    context = scoped_facts(context)
    assert "unsupported_review_conclusion" in warnings(
        context, text, [f"endpoint_1/query/{name}"], [fact]
    )


def test_matching_and_endpoint_wide_facts_preserve_scope(context):
    context = scoped_facts(context)
    text = "Rate limiting is present for this tested probe."
    assert not warnings(context, text, ["endpoint_1/query/systemDiagnostics"], ["SF2"])
    assert not warnings(
        context,
        "Review the token argument for this operation.",
        ["endpoint_1/query/login"],
        ["SF1"],
    )
    endpoint_fact = context.security_facts[1].model_copy(update={"name": None, "kind": None})
    context = context.model_copy(update={"security_facts": (endpoint_fact,)})
    assert not warnings(context, text, facts=["SF2"])
    assert "unsupported_control_claim" in warnings(
        context, text, ["endpoint_1/query/login"], ["SF2"]
    )


def test_query_and_mutation_names_are_not_interchangeable(context):
    context = scoped_facts(context)
    fact = context.security_facts[0].model_copy(update={"kind": "mutation"})
    context = context.model_copy(update={"security_facts": (fact,)})
    assert "unsupported_review_conclusion" in warnings(
        context,
        "Review the token argument for this operation.",
        ["endpoint_1/query/login"],
        ["SF1"],
    )


def test_new_quality_warnings_remain_nonfatal_without_regeneration(phase_ten_scan):
    scan = phase_ten_scan("type Query { health: String }", ScanMode.SAFE)[0]
    context = build_ai_context(scan)
    payload = security_answer_fields(context)
    payload["limitations"] = [
        {"text": "No rate limiting is present. Schema retrieval was partial.", "references": []}
    ]
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "done_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(payload)},
            },
        )

    result = ai_assistance.interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(calls) == 1
    assert result.validation_failures == ()
    assert set(result.quality_warnings) == {
        "unsupported_control_claim",
        "unsupported_review_conclusion",
    }
    assert result.interpretation.model_dump(mode="json") == payload


def test_same_name_on_two_endpoints_does_not_share_facts(phase_ten_scan):
    scan = phase_ten_scan("type Query { items: [Item] } type Item { id: ID }", ScanMode.SAFE)[0]
    generation = scan.query_generation
    analysis = generation.operation_analysis
    original = analysis.endpoints[0]
    other = "http://127.0.0.1/other"
    second = replace(
        original,
        endpoint=other,
        operations=tuple(replace(op, endpoint=other) for op in original.operations),
    )
    review = generation.security_review
    second_fact = replace(
        review.candidates[0], endpoint=other, related_operation=second.operations[0]
    )
    scan = replace(
        scan,
        query_generation=replace(
            generation,
            operation_analysis=replace(analysis, endpoints=(original, second)),
            security_review=replace(review, candidates=(*review.candidates, second_fact)),
        ),
    )
    context = build_ai_context(scan)
    assert {o.operation for o in context.operations} == {
        "endpoint_1/query/items",
        "endpoint_2/query/items",
    }
    assert {f.endpoint for f in context.security_facts} == {"endpoint_1", "endpoint_2"}
    foreign = next(f for f in context.security_facts if f.endpoint == "endpoint_2")
    assert "unsupported_review_conclusion" in warnings(
        context,
        "Review the collection schema for this operation.",
        ["endpoint_1/query/items"],
        [foreign.security_fact_ref],
    )
    assert not warnings(
        context,
        "Review the collection schema for this operation.",
        ["endpoint_2/query/items"],
        [foreign.security_fact_ref],
    )
    assert other not in serialize_context(context)


def test_whole_scan_projection_preserves_identity_and_privacy(phase_ten_scan):
    whole = assemble(phase_ten_scan(SDL)[0])
    before = deepcopy(whole)
    context = build_ai_context(whole)
    # These two synthetic policy results omit their resolved probes. Do not
    # invent an endpoint from their operation name alone.
    missing_probe = {"authorization_policy", "sensitive_input_validation"}
    assert all(
        f.endpoint == "endpoint_1"
        for f in context.security_facts
        if f.name and f.capability not in missing_probe
    )
    assert all(f.endpoint is None for f in context.security_facts if f.capability in missing_probe)
    assert all(
        f.endpoint == "endpoint_1" and f.name is None
        for f in context.security_facts
        if f.capability == "federation"
    )
    encoded = serialize_context(context)
    assert not any(value in encoded for value in (*CANARIES, "https://", "http://"))
    assert len(encoded.encode()) <= MAX_CONTEXT_BYTES
    assert whole == before
