"""Offline presentation joins, bounded response values and grounding diagnostics."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO

import httpx
import pytest
from rich.console import Console

from fixtures.ai_response import security_answer_fields
from fixtures.cli_output import plain_cli_output
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIAnalysisStatus, AIInterpretationResult, AIReferenceProjection
from gqlsleuth.ai.prompt import execution_summary, validate_interpretation
from gqlsleuth.ai.quality import INCOMPLETE_PROSE, WITHHELD_PROSE, enforce_interpretation_grounding
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.presentation.recovery import RecoveryPresentation
from gqlsleuth.presentation.responses import compact_mutation_body
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.operation_review import operation_review_section
from gqlsleuth.reporting.presentation import technical_sections
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.reporting.scaling import bound_section

SDL = """
type Query { user(id: ID!): User users: [User] }
type Mutation { user(id: ID!): User createUser: User }
type User { id: ID email: String }
"""


@pytest.fixture
def prepared(phase_ten_scan):
    scan, _ = phase_ten_scan(SDL, mode=ScanMode.SAFE)
    context = build_ai_context(scan)
    original = validate_interpretation(json.dumps(security_answer_fields(context)), context)
    result = AIInterpretationResult(
        AIAnalysisStatus.SUCCESS,
        "qwen3:8b",
        datetime(2026, 11, 4, tzinfo=UTC),
        0,
        context.metadata,
        original,
        references=AIReferenceProjection(
            operations=context.operations, security_facts=context.security_facts
        ),
        execution_summary=execution_summary(context),
        withheld_fields=(),
    )
    return scan, context, result


def capture(scan, ai=None, *, verbose=False, width=80, terminal=False):
    stream = StringIO()
    console = Console(
        file=stream,
        width=width,
        height=25,
        theme=CONSOLE_THEME,
        force_terminal=terminal,
        no_color=True,
        legacy_windows=False,
    )
    render_completed_assessment(console, scan, verbose=verbose, ai_result=ai)
    if ai:
        render_ai(console, ai, verbose=verbose, include_operations=False)
    return plain_cli_output(stream.getvalue())


@pytest.mark.parametrize("verbose", [False, True])
@pytest.mark.parametrize("width", [45, 80, 140])
def test_summaries_and_unified_review_are_human_only(prepared, monkeypatch, verbose, width):
    scan, context, ai = prepared
    before = deepcopy(scan)
    serialized = serialize_context(context)
    report = build_report(scan, ai_interpretation=ai)
    canonical = render_report(report, ReportFormat.JSON)

    def no_request(*args, **kwargs):
        raise AssertionError("Presentation must not call HTTP or Ollama")

    monkeypatch.setattr(HttpClient, "send", no_request)
    monkeypatch.setattr(OllamaClient, "interpret", no_request)
    output = capture(scan, ai, verbose=verbose, width=width)
    assert "EXECUTIVE SCAN SUMMARY" not in output
    assert "Total type count" not in output and "Query field count" not in output
    assert "OPERATION REVIEW" in output and "OPERATION ANALYSIS" not in output
    assert "Attempted: Yes" not in output
    assert "4 additional AI entries" not in output
    assert "Query: user" in output and "Mutation: user" in output
    assert max(map(len, output.splitlines())) <= width
    assert "\x1b" not in output
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "Operation Review" in text and "Operation Analysis" not in text
        assert "Executive Scan Summary" not in text
        assert text.count("Safety Notice") == 1
        assert "<h" not in text.split("Safety Notice")[1]
    assert "ai_endpoint_urls" not in canonical
    assert json.loads(canonical)["summary"] == report.summary
    assert render_report(report, ReportFormat.JSON) == canonical
    assert scan == before and serialize_context(context) == serialized


def test_join_requires_endpoint_kind_and_name_and_preserves_unmatched(prepared):
    scan, _, ai = prepared
    report = build_report(scan, ai_interpretation=ai)
    user = next(i for i in report.review_candidates if i.name == "user" and i.kind.value == "query")
    second = replace(user, endpoint="https://second.example/graphql")
    report = replace(report, review_candidates=(*report.review_candidates, second))
    entries = operation_review_section(report).entries
    first = next(
        e
        for e in entries
        if e.title == "Query: user" and dict(e.details)["Endpoint"] == user.endpoint
    )
    other = next(
        e
        for e in entries
        if e.title == "Query: user" and dict(e.details)["Endpoint"] == second.endpoint
    )
    mutation = next(e for e in entries if e.title == "Mutation: user")
    assert first.references == ("endpoint_1/query/user",)
    assert mutation.references == ("endpoint_1/mutation/user",)
    assert other.references == ()
    assert not any(p.startswith("AI Interpretation:") for p in other.paragraphs)
    # Unknown endpoint projection cannot be joined by an otherwise identical name.
    unknown = operation_review_section(replace(report, ai_endpoint_urls=()))
    assert len(unknown.entries) == len(report.review_candidates) + len(
        ai.interpretation.operation_interpretations
    )
    # AI-only entries remain independently accessible.
    ai_only = operation_review_section(replace(report, review_candidates=()))
    assert len(ai_only.entries) == len(ai.interpretation.operation_interpretations)


@pytest.mark.parametrize("state", ["disabled", "unavailable", "withheld"])
def test_deterministic_review_survives_ai_state(prepared, state):
    scan, context, ai = prepared
    if state == "disabled":
        ai = None
    elif state == "unavailable":
        ai = replace(
            ai,
            status=AIAnalysisStatus.UNAVAILABLE,
            interpretation=None,
            error_message="Local Ollama unavailable.",
        )
    else:
        payload = security_answer_fields(context)
        payload["operation_interpretations"][0]["interpretation"] = (
            "This operation lacks authorization checks."
        )
        original = validate_interpretation(json.dumps(payload), context)
        filtered, warnings, fields = enforce_interpretation_grounding(original, context)
        ai = replace(ai, interpretation=filtered, quality_warnings=warnings, withheld_fields=fields)
    report = build_report(scan, ai_interpretation=ai)
    review = operation_review_section(report)
    assert len(review.entries) >= len(report.review_candidates)
    assert any(p.startswith("Deterministic review:") for e in review.entries for p in e.paragraphs)
    if state == "disabled":
        assert not any("AI " in p for e in review.entries for p in e.paragraphs)
    elif state == "withheld":
        prose = " ".join(p for e in review.entries for p in e.paragraphs)
        assert "Withheld — unsupported by supplied facts" in prose
        assert "lacks authorization" not in prose
        assert ai.interpretation.operation_interpretations[0].manual_follow_up in prose


def test_review_caps_and_structural_candidates_remain_accessible(prepared):
    scan, _, ai = prepared
    report = build_report(scan, ai_interpretation=ai)
    operation = report.review_candidates[0]
    report = replace(
        report, review_candidates=tuple(replace(operation, name=f"user{i}") for i in range(30))
    )
    section = operation_review_section(report)
    bounded = bound_section(section)
    assert len(bounded.entries) == 20
    assert f"Showing 20 of {len(section.entries)}" in " ".join(bounded.paragraphs)
    assert len(report.review_candidates) == 30
    structural = next(s for s in technical_sections(report) if s.title == "GraphQL Security Review")
    assert structural.entries


def test_progressive_diagnostics_are_verbose_but_partial_warning_is_compact(prepared, monkeypatch):
    scan, _, _ = prepared
    report = build_report(scan)
    endpoint = next(e for e in report.endpoints if e.schema_summary)
    endpoint = replace(
        endpoint,
        schema_retrieval_status="partial",
        schema_retrieval_summary="PROGRESSIVE — PARTIAL",
        recovery=RecoveryPresentation(
            (
                ("Recovery method", "PROGRESSIVE"),
                ("Requests", "18"),
                ("Last query shape", "directives"),
            ),
            ("Request budget stopped incomplete recovery.",),
            (),
        ),
    )
    report = replace(report, endpoints=(endpoint,))
    monkeypatch.setattr("gqlsleuth.presentation.completed.build_report", lambda *a, **kw: report)
    compact = capture(scan)
    detail = capture(scan, verbose=True)
    assert "PROGRESSIVE" in compact and "PARTIAL" in compact
    assert "coverage may be incomplete" in " ".join(compact.split())
    assert "Last query shape" not in compact and "Recovery method" not in compact
    assert "Last query shape" in detail and "directives" in detail


def test_two_endpoint_ai_entries_are_never_interchanged(prepared):
    scan, _, ai = prepared
    report = build_report(scan, ai_interpretation=ai)
    first = next(
        o
        for o in ai.interpretation.operation_interpretations
        if o.operation == "endpoint_1/query/user"
    )
    second = first.model_copy(
        update={
            "operation": "endpoint_2/query/user",
            "interpretation": "Second endpoint interpretation.",
        }
    )
    projection = next(o for o in ai.references.operations if o.operation == first.operation)
    ai = replace(
        ai,
        interpretation=ai.interpretation.model_copy(
            update={"operation_interpretations": (first, second)}
        ),
        references=ai.references.model_copy(
            update={
                "operations": (
                    projection,
                    projection.model_copy(update={"operation": second.operation}),
                )
            }
        ),
    )
    operation = next(
        o for o in report.review_candidates if o.name == "user" and o.kind.value == "query"
    )
    url = "https://second.example/graphql"
    report = replace(
        report,
        ai_interpretation=ai,
        review_candidates=(operation, replace(operation, endpoint=url)),
        ai_endpoint_urls=(*report.ai_endpoint_urls, ("endpoint_2", url)),
    )
    entries = operation_review_section(report).entries
    assert len(entries) == 2
    assert dict(entries[0].details)["Endpoint"] == operation.endpoint
    assert dict(entries[1].details)["Endpoint"] == url
    assert first.interpretation in " ".join(entries[0].paragraphs)
    assert second.interpretation not in " ".join(entries[0].paragraphs)
    assert second.interpretation in " ".join(entries[1].paragraphs)


def test_unattempted_mutations_never_gain_response_previews(phase_ten_scan):
    safe, _ = phase_ten_scan(SDL)
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("No execution authorized"))
    ) as client:
        result = execute_selected_mutations(prepare_active_mutations(safe), client=client)
    output = capture(result)
    assert "Observed response" not in output and "RESPONSE" not in output
    assert not result.execution_evidence


@pytest.mark.parametrize(
    "body,expected,hidden",
    [
        (b'{"data":{"createUser":{"id":"101"}}}', '"id": "101"', ""),
        (b'{"data":null}', '"data": null', ""),
        (b'{"data":{}}', '"data": {}', ""),
        (b"", "Empty response body", ""),
        (b"not json", "No renderable GraphQL", "not json"),
        (b'{"errors":[{"message":"ERROR_CANARY"}]}', "GraphQL errors: 1", "ERROR_CANARY"),
        (
            b'{"data":{"createUser":{"id":"1"}},"errors":[{"message":"ERROR_CANARY"}]}',
            "GraphQL data: present",
            "ERROR_CANARY",
        ),
        (
            b'{"data":{"token":"TOKEN_CANARY","email":"PRIVATE_CANARY"}}',
            "values omitted",
            "TOKEN_CANARY",
        ),
        (b'{"data":{"value":"' + b"x" * 5000 + b'"}}', "4 KiB", "xxxxx"),
        (b'{"data":' + b"[" * 9 + b"null" + b"]" * 9 + b"}", "values omitted", "[[["),
    ],
)
def test_compact_mutation_response_budget_and_privacy(body, expected, hidden):
    preview = compact_mutation_body(body)
    text = preview.text + (preview.notice or "")
    assert expected in text
    if hidden:
        assert hidden not in text
    assert len(preview.text) <= 4096


@pytest.mark.parametrize("network", [False, True])
def test_executed_mutations_preview_in_default_and_reports(phase_ten_scan, monkeypatch, network):
    safe, _ = phase_ten_scan(SDL)
    requests = []

    def handler(request):
        requests.append(request)
        if network:
            raise httpx.ReadError("FAKE_TRANSPORT_PRIVATE", request=request)
        return httpx.Response(200, json={"data": {"result": {"id": "101"}}})

    preview = prepare_active_mutations(safe)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = execute_selected_mutations(
            preview, selected_indices=(1, 2), confirmed=True, client=client
        )
    assert len(requests) == 2
    before = deepcopy(result)

    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected request")

    monkeypatch.setattr(HttpClient, "send", forbidden)
    output = capture(result)
    assert "MUTATION EXECUTION" in output
    assert (
        output.count("No HTTP response was received") == 2
        if network
        else output.count('"101"') == 2
    )
    assert "FAKE_TRANSPORT_PRIVATE" not in output
    report = build_report(result)
    canonical = render_report(report, ReportFormat.JSON)
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "NETWORK_FAILURE" in text.replace("\\", "") if network else "101" in text
        assert text.count("Safety Notice") == 1
    assert render_report(report, ReportFormat.JSON) == canonical and result == before
    assert len(requests) == 2


@pytest.mark.parametrize(
    "text,code",
    [
        (
            "If object-level authorization is insufficient, user information could cross "
            "an intended access boundary.",
            None,
        ),
        ("Ownership and authorization enforcement require manual validation.", None),
        ("The user Query returns an individual User object.", None),
        ("The user Query completed without a classified execution error.", None),
        ("The user Query was not executed.", "unsupported_execution_claim"),
        ("This operation lacks ownership validation.", "unsupported_control_claim"),
        ("The user Query returns an individual Country object.", "unsupported_review_conclusion"),
        ("The operation could expose", "incomplete_prose"),
    ],
)
def test_withholding_investigation_codes_and_valid_siblings(prepared, text, code):
    scan, context, _ = prepared
    before = deepcopy(scan)
    payload = security_answer_fields(context)
    item = next(
        i for i in payload["operation_interpretations"] if i["operation"] == "endpoint_1/query/user"
    )
    item["interpretation"] = text
    original = validate_interpretation(json.dumps(payload), context)
    filtered, warnings, decisions = enforce_interpretation_grounding(original, context)
    index = next(
        i
        for i, op in enumerate(original.operation_interpretations)
        if op.operation == item["operation"]
    )
    if code:
        decision = next(
            d for d in decisions if d.index == index and d.section == "operation_interpretations"
        )
        assert code in decision.rule_codes
        assert decision.field == "interpretation"
        assert filtered.operation_interpretations[index].interpretation in {
            WITHHELD_PROSE,
            INCOMPLETE_PROSE,
        }
        # Index -> exact supplied reference -> bounded context; no rejected prose needed.
        assert next(
            o for o in context.operations if o.operation == item["operation"]
        ).schema_structure
    else:
        assert not decisions and not warnings
        assert filtered == original
    assert filtered.operation_interpretations[index].manual_follow_up == item["manual_follow_up"]
    assert scan == before
