"""Null GraphQL data is a human qualification, never a new execution classification."""

import json
import re
from dataclasses import replace
from html import unescape
from io import StringIO

import httpx
import pytest
from rich.console import Console

from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.prompt import build_system_prompt
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.graphql.safe_execution import classify_execution_response
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.assessment import build_assessment
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_active_execution
from gqlsleuth.presentation.limitations import null_data_limitations
from gqlsleuth.presentation.responses import NULL_DATA_NOTICE, success_with_null_data
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import technical_sections
from gqlsleuth.reporting.renderers import render_report

SDL = "type Query { optionalThing: String } type Mutation { createThing: String }"
CASES = [
    ({"data": None}, "success", True),
    ({"data": {"optionalThing": {"id": "1"}}}, "success", False),
    ({"data": {"optionalThing": None}}, "success", False),
    ({"data": {"optionalThing": False}}, "success", False),
    ({"data": {"optionalThing": 0}}, "success", False),
    ({"data": {"optionalThing": ""}}, "success", False),
    ({"data": {"optionalThing": []}}, "success", False),
    ({"data": {"optionalThing": {}}}, "success", False),
    ({"data": {}}, "success", False),
    ({"data": None, "errors": []}, "success", True),
    ({"data": None, "errors": [{"message": "boom"}]}, "graphql_error", False),
    (
        {"data": {"optionalThing": None}, "errors": [{"message": "forbidden"}]},
        "graphql_error",
        False,
    ),
    ({"errors": [{"message": "boom"}]}, "graphql_error", False),
    ({}, "invalid_response", False),
    ([], "invalid_response", False),
    (None, "invalid_response", False),
    (b"not JSON", "invalid_response", False),
]


def body_bytes(value):
    return value if isinstance(value, bytes) else json.dumps(value).encode()


def human_text(report, format):
    text = unescape(render_report(report, format))
    return re.sub(r"\\([^\w\s])", r"\1", text) if format is ReportFormat.MARKDOWN else text


@pytest.fixture
def execute(phase_ten_scan):
    def run(body, *, active=False, http_status=200, sdl=SDL, network_failure=False):
        base, _ = phase_ten_scan(sdl, mode=ScanMode.ACTIVE if active else ScanMode.SAFE)
        requests = []

        def handler(request):
            requests.append((request.method, json.loads(request.content)))
            if network_failure:
                raise httpx.ConnectError("offline fixture", request=request)
            return httpx.Response(http_status, content=body_bytes(body))

        with HttpClient(transport=httpx.MockTransport(handler)) as client:
            safe = execute_generated_queries(base.query_generation, client=client)
            if active:
                preview = prepare_active_mutations(safe)
                result = execute_selected_mutations(
                    preview, selected_indices=(1,), confirmed=True, client=client
                )
            else:
                result = safe
        return result, requests

    return run


@pytest.mark.parametrize("body,status,qualified", CASES)
@pytest.mark.parametrize("active", [False, True])
def test_query_and_mutation_classifications_and_human_qualification_are_separate(
    execute, body, status, qualified, active, monkeypatch
):
    result, requests = execute(body, active=active)
    assert len(requests) == (2 if active else 1)
    safe = result.safe_execution if active else result
    generated = safe.query_generation.queries[0]
    assert requests[0] == (
        "POST",
        {"query": generated.query_text, "variables": generated.variables},
    )
    assert all("operationName" not in payload for _, payload in requests)
    if active:
        artifact = result.executions[0].preview.generated_mutation
        assert requests[1] == (
            "POST",
            {"query": artifact.query_text, "variables": artifact.variables},
        )
    assert safe.executions[0].status.value == status
    if active:
        assert result.executions[0].status.value == status
    evidence = result.evidence
    assert safe.execution_evidence[0].response_body == body_bytes(body)
    if active:
        assert result.execution_evidence[0].response_body == body_bytes(body)
    report = build_report(result)
    canonical = render_report(report, ReportFormat.JSON)
    ai_context = serialize_context(build_ai_context(result))
    assessment = build_assessment(report)
    assert not assessment.findings and assessment.additional_policy_violations == 0
    assert bool(null_data_limitations(report)) is qualified
    details = next(s for s in technical_sections(report) if s.title == "Safe Query Execution")
    assert any(dict(e.details).get("Response data") == "Null" for e in details.entries) is qualified

    def unexpected(*args, **kwargs):
        pytest.fail("Human rendering attempted HTTP")

    monkeypatch.setattr(HttpClient, "send", unexpected)
    for verbose in (False, True):
        output = StringIO()
        render_completed_assessment(
            Console(file=output, width=100, theme=CONSOLE_THEME), result, verbose=verbose
        )
        text = " ".join(output.getvalue().split())
        assert ("classified SUCCESS contained top-level" in text) is qualified
        assert "does not establish meaningful application data or business success" in text
        if verbose:
            assert (NULL_DATA_NOTICE in text) is qualified
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = human_text(report, format)
        assert (NULL_DATA_NOTICE in text) is qualified
        assert ("classified SUCCESS contained top-level" in text) is qualified
        assert text.rfind("Safety Notice") > text.rfind("Errors and Limitations")
        assert "\x1b" not in text
    assert render_report(report, ReportFormat.JSON) == canonical
    assert json.loads(canonical)["report_schema_version"] == 2
    assert "Response data" not in canonical and NULL_DATA_NOTICE not in canonical
    assert result.evidence == evidence
    assert serialize_context(build_ai_context(result)) == ai_context
    assert len(requests) == (2 if active else 1)


@pytest.mark.parametrize("http_status", [200, 201, 204, 301, 399, 400, 403, 500])
def test_existing_http_and_graphql_error_precedence(http_status):
    null = b'{"data":null}'
    status = "http_error" if http_status >= 400 else "success"
    assert classify_execution_response(http_status, null).status.value == status
    assert success_with_null_data(status, null) is (http_status < 400)
    assert (
        classify_execution_response(
            http_status, b'{"data":null,"errors":[{"message":"boom"}]}'
        ).status
        is QueryExecutionStatus.GRAPHQL_ERROR
    )
    assert classify_execution_response(http_status, b"{}").status.value == (
        "http_error" if http_status >= 400 else "invalid_response"
    )


def test_null_success_is_not_inferred_from_missing_attempt_evidence(execute):
    result, _ = execute({"data": None})
    report = build_report(replace(result, execution_evidence=()))
    assert not null_data_limitations(report)
    details = next(s for s in technical_sections(report) if s.title == "Safe Query Execution")
    assert not any("Response data" in dict(e.details) for e in details.entries)


def test_transport_failure_is_not_null_data_success(execute):
    result, requests = execute(None, network_failure=True)
    assert len(requests) == 1
    assert result.executions[0].status is QueryExecutionStatus.NETWORK_FAILURE
    assert not null_data_limitations(build_report(result))
    assert result.execution_evidence[0].response_body is None


def test_aggregate_is_bounded_and_visible_in_compact_output(execute):
    sdl = "type Query { " + " ".join(f"thing{i}: String" for i in range(25)) + " }"
    result, requests = execute({"data": None}, sdl=sdl)
    assert len(requests) == 20  # Existing SAFE request limit, not changed by presentation.
    report = build_report(result)
    notes = null_data_limitations(report)
    assert len(notes) == 1 and "20 execution response(s)" in notes[0] and "and 17 more" in notes[0]
    assert notes[0].count("query thing") == 3
    section = next(s for s in technical_sections(report) if s.title == "Safe Query Execution")
    assert len(section.entries) == 10
    assert len(section.table_rows) == 20
    output = StringIO()
    render_completed_assessment(Console(file=output, width=45, theme=CONSOLE_THEME), result)
    text = " ".join(output.getvalue().split())
    assert notes[0] in text and "SUCCESS" in text


def test_active_runtime_response_uses_same_qualification(execute):
    result, _ = execute({"data": None}, active=True)
    output = StringIO()
    render_active_execution(Console(file=output, width=180, theme=CONSOLE_THEME), result)
    text = output.getvalue()
    assert "createThing" in text and "SUCCESS" in text
    assert "Response data: Null" in text and NULL_DATA_NOTICE in text


def test_ai_status_metadata_is_not_a_returned_data_claim(execute):
    result, _ = execute({"data": None})
    context = build_ai_context(result)
    assert context.operations[0].execution_status is QueryExecutionStatus.SUCCESS
    assert context.counts["query_success"] == 1
    assert context.operations[0].attempted
    assert "response_body" not in serialize_context(context)
    prompt = build_system_prompt(context)
    assert "Top-level GraphQL data may be null even with SUCCESS" in prompt
    assert "never infer returned data or a meaningful application result from SUCCESS" in prompt
