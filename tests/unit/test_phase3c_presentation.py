"""Final assessment polish preserves canonical facts, scope and preview policy."""

from copy import deepcopy
from dataclasses import replace
from io import StringIO
from uuid import UUID

import httpx
import pytest
from rich.console import Console
from test_phase3b_presentation import capture
from test_phase3b_presentation import prepared as prepared

from gqlsleuth.ai.models import AIAnalysisStatus, AIWithheldField
from gqlsleuth.ai.sections import quality_summary_lines
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.analysis import InterestPriority
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.presentation.object_lookup import FOLLOW_UP_NOTICE
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.operation_review import operation_review_section
from gqlsleuth.reporting.presentation import security_review_section
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.reporting.scaling import bound_section


def flatten(section):
    return (section, *(part for child in section.children for part in flatten(child)))


def ai_console(result, verbose=False):
    stream = StringIO()
    render_ai(
        Console(file=stream, width=100, height=25, no_color=True, theme=CONSOLE_THEME),
        result,
        verbose=verbose,
        include_operations=False,
    )
    return " ".join(stream.getvalue().split())


def test_ai_only_operation_keeps_metadata_without_internal_placeholder(prepared):
    scan, _, ai = prepared
    report = replace(build_report(scan, ai_interpretation=ai), review_candidates=())
    entries = operation_review_section(report).entries
    assert len(entries) == len(ai.interpretation.operation_interpretations)
    for entry in entries:
        assert "Review interest" in dict(entry.details) and "Execution" in dict(entry.details)
        assert "retained" not in " ".join(entry.paragraphs)
        assert not any(p.startswith("Deterministic review:") for p in entry.paragraphs)
        assert entry.references
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        output = render_report(report, format)
        assert "No deterministic operation-review detail" not in output
        assert "AI Interpretation:" in output


@pytest.mark.parametrize("mode", [ScanMode.SAFE, ScanMode.ACTIVE])
@pytest.mark.parametrize("verbose", [False, True])
def test_review_precedes_execution_without_duplicate_inventory(phase_ten_scan, mode, verbose):
    scan, _ = phase_ten_scan("type Query { user(id: ID!): User } type User { id: ID }", mode=mode)
    before = deepcopy(scan)
    output = capture(scan, verbose=verbose)
    assert output.index("OPERATION REVIEW") < output.index("QUERY EXECUTION")
    assert output.count("OPERATION REVIEW") == 1
    assert output.count("Query: user") == 1
    assert scan == before
    skipped = replace(scan, executions=(), execution_evidence=())
    assert "OPERATION REVIEW" in capture(skipped, verbose=verbose)


@pytest.mark.parametrize("verbose", [False, True])
def test_single_endpoint_inherited_only_by_final_reviews(prepared, verbose):
    scan, _, ai = prepared
    output = capture(scan, ai, verbose=verbose)
    review = output.split("OPERATION REVIEW", 1)[1].split("QUERY EXECUTION", 1)[0]
    shortlist = output.split("PRIORITIZED REVIEW", 1)[1].split("OPERATION REVIEW", 1)[0]
    assert "Endpoint:" not in review and "Endpoint:" not in shortlist
    assert "GraphQL endpoint: https://example.com/graphql" in output
    report = build_report(scan, ai_interpretation=ai)
    from gqlsleuth.reporting.presentation import human_sections

    for section in human_sections(report):
        for child in flatten(section):
            if child.title in {"Prioritized Review", "Operation Review"}:
                assert not any(node.endpoint for node in flatten(child))


def test_multiple_endpoint_final_reviews_remain_explicit(prepared, monkeypatch):
    scan, _, ai = prepared
    report = build_report(scan, ai_interpretation=ai)
    candidate = report.review_candidates[0]
    endpoint = "https://second.example/graphql"
    report = replace(
        report, review_candidates=(*report.review_candidates, replace(candidate, endpoint=endpoint))
    )
    monkeypatch.setattr("gqlsleuth.presentation.completed.build_report", lambda *a, **kw: report)
    output = capture(scan, ai, verbose=True)
    review = output.split("OPERATION REVIEW", 1)[1].split("QUERY EXECUTION", 1)[0]
    assert "Endpoint: " + endpoint in review
    assert "Endpoint: " + candidate.endpoint in review
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        assert endpoint in render_report(report, format).replace("\\", "")


@pytest.fixture
def lookup_report(phase_ten_scan):
    scan, _ = phase_ten_scan(
        """
        type Query { user(id: ID!): User photo(photoId: ID!): Photo album(id: ID!): Album }
        type User { id: ID friends: [User] } type Photo { id: ID } type Album { id: ID }
    """,
        mode=ScanMode.SAFE,
    )
    report = build_report(scan)
    candidates = tuple(
        replace(c, source_evidence_ids=(UUID(int=index + 1),))
        for index, c in enumerate(report.graphql_security_review.candidates)
    )
    return replace(
        report,
        graphql_security_review=replace(report.graphql_security_review, candidates=candidates),
    )


def test_equivalent_lookups_share_guidance_preserve_specifics(lookup_report):
    report = lookup_report
    before = render_report(report, ReportFormat.JSON)
    section = security_review_section(
        report.graphql_security_review, follow_ups=report.object_lookup_follow_up
    )
    grouped = next(child for child in section.children if child.title == "Object Lookup Review")
    assert len(grouped.entries) == len(grouped.table_rows) == 3
    assert FOLLOW_UP_NOTICE in grouped.paragraphs
    assert all(FOLLOW_UP_NOTICE not in e.paragraphs for e in grouped.entries)
    assert {row[1] for row in grouped.table_rows} == {"id: ID!", "photoId: ID!"}
    assert {row[2] for row in grouped.table_rows} == {"User", "Photo", "Album"}
    assert any("Recursive Relationship" in e.title for e in section.entries)
    for candidate in report.graphql_security_review.candidates:
        if candidate.candidate_type is SecurityCandidateType.OBJECT_LOOKUP_REVIEW:
            entry = next(e for e in grouped.entries if e.title == candidate.subject)
            assert str(candidate.source_evidence_ids[0]) in str(entry.evidence_references)
            assert candidate.related_operation.priority.value.replace("_", " ").upper() in str(
                grouped.table_rows
            )
    for hint in report.object_lookup_follow_up:
        assert hint.object_auth_case_template in str(grouped.entries)
        assert hint.sequential_discovery_seed_template in str(grouped.entries)
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format).replace("\\", "")
        assert text.count("Supply a known runtime object identifier") == 1
        assert text.count("Safety Notice") == 1
        assert "<h" not in text.split("Safety Notice")[1]
    assert render_report(report, ReportFormat.JSON) == before


def test_lookup_groups_do_not_combine_endpoints_or_different_guidance(lookup_report):
    report = lookup_report
    base = next(
        c
        for c in report.graphql_security_review.candidates
        if c.candidate_type is SecurityCandidateType.OBJECT_LOOKUP_REVIEW
    )
    distinct = replace(base, review_guidance="Review a distinct operator-defined access policy.")
    other = replace(base, endpoint="https://second.example/graphql")
    changed_priority = replace(
        base,
        subject="query extra",
        related_operation=replace(base.related_operation, priority=InterestPriority.HIGH_INTEREST),
    )
    review = replace(
        report.graphql_security_review, candidates=(base, changed_priority, distinct, other)
    )
    section = security_review_section(review)
    assert len(section.children) == 1 and len(section.children[0].table_rows) == 2
    assert "HIGH INTEREST" in str(section.children[0].table_rows)
    assert len(section.entries) == 2
    assert dict(section.entries[1].details)["Endpoint"] == other.endpoint
    assert distinct.review_guidance in " ".join(section.entries[0].paragraphs)


def test_grouping_respects_global_detail_cap(lookup_report):
    review = lookup_report.graphql_security_review
    base = next(
        c
        for c in review.candidates
        if c.candidate_type is SecurityCandidateType.OBJECT_LOOKUP_REVIEW
    )
    review = replace(
        review, candidates=tuple(replace(base, subject=f"query item{i}") for i in range(30))
    )
    section = bound_section(security_review_section(review))
    assert "Showing 10 of 30" in " ".join(section.paragraphs)
    assert sum(len(s.entries) for s in flatten(section)) == 10
    assert len(review.candidates) == 30


@pytest.mark.parametrize("fields,warnings", [(0, 0), (1, 1), (2, 1), (2, 2), (4, 1)])
def test_compact_quality_counts_distinguish_fields_and_categories(prepared, fields, warnings):
    _, _, result = prepared
    decisions = tuple(
        AIWithheldField("operation_interpretations", i, "interpretation") for i in range(fields)
    )
    result = replace(
        result,
        withheld_fields=decisions,
        quality_warnings=("unsupported_control_claim", "incomplete_prose")[:warnings],
    )
    compact = ai_console(result)
    total = len(result.interpretation.operation_interpretations)
    assert f"{total - fields}/{total} retained; {fields} withheld" in compact
    assert "Other withheld fields:" not in compact and "potential issue" not in compact
    assert "not a Finding or vulnerability confirmation" in compact
    if warnings:
        assert f"{warnings} warning" in compact and f"{fields} field" in compact
    detailed = ai_console(result, verbose=True)
    for line in quality_summary_lines(result):
        assert line in detailed


@pytest.mark.parametrize(
    "status",
    [AIAnalysisStatus.UNAVAILABLE, AIAnalysisStatus.INVALID_RESPONSE, AIAnalysisStatus.NOT_RUN],
)
def test_ai_non_success_never_invents_ratios(prepared, status):
    _, _, result = prepared
    output = ai_console(
        replace(result, status=status, interpretation=None, error_message="Controlled AI status.")
    )
    assert status.value in output.lower() and "retained;" not in output


def test_empty_ai_and_truncation_remain_explicit(prepared):
    _, _, result = prepared
    result = replace(
        result,
        interpretation=result.interpretation.model_copy(update={"operation_interpretations": ()}),
        context_metadata=result.context_metadata.model_copy(
            update={"context_truncated": True, "operations_omitted": 7}
        ),
    )
    output = ai_console(result)
    assert "No operation interpretations supplied" in output
    assert "7 operations" in output and "context truncated" in output


def test_missing_field_accounting_does_not_invent_retention_counts(prepared):
    _, _, result = prepared
    output = ai_console(replace(result, withheld_fields=None))
    assert "supplied; withholding accounting unavailable" in output
    assert "retained;" not in output


def test_multiple_mutation_responses_include_transport_failure(phase_ten_scan):
    safe, _ = phase_ten_scan(
        "type Query { health: String } "
        "type Mutation { createUser: User updateUser: User } type User { id: ID }"
    )
    calls = []

    def respond(request):
        calls.append(request)
        if len(calls) == 2:
            raise httpx.ConnectError("FAKE_TRANSPORT_CANARY", request=request)
        return httpx.Response(200, json={"data": {"createUser": {"id": "TEST_ID"}}})

    with HttpClient(transport=httpx.MockTransport(respond)) as client:
        result = execute_selected_mutations(
            prepare_active_mutations(safe), selected_indices=(1, 2), confirmed=True, client=client
        )
    before = deepcopy(result)
    output = capture(result)
    assert output.count("Status:") == 2
    assert "Status: SUCCESS | HTTP: 200" in output
    assert "Status: NETWORK_FAILURE | HTTP: None" in output
    assert "No HTTP response was received" in output
    assert output.index("MUTATION EXECUTION") < output.index("IMPORTANT LIMITATIONS")
    assert len(calls) == 2 and result == before


@pytest.mark.parametrize(
    "body",
    [
        b'{"data":{"createUser":{"id":"TEST_ID"}}}',
        b'{"data":null}',
        b'{"data":{}}',
        b"",
        b'{"errors":[{"message":"PRIVATE_CANARY"}]}',
        b'{"data":{"token":"PRIVATE_CANARY"}}',
        b"x" * 5000,
    ],
)
def test_mutation_preview_compact_layout_preserves_policy(phase_ten_scan, body):
    safe, _ = phase_ten_scan(
        "type Query { health: String } type Mutation { createUser: User } type User { id: ID }"
    )
    with HttpClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    ) as client:
        result = execute_selected_mutations(
            prepare_active_mutations(safe), selected_indices=(1,), confirmed=True, client=client
        )
    before = deepcopy(result)
    output = capture(result)
    assert "Status:" in output and "HTTP: 200" in output and "Duration:" in output
    assert "METADATA" not in output and "\nBODY" not in output
    assert "Observed response:" in output
    assert "PRIVATE_CANARY" not in output
    if len(body) > 4096:
        assert "4 KiB" in output
    assert result == before
