"""Human labels distinguish retained review sets without changing their membership."""

import json
from copy import deepcopy
from dataclasses import replace
from io import StringIO

import pytest
from rich.console import Console

import gqlsleuth.presentation.completed as completed
from gqlsleuth.domain.analysis import InterestPriority
from gqlsleuth.domain.security_review import (
    GraphQLSecurityReviewCandidate,
    GraphQLSecurityReviewResult,
    SecurityCandidateType,
)
from gqlsleuth.presentation.assessment import PRIORITIZED_REVIEW_NOTICE, build_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import technical_sections
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture(params=[(0, 83, False, 83), (10, 5, False, 8), (10, 0, False, 3), (10, 5, True, 7)])
def review_state(request, phase_ten_scan):
    operation_count, structural_count, overlap, expected_count = request.param
    safe, _ = phase_ten_scan("type Query { health: String }")
    report = build_report(safe)
    base = report.queries[0].generated.operation
    operations = tuple(
        replace(
            base,
            name=f"operation{i}",
            interest_score=9 if i == 0 else 7 if i < 3 else 3 if i < 6 else 1,
            priority=InterestPriority.CRITICAL_INTEREST
            if i == 0
            else InterestPriority.HIGH_INTEREST
            if i < 3
            else InterestPriority.MEDIUM_INTEREST
            if i < 6
            else InterestPriority.LOW_INTEREST,
        )
        for i in range(operation_count)
    )
    structural = tuple(
        GraphQLSecurityReviewCandidate(
            SecurityCandidateType.LIST_BOUNDING_REVIEW,
            base.endpoint,
            f"surface{i:02}",
            "Schema-derived review candidate.",
            (),
            "Manual validation required.",
            operations[0 if overlap and i == 0 else i + 3] if operations else None,
        )
        for i in range(structural_count)
    )
    report = replace(
        report,
        review_candidates=operations,
        graphql_security_review=GraphQLSecurityReviewResult(structural),
        summary={**report.summary, "security_review_candidate_count": operation_count},
    )
    return safe, report, expected_count, overlap


def test_counts_membership_and_order_preserve_existing_selection(review_state):
    _, report, expected_count, overlap = review_state
    view = build_assessment(report)
    structural = report.graphql_security_review.candidates
    # Pre-existing selection order: every structural item, then unrepresented HIGH/CRITICAL.
    expected = [
        (
            "Attack Surface",
            f"query {c.related_operation.name}" if c.related_operation else c.subject,
        )
        for c in structural
    ]
    expected += [
        ("Operations", f"query operation{i}")
        for i in range(3)
        if report.review_candidates and not (overlap and i == 0)
    ]
    assert [(i.capability, i.operation) for i in view.manual_review] == expected
    assert view.review_candidate_count == len(expected) == expected_count
    assert dict(view.validation_rows)["Prioritized review items"] == str(expected_count)
    sections = {s.title: s for s in technical_sections(report)}
    assert dict(sections["Executive Scan Summary"].rows)["Operation review candidate count"] == str(
        len(report.review_candidates)
    )
    assert dict(sections["GraphQL Security Review"].rows)["Structural review candidates"] == str(
        len(structural)
    )
    assert [e.title for e in sections["Operation Review Candidates"].entries] == [
        f"Query {op.name}" for op in report.review_candidates
    ]
    if not report.review_candidates:
        assert "None recorded." in sections["Operation Review Candidates"].paragraphs


@pytest.mark.parametrize("verbose", [False, True])
def test_console_terminology_without_selection_or_data_changes(review_state, monkeypatch, verbose):
    safe, report, expected_count, _ = review_state
    before = deepcopy(report)
    monkeypatch.setattr(completed, "build_report", lambda *a, **k: report)
    output = StringIO()
    completed.render_completed_assessment(
        Console(file=output, width=100, theme=CONSOLE_THEME), safe, verbose=verbose
    )
    text = " ".join(output.getvalue().split())
    assert f"Prioritized review items {expected_count}" in text
    assert "PRIORITIZED REVIEW" in text
    assert PRIORITIZED_REVIEW_NOTICE in text
    assert "Manual review candidates" not in text
    assert "Security Review Candidates" not in text
    if verbose:
        assert "OPERATION REVIEW CANDIDATES" in text
        assert f"Operation review candidate count {len(report.review_candidates)}" in text
        assert (
            f"Structural review candidates {len(report.graphql_security_review.candidates)}" in text
        )
    assert report == before


@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_human_report_terms_and_canonical_json_are_independent(review_state, format):
    _, report, expected_count, _ = review_state
    before = deepcopy(report)
    canonical = render_report(report, ReportFormat.JSON)
    text = render_report(report, format).replace("\\", "")
    assert "Prioritized Review" in text and "Prioritized review items" in text
    assert "Operation Review Candidates" in text and "Operation review candidate count" in text
    assert "Structural review candidates" in text
    assert PRIORITIZED_REVIEW_NOTICE in text
    assert "Manual review candidates" not in text and "Security review candidate count" not in text
    assert "8 of 15" not in text
    assert text.rfind("Safety Notice") > text.rfind("Operation Review Candidates")
    data = json.loads(canonical)
    assert data["report_schema_version"] == 2
    assert data["summary"]["security_review_candidate_count"] == len(report.review_candidates)
    assert "operation_review_candidate_count" not in data["summary"]
    assert len(data["graphql_security_review"]["candidates"]) == len(
        report.graphql_security_review.candidates
    )
    assert build_assessment(report).review_candidate_count == expected_count
    assert render_report(report, ReportFormat.JSON) == canonical and report == before
