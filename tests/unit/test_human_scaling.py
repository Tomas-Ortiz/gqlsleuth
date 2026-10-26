"""Large offline inventories keep exhaustive canonical facts and bounded human views."""

import json
from copy import deepcopy
from dataclasses import replace
from io import StringIO

import pytest
from rich.console import Console

from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.analysis import InterestPriority
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.completed import _render_technical, render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_mutations
from gqlsleuth.presentation.limits import MAX_HUMAN_DETAIL_ITEMS, MAX_HUMAN_INVENTORY_ITEMS
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat, ReportIssue
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection, technical_sections
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.reporting.scaling import bound_section, scale_operations


@pytest.fixture
def base(phase_ten_scan, monkeypatch):
    safe, requests = phase_ten_scan(
        """
        type Query { health: String }
        type Mutation { createItem(input: String!): String deleteItem: String }
    """,
        execution_data={"health": "ok"},
    )
    active = execute_selected_mutations(prepare_active_mutations(safe), confirmed=False)
    monkeypatch.setattr(HttpClient, "send", lambda *a, **k: pytest.fail("Rendering sent HTTP"))
    return safe, active, build_report(safe), requests


def clone(item, index):
    operation = replace(
        item.generated.operation, name=f"item{index:03}", priority=InterestPriority.LOW_INTEREST
    )
    generated = replace(
        item.generated,
        operation=operation,
        query_text=f"query {{ item{index:03} }}",
        manual_adjustments=(),
    )
    return replace(item, generated=generated)


def section(report, title):
    return next(s for s in technical_sections(report) if s.title == title)


@pytest.mark.parametrize("count", [3, 327])
@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_generated_inventory_is_bounded_stable_and_json_is_exhaustive(base, count, format):
    _, _, original, requests = base
    report = replace(original, queries=tuple(clone(original.queries[0], i) for i in range(count)))
    before = deepcopy(report)
    canonical = render_report(report, ReportFormat.JSON)
    request_count = len(requests)
    generated = section(report, "Generated Queries")
    assert len(generated.table_rows) == min(count, MAX_HUMAN_INVENTORY_ITEMS)
    assert [row[0] for row in generated.table_rows] == [
        f"item{i:03}" for i in range(min(count, MAX_HUMAN_INVENTORY_ITEMS))
    ]
    assert not generated.entries
    rendered = render_report(report, format)
    assert "item000" in rendered
    assert "query { item000 }" not in rendered
    assert "canonical JSON report" in rendered
    if count > MAX_HUMAN_INVENTORY_ITEMS:
        assert "Showing 20 of 327 generated Queries" in rendered
        assert "item326" not in rendered
    assert len(json.loads(canonical)["queries"]) == count
    assert json.loads(canonical)["report_schema_version"] == 2
    assert render_report(report, ReportFormat.JSON) == canonical
    assert report == before and len(requests) == request_count


@pytest.mark.parametrize(
    "status",
    [
        "success",
        "graphql_error",
        "http_error",
        "network_failure",
        "invalid_response",
        "skipped_safety",
        "skipped_limit",
        "unresolved",
    ],
)
def test_execution_inventory_and_exception_detail_policy(base, status):
    _, _, report, _ = base
    item = report.queries[0]
    attempted = not status.startswith("skipped") and status != "unresolved"
    response = (
        item.execution.response.model_copy(
            update={"body": b'{"errors":[{"message":"BODY_MARKER"}]}'}
        )
        if attempted and status != "network_failure"
        else None
    )
    execution = replace(
        item.execution,
        status=status,
        reason="REASON_MARKER",
        response=response,
        attempted=attempted,
    )
    report = replace(report, queries=(replace(item, execution=execution),))
    view = section(report, "Safe Query Execution")
    assert view.table_rows[0][1] == status.upper()
    assert bool(view.entries) is (status != "success")
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format).replace("\\_", "_")
        if status == "success":
            assert "BODY_MARKER" not in rendered
        else:
            assert "REASON_MARKER" in rendered
            if response:
                assert "BODY_MARKER" in rendered
    if view.entries and response:
        assert "Status" not in dict(view.entries[0].details)
        assert "HTTP status" not in dict(view.entries[0].details)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert canonical["queries"][0]["execution"]["status"] == status


def test_success_with_explicit_support_reference_keeps_request_and_response(base):
    _, _, report, _ = base
    item = report.queries[0]
    support = ReportSection(
        "Authentication & Token Findings",
        entries=(
            ReportEntry(
                "Scoped finding",
                evidence_references=(("Baseline", str(item.execution.evidence_ids[0])),),
            ),
        ),
    )
    views = scale_operations(report, (ReportSection("Safe Query Execution"), support))
    detail = views[0].entries[0]
    assert detail.response is not None and detail.request_blocks
    assert detail.request_blocks[0][1] == item.generated.query_text


def test_many_errors_are_bounded_with_exact_omission_notice(base):
    _, _, report, _ = base
    item = report.queries[0]
    items = tuple(
        replace(
            clone(item, i),
            execution=replace(item.execution, status="graphql_error", reason=f"reason{i}"),
        )
        for i in range(60)
    )
    report = replace(report, queries=items)
    view = section(report, "Safe Query Execution")
    assert dict(view.rows)["GRAPHQL_ERROR"] == "60"
    assert len(view.entries) == MAX_HUMAN_DETAIL_ITEMS
    assert "Showing 10 of 60 available exception/review detail sections" in " ".join(
        view.paragraphs
    )
    assert [entry.title for entry in view.entries] == [f"item{i:03}" for i in range(10)]
    assert len(json.loads(render_report(report, ReportFormat.JSON))["queries"]) == 60


def test_unselected_mutations_are_rows_but_blocked_and_selected_remain_detailed(base):
    _, active, _, _ = base
    report = build_report(active)
    view = section(report, "Active Mutation Analysis")
    assert len(view.table_rows) == 2
    assert all("createItem" not in entry.title for entry in view.entries)
    assert any("deleteItem" in entry.title for entry in view.entries)
    selected = execute_selected_mutations(active.preview, selected_indices=(1,), confirmed=False)
    selected_view = section(build_report(selected), "Active Mutation Analysis")
    assert any("createItem" in entry.title for entry in selected_view.entries)
    output = StringIO()
    render_mutations(
        Console(file=output, width=120, theme=CONSOLE_THEME),
        tuple(enumerate(active.preview.candidates, 1)),
        title="Selected Mutations",
    )
    text = output.getvalue()
    assert "https://example.com/graphql" in text
    assert "mutation" in text and "Variables:" in text


@pytest.mark.parametrize("width", [55, 120])
def test_verbose_is_bounded_and_compact_has_no_safe_request_dump(base, width):
    safe, _, report, _ = base
    for verbose in (False, True):
        output = StringIO()
        render_completed_assessment(
            Console(file=output, width=width, theme=CONSOLE_THEME), safe, verbose=verbose
        )
        assert report.queries[0].generated.query_text not in output.getvalue()
    report = replace(report, queries=tuple(clone(report.queries[0], i) for i in range(327)))
    output = StringIO()
    _render_technical(
        Console(file=output, width=width, theme=CONSOLE_THEME), section(report, "Generated Queries")
    )
    text = " ".join(output.getvalue().split())
    assert "Showing 20 of 327 generated Queries" in text
    assert "item326" not in text
    assert len(output.getvalue()) < 10000


def test_generic_collection_bounds_are_explicit_and_idempotent():
    source = ReportSection(
        "Errors and Limitations", entries=tuple(ReportEntry(f"error{i}") for i in range(50))
    )
    bounded = bound_section(source)
    assert len(bounded.entries) == MAX_HUMAN_DETAIL_ITEMS
    assert "Showing 10 of 50 available detail sections" in " ".join(bounded.paragraphs)
    assert bound_section(bounded) == bounded
    assert len(source.entries) == 50


def test_table_styling_does_not_rewrite_operation_names():
    output = StringIO()
    _render_technical(
        Console(file=output, width=120, theme=CONSOLE_THEME),
        ReportSection(
            "Generated Queries",
            table_headers=("Operation", "Priority", "Generation"),
            table_rows=(("high", "HIGH INTEREST", "GENERATED"),),
        ),
    )
    assert "high" in output.getvalue()
    assert "HIGH INTEREST" in output.getvalue()


def test_real_retained_finding_preserves_supporting_success_detail(phase_ten_scan):
    from fixtures.whole_scan_ai import SDL, assemble

    result = assemble(phase_ten_scan(SDL)[0])
    before = deepcopy(result)
    report = build_report(result)
    assert report.rate_limiting_abuse_controls.findings
    view = section(report, "Safe Query Execution")
    lookup = next(entry for entry in view.entries if entry.title == "lookup")
    assert lookup.response is not None and lookup.request_blocks
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format).replace("\\", "")
        assert "Rate limiting / abuse-control weakness" in text
        assert text.rfind("Safety Notice") > text.rfind("Detailed Technical Results")
    assert result == before


def test_selected_late_mutation_detail_is_not_hidden_by_blocked_candidates(base):
    _, active, _, _ = base
    report = build_report(active)
    candidates = report.active.candidates
    blocked = next(i for i in candidates if i.preview_decision == "blocked_safety")
    selected = next(i for i in candidates if i.preview_decision != "blocked_safety")
    selected = replace(selected, candidate_index=31, selected=True)
    report = replace(
        report,
        active=replace(
            report.active,
            candidates=tuple(replace(blocked, candidate_index=i) for i in range(1, 31))
            + (selected,),
            selected_indices=(31,),
        ),
    )
    view = section(report, "Active Mutation Analysis")
    detail = next(e for e in view.entries if e.title.startswith("[31]"))
    assert detail.request_blocks[0][1] == selected.generated.query_text
    assert len(view.entries) == MAX_HUMAN_DETAIL_ITEMS
    assert "Showing 10 of 31" in " ".join(view.paragraphs)


BUDGET_REASON = "Per-scan safe execution limit of 20 was reached."


def budget_report(report, *, successes=20, skips=307):
    item = report.queries[0]
    skipped = tuple(
        replace(
            clone(item, i),
            execution=replace(
                item.execution,
                status="skipped_limit",
                reason=BUDGET_REASON,
                attempted=False,
                recorded_attempted=False,
                response=None,
                evidence_ids=(),
            ),
        )
        for i in range(successes, successes + skips)
    )
    return replace(
        report,
        queries=tuple(clone(item, i) for i in range(successes)) + skipped,
        errors_and_limitations=tuple(
            ReportIssue(
                "query",
                i.generated.endpoint,
                i.generated.operation_name,
                "skipped_limit",
                BUDGET_REASON,
            )
            for i in skipped
        ),
    )


def human_views(report):
    output = StringIO()
    for title in ("Safe Query Execution", "Errors and Limitations"):
        _render_technical(
            Console(file=output, width=120, theme=CONSOLE_THEME), section(report, title)
        )
    return [output.getvalue()] + [
        render_report(report, format).replace("\\", "")
        for format in (ReportFormat.MARKDOWN, ReportFormat.HTML)
    ]


def test_repeated_safe_budget_skips_are_aggregate_human_facts_only(base):
    report = budget_report(base[2])
    before = deepcopy(report)
    canonical = render_report(report, ReportFormat.JSON)
    view = section(report, "Safe Query Execution")
    assert dict(view.rows) == {"SUCCESS": "20", "SKIPPED_LIMIT": "307"}
    assert len(view.table_rows) == MAX_HUMAN_INVENTORY_ITEMS == 20
    assert MAX_HUMAN_DETAIL_ITEMS == 10
    assert not view.entries
    limitations = section(report, "Errors and Limitations")
    assert len(limitations.entries) == 1
    assert dict(limitations.entries[0].details)["Records"] == "307"
    for text in human_views(report):
        assert "307 Queries were not executed." in text
        assert BUDGET_REASON in text
        assert "Showing 10 of 307" not in text
        assert "item020" not in text
    data = json.loads(canonical)
    assert sum(i["execution"]["status"] == "skipped_limit" for i in data["queries"]) == 307
    assert len(data["errors_and_limitations"]) == 307
    assert render_report(report, ReportFormat.JSON) == canonical and report == before


@pytest.mark.parametrize(
    "status",
    [
        "graphql_error",
        "network_failure",
        "http_error",
        "invalid_response",
        "unresolved",
        "skipped_safety",
    ],
)
def test_budget_skips_cannot_hide_later_material_detail(base, status):
    report = budget_report(base[2], successes=0)
    item = clone(base[2].queries[0], 999)
    item = replace(item, execution=replace(item.execution, status=status, reason="MATERIAL_REASON"))
    report = replace(
        report,
        queries=report.queries + (item,),
        errors_and_limitations=report.errors_and_limitations
        + (
            ReportIssue(
                "query",
                item.generated.endpoint,
                item.generated.operation_name,
                status,
                "MATERIAL_REASON",
            ),
        ),
    )
    assert [e.title for e in section(report, "Safe Query Execution").entries] == ["item999"]
    assert section(report, "Errors and Limitations").entries[0].title == "query: item999"
    for text in human_views(report):
        assert "MATERIAL_REASON" in text and "item999" in text


def test_distinct_limit_reason_keeps_detail_and_separate_limitation(base):
    report = budget_report(base[2], successes=0)
    item = replace(
        report.queries[-1],
        execution=replace(
            report.queries[-1].execution, reason="A distinct capability budget prevented execution."
        ),
    )
    report = replace(
        report,
        queries=report.queries[:-1] + (item,),
        errors_and_limitations=report.errors_and_limitations[:-1]
        + (replace(report.errors_and_limitations[-1], message=item.execution.reason),),
    )
    assert len(section(report, "Safe Query Execution").entries) == 1
    assert len(section(report, "Errors and Limitations").entries) == 2
    for text in human_views(report):
        assert "306 Queries were not executed." in text
        assert item.execution.reason in text


def test_limitation_group_key_preserves_endpoint_stage_code_and_normalized_reason(base):
    report = budget_report(base[2], successes=0, skips=1)
    issue = report.errors_and_limitations[0]
    report = replace(
        report,
        errors_and_limitations=(
            issue,
            replace(
                issue,
                operation_name="another",
                message="  Per-scan safe execution limit of 20\nwas reached. ",
            ),
            replace(issue, endpoint="https://other.example/graphql"),
            replace(issue, stage="mutation"),
            replace(issue, code="skipped_safety"),
            replace(issue, message="Different reason."),
        ),
    )
    view = section(report, "Errors and Limitations")
    assert len(view.entries) == 5
    groups = [e for e in view.entries if "Records" in dict(e.details)]
    assert len(groups) == 1 and dict(groups[0].details)["Records"] == "2"
    assert groups[0].paragraphs[0] == BUDGET_REASON


def test_actual_safe_pipeline_budget_records_render_without_repeated_details(phase_ten_scan):
    safe, requests = phase_ten_scan(
        "type Query { " + " ".join(f"item{i:03}: String" for i in range(327)) + " }",
        mode=ScanMode.SAFE,
        execution_data={},
    )
    report = build_report(safe)
    request_count = len(requests)
    canonical = render_report(report, ReportFormat.JSON)
    assert report.summary["query_count"] == 327
    view = section(report, "Safe Query Execution")
    assert dict(view.rows) == {"SUCCESS": "20", "SKIPPED_LIMIT": "307"}
    assert not view.entries
    assert len(section(report, "Errors and Limitations").entries) == 1
    for verbose in (False, True):
        output = StringIO()
        render_completed_assessment(
            Console(file=output, width=120, theme=CONSOLE_THEME), safe, verbose=verbose
        )
        text = " ".join(output.getvalue().split())
        assert "SUCCESS 20" in text and "SKIPPED_LIMIT 307" in text
        assert "Showing 10 of 307" not in text
        if verbose:
            assert "307 Queries were not executed." in text
    assert len(requests) == request_count
    assert render_report(report, ReportFormat.JSON) == canonical
