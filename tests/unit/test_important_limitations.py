"""Human-only limitation summaries preserve exhaustive deterministic records."""

import html
import json
import re
from copy import deepcopy
from dataclasses import replace
from io import StringIO

import pytest
from rich.console import Console

from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.presentation.assessment import build_assessment
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ActiveReport, ReportFormat, ReportIssue
from gqlsleuth.reporting.presentation import technical_sections
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def base(phase_ten_scan):
    scan, _ = phase_ten_scan("type Query { health: String }")
    return scan, build_report(scan)


def outcomes(report, cases, *, kind="query", endpoint=None):
    """One operation-level outcome record per execution/skip, as the report builder retains."""
    original = report.queries[0]
    items, issues = [], []
    endpoint = endpoint or original.generated.endpoint
    for name, code, reason in cases:
        operation = replace(
            original.generated.operation, name=name, endpoint=endpoint, kind=OperationKind(kind)
        )
        skipped = code.startswith("skipped")
        execution = replace(
            original.execution,
            status=code,
            reason=reason,
            attempted=not skipped,
            recorded_attempted=not skipped,
            evidence_ids=() if skipped else original.execution.evidence_ids,
            response=None if skipped else original.execution.response,
        )
        items.append(
            replace(
                original,
                generated=replace(original.generated, operation=operation),
                execution=execution,
            )
        )
        if code != "success":
            issues.append(ReportIssue(kind, endpoint, name, code, reason))
    return replace(
        report,
        queries=tuple(items) if kind == "query" else report.queries,
        active=ActiveReport(tuple(items), (), True) if kind == "mutation" else report.active,
        errors_and_limitations=tuple(issues),
    )


def notes(report):
    return build_assessment(report).limitations


def normalized(text):
    return " ".join(re.sub(r"<[^>]+>", " ", html.unescape(text)).replace("\\", "").split())


def test_two_graphql_outcomes_shared_across_formats_without_changing_details(base, monkeypatch):
    scan, original = base
    report = outcomes(
        original,
        [
            ("systemDiagnostics", "graphql_error", "RAW_ERROR_A: missing two required arguments"),
            ("me", "graphql_error", "RAW_ERROR_B: missing one required argument"),
        ],
    )
    before = deepcopy(report)
    canonical = render_report(report, ReportFormat.JSON)
    text = "2 query executions returned GraphQL errors (systemDiagnostics, me)."
    assert notes(report) == (text,)
    assert "RAW_ERROR" not in text
    detail = next(s for s in technical_sections(report) if s.title == "Errors and Limitations")
    assert [e.title for e in detail.entries] == ["query: systemDiagnostics", "query: me"]
    assert all("RAW_ERROR" in e.paragraphs[0] for e in detail.entries)
    monkeypatch.setattr("gqlsleuth.presentation.completed.build_report", lambda *a, **kw: report)
    for verbose in (False, True):
        stream = StringIO()
        render_completed_assessment(
            Console(file=stream, width=80, theme=CONSOLE_THEME), scan, verbose=verbose
        )
        assert text in normalized(stream.getvalue())
    for format_ in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format_)
        assert "Important Limitations" in rendered
        assert text in normalized(rendered)
        assert "RAW_ERROR_A" in normalized(rendered) and "RAW_ERROR_B" in normalized(rendered)
        assert "query: GRAPHQL ERROR." not in rendered
        assert rendered.count("Safety Notice") == 1
    assert report == before and render_report(report, ReportFormat.JSON) == canonical
    data = json.loads(canonical)
    assert data["report_schema_version"] == 2
    assert len(data["errors_and_limitations"]) == 2


def test_one_execution_is_not_a_count_of_error_objects(base):
    report = outcomes(base[1], [("me", "graphql_error", "Multiple GraphQL error objects")])
    assert notes(report) == ("1 query execution returned a GraphQL error (me).",)


def test_large_budget_and_later_material_failure_remain_visible(base):
    reason = "Per-scan safe execution limit of 20 was reached."
    report = outcomes(
        base[1],
        [
            *[(f"success{i}", "success", "Success") for i in range(20)],
            *[(f"skipped{i}", "skipped_limit", reason) for i in range(307)],
        ],
    )
    assert notes(report) == ("307 queries were not executed. " + reason,)
    canonical = render_report(report, ReportFormat.JSON)
    assert len(json.loads(canonical)["errors_and_limitations"]) == 307
    assert "skipped0" not in " ".join(notes(report))
    report = replace(
        report,
        errors_and_limitations=report.errors_and_limitations
        + (
            ReportIssue(
                "query",
                report.queries[0].generated.endpoint,
                "later",
                "network_failure",
                "Query request failed with HttpTransportError.",
            ),
            ReportIssue(
                "query",
                report.queries[0].generated.endpoint,
                "later",
                "HttpTransportError",
                "PRIVATE_DETAIL",
            ),
        ),
    )
    assert len(notes(report)) == 2
    assert (
        notes(report)[0]
        == "1 query execution could not complete because of transport failures (later)."
    )
    assert notes(report)[1].startswith("307 queries were not executed.")
    assert "PRIVATE_DETAIL" not in " ".join(notes(report))


def test_safety_tokens_share_only_their_known_cause(base):
    cases = [
        (
            name,
            "skipped_safety",
            f"Query name contains explicit state-changing action token(s): {token}.",
        )
        for name, token in [
            ("deleteAllPastes", "delete"),
            ("readAndBurn", "burn"),
            ("systemUpdate", "update"),
        ]
    ]
    report = outcomes(base[1], cases)
    assert len(notes(report)) == 1
    assert (
        "3 queries were not executed because their names contain state-changing action tokens"
        in notes(report)[0]
    )
    assert "(deleteAllPastes, readAndBurn, systemUpdate)" in notes(report)[0]
    report = outcomes(
        base[1],
        cases + [("other", "skipped_safety", "Parsed schema is unavailable for this endpoint.")],
    )
    assert len(notes(report)) == 2
    assert "parsed schema was unavailable for validation (other)" in notes(report)[1]
    assert len(report.errors_and_limitations) == 4


@pytest.mark.parametrize(
    "code,reason,expected",
    [
        ("http_error", "Private HTTP detail", "failed at the HTTP layer"),
        (
            "invalid_response",
            "Private raw malformed body",
            "returned a response that could not be interpreted as GraphQL",
        ),
        (
            "network_failure",
            "Query request failed with HttpTimeoutError.",
            "could not complete because of timeouts",
        ),
    ],
)
def test_material_execution_classifications_remain_distinct(base, code, reason, expected):
    report = outcomes(base[1], [("me", code, reason)])
    assert notes(report) == (f"1 query execution {expected} (me).",)
    assert "Private" not in " ".join(notes(report))


def test_discovery_transport_counts_paths_and_distinguishes_origins(base):
    report = replace(
        base[1],
        errors_and_limitations=tuple(
            ReportIssue(
                "discovery",
                f"https://example.com/path{i}",
                None,
                "HttpTransportError",
                "PRIVATE_DETAIL",
            )
            for i in range(10)
        ),
    )
    assert len(notes(report)) == 1
    assert (
        "Transport failures prevented responses during endpoint discovery for 10 probed paths."
        in notes(report)[0]
    )
    assert "Check the URL, network reachability, proxy and TLS settings." in notes(report)[0]
    report = replace(
        report,
        errors_and_limitations=report.errors_and_limitations
        + (
            ReportIssue(
                "discovery",
                "https://second.example/graphql",
                None,
                "HttpTimeoutError",
                "PRIVATE_OTHER",
            ),
        ),
    )
    assert len(notes(report)) == 2
    assert notes(report)[0].startswith("https://example.com:")
    assert notes(report)[1].startswith("https://second.example:")
    assert "1 probed path." in notes(report)[1]


def test_query_mutation_and_multi_endpoint_scope_are_not_merged(base):
    report = outcomes(base[1], [("me", "graphql_error", "query reason")])
    mutation = outcomes(
        base[1], [("updateProfile", "graphql_error", "mutation reason")], kind="mutation"
    )
    report = replace(
        report,
        active=mutation.active,
        errors_and_limitations=(
            *report.errors_and_limitations,
            *mutation.errors_and_limitations,
            ReportIssue(
                "query", "https://second.example/graphql", "me", "graphql_error", "another cause"
            ),
        ),
    )
    assert len(notes(report)) == 3
    assert "1 mutation execution returned a GraphQL error (updateProfile)." in notes(report)[1]
    assert all(note.startswith("https://") for note in notes(report))
    assert notes(report)[2].startswith("https://second.example/graphql:")


def test_many_errors_keep_exact_count_without_a_name_dump(base):
    report = outcomes(
        base[1], [(f"operation{i}", "graphql_error", f"raw message {i}") for i in range(37)]
    )
    assert notes(report) == (
        "37 query executions returned GraphQL errors; "
        "see detailed results for the affected operations.",
    )
    assert len(json.loads(render_report(report, ReportFormat.JSON))["errors_and_limitations"]) == 37


def test_existing_schema_and_ai_coverage_prose_remains(base):
    from gqlsleuth.ai.context import build_ai_context
    from gqlsleuth.ai.models import AIAnalysisStatus, AIInterpretationResult

    scan, report = base
    context = build_ai_context(scan)
    ai = AIInterpretationResult(
        AIAnalysisStatus.SUCCESS,
        "qwen3:8b",
        report.generated_at,
        0,
        context.metadata.model_copy(update={"context_truncated": True}),
    )
    report = replace(report, endpoints=(), errors_and_limitations=(), ai_interpretation=ai)
    assert notes(report) == (
        "No confirmed or probable GraphQL endpoint was retained.",
        "No parsed schema was available; operation coverage is limited.",
        "AI context was truncated; interpretation covers only supplied facts.",
    )


def test_introspection_transport_detail_is_not_lost_to_generic_status(base):
    endpoint = base[1].endpoints[0].endpoint
    report = replace(
        base[1],
        errors_and_limitations=(
            ReportIssue("introspection", endpoint, None, "network_failure", "Generic failure"),
            ReportIssue("introspection", endpoint, None, "HttpTimeoutError", "PRIVATE_DETAIL"),
        ),
    )
    assert len(notes(report)) == 1
    assert "Introspection was limited by timeouts." in notes(report)[0]
    assert "PRIVATE_DETAIL" not in notes(report)[0]


@pytest.mark.parametrize("limit", [7, 20])
def test_budget_limit_is_read_from_standard_reason_not_hardcoded(base, limit):
    reason = f"Per-scan safe execution limit of {limit} was reached."
    report = outcomes(base[1], [("later", "skipped_limit", reason)])
    assert notes(report) == ("1 query was not executed. " + reason,)
