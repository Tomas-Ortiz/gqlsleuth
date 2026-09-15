"""Phase 16 composition, zero-request equivalence, report/AI and named-context boundaries."""

import json
import re
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

import gqlsleuth.application.query_generation as generation_module
import gqlsleuth.cli as cli
from fixtures.phase16_smoke import SDL
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIAnalysisStatus
from gqlsleuth.ai.prompt import execution_summary
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.application.differential_review import ContextScanResult, compare_context_scans
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.application.security_review import review_analyzed_schemas
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_scan, render_security_review
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.differential import build_differential_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.mark.parametrize("mode", list(ScanMode))
def test_exact_request_generation_execution_and_ai_equivalence(phase_ten_scan, monkeypatch, mode):
    scan, requests = phase_ten_scan(SDL, mode=mode)
    review = scan.query_generation.security_review
    assert {item.candidate_type for item in review.candidates} == set(SecurityCandidateType)
    before = deepcopy(scan)
    with monkeypatch.context() as local:
        local.setattr(
            HttpClient, "send", lambda *args: pytest.fail("Structural review requested HTTP")
        )
        local.setattr(
            OllamaClient, "interpret", lambda *args: pytest.fail("Structural review called AI")
        )
        assert review_analyzed_schemas(scan.query_generation.operation_analysis) == review
    schema_ids = {
        item.evidence_id
        for item in scan.evidence
        if item.evidence_type is EvidenceType.SCHEMA_ARTIFACT
    }
    assert schema_ids and all(
        set(item.source_evidence_ids) == schema_ids for item in review.candidates
    )
    with monkeypatch.context() as local:
        local.setattr(generation_module, "review_analyzed_schemas", lambda _: None)
        baseline, baseline_requests = phase_ten_scan(SDL, mode=mode)
    assert requests == baseline_requests
    assert scan.query_generation.queries == baseline.query_generation.queries
    assert [(item.operation_name, item.status, item.attempted) for item in scan.executions] == [
        (item.operation_name, item.status, item.attempted) for item in baseline.executions
    ]
    assert serialize_context(build_ai_context(scan)) == serialize_context(
        build_ai_context(baseline)
    )
    assert [item.evidence_type for item in scan.evidence] == [
        item.evidence_type for item in baseline.evidence
    ]
    if mode is ScanMode.ACTIVE:
        previews = [prepare_active_mutations(item) for item in (scan, baseline)]
        assert previews[0].candidates == previews[1].candidates
        outgoing = []

        def send(request):
            outgoing.append(json.loads(request.content))
            return httpx.Response(200, json={"data": None})

        with HttpClient(transport=httpx.MockTransport(send)) as client:
            results = [
                execute_selected_mutations(
                    preview, selected_indices=(1,), confirmed=True, client=client
                )
                for preview in previews
            ]
        assert len(outgoing) == 2 and outgoing[0] == outgoing[1]
        assert [(item.decision, item.status) for item in results[0].executions] == [
            (item.decision, item.status) for item in results[1].executions
        ]
        assert serialize_context(build_ai_context(results[0])) == serialize_context(
            build_ai_context(results[1])
        )
    assert scan == before


def test_console_reports_and_ai_remain_local(phase_ten_scan, monkeypatch):
    scan, _ = phase_ten_scan(SDL, mode=ScanMode.SAFE)
    monkeypatch.setattr(
        HttpClient, "send", lambda *args: pytest.fail("Presentation requested HTTP")
    )
    report = build_report(scan, generated_at=datetime(2026, 9, 14, tzinfo=UTC))
    canonical = render_report(report, ReportFormat.JSON)
    data = json.loads(canonical)["graphql_security_review"]
    assert data["candidates"] and data["analyzed_endpoints"]
    assert all(item["source_evidence_ids"] for item in data["candidates"])
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "GraphQL Security Review" in text
        assert "File Upload Surface" in text and "Manual review:" in text
        assert "schema control does not prove" in text
        assert text.count("Safety Notice") == 1
        assert not re.search(r"<h[234]>|^#{2,4} ", text.split("Safety Notice")[1], re.M)
    assert render_report(report, ReportFormat.JSON) == canonical
    for verbose in (False, True):
        stream = StringIO()
        render_scan(Console(file=stream, width=80, theme=CONSOLE_THEME), scan, verbose=verbose)
        output = stream.getvalue()
        assert "GraphQL Security Review" in output and "Object Lookup Review" in output
        if verbose:
            assert "Cycle:" in output and "Manual review:" in output
    stream = StringIO()
    render_security_review(
        Console(file=stream, width=45, theme=CONSOLE_THEME), scan.query_generation.security_review
    )
    assert max(map(len, stream.getvalue().splitlines())) <= 45

    ai_requests = []

    def ollama(request):
        ai_requests.append(json.loads(request.content))
        context = build_ai_context(scan)
        return httpx.Response(
            200,
            json={
                "done": True,
                "model": "qwen3:8b",
                "message": {
                    "role": "assistant",
                    "content": json.dumps(
                        {
                            "scan_summary": {"text": execution_summary(context), "operations": []},
                            "operation_review": [],
                            "limitations": [],
                        }
                    ),
                },
            },
        )

    ai = interpret_completed_scan(scan, client=OllamaClient(transport=httpx.MockTransport(ollama)))
    assert ai.status is AIAnalysisStatus.SUCCESS and len(ai_requests) == 1
    assert "supporting_facts" not in json.dumps(ai_requests)
    assert "source_evidence_ids" not in json.dumps(ai_requests)
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(build_report(scan, ai_interpretation=ai), format)
        assert text.index("AI-Assisted Interpretation") < text.index("Safety Notice")


def test_missing_schema_and_missing_phase_seven_are_explicit(phase_ten_scan):
    scan, _ = phase_ten_scan(mode=ScanMode.SAFE)
    analysis = scan.query_generation.operation_analysis
    no_schema = replace(
        analysis, schema_scan=replace(analysis.schema_scan, schemas=()), endpoints=()
    )
    review = review_analyzed_schemas(no_schema)
    assert not review.analyzed_endpoints and not review.candidates and review.limitations
    missing_analysis = review_analyzed_schemas(replace(analysis, endpoints=()))
    assert missing_analysis.analyzed_endpoints
    assert any(
        "Phase 7 analysis unavailable" in item.reason for item in missing_analysis.limitations
    )


def test_named_context_reviews_do_not_change_differential_pairs(phase_ten_scan, monkeypatch):
    left, _ = phase_ten_scan("type Query { health: String }", mode=ScanMode.SAFE)
    right, _ = phase_ten_scan(SDL, mode=ScanMode.SAFE)
    discovery = (
        left.query_generation.operation_analysis.schema_scan.introspection.detection.discovery
    )
    target = discovery.target
    contexts = (ContextScanResult("tenant-x", left), ContextScanResult("label-y", right))
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Comparison requested HTTP"))
    result = compare_context_scans(target, contexts)
    baseline = compare_context_scans(
        target,
        tuple(
            replace(
                context,
                scan=replace(
                    context.scan,
                    query_generation=replace(context.scan.query_generation, security_review=None),
                ),
            )
            for context in contexts
        ),
    )
    assert result.pairs == baseline.pairs
    report = build_differential_report(result)
    data = json.loads(render_report(report, ReportFormat.JSON))
    assert not data["contexts"][0]["scan"]["graphql_security_review"]["candidates"]
    assert data["contexts"][1]["scan"]["graphql_security_review"]["candidates"]
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "Context: tenant" in text and "Context: label" in text
        assert "GraphQL Security Review" in text and "File Upload Surface" in text
        assert text.count("Safety Notice") == 1


def test_cli_adds_review_without_new_options_or_requests(phase_ten_scan, monkeypatch, tmp_path):
    scan, _ = phase_ten_scan(SDL, mode=ScanMode.SAFE)
    monkeypatch.setattr(cli, "run_safe_execution_scan", lambda *args, **kwargs: scan)
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("CLI added HTTP"))
    result = CliRunner().invoke(
        cli.app,
        ["scan", "https://example.com/graphql", "-f", "json,markdown,html", "-o", str(tmp_path)],
    )
    assert result.exit_code == 0, result.exception
    assert "GraphQL Security Review" in result.output
    assert len(list(tmp_path.iterdir())) == 3


def test_wrapper_decisions_use_optional_schema_arguments_and_reach_all_views(phase_ten_scan):
    scan, _ = phase_ten_scan(SDL, mode=ScanMode.SAFE)
    review = scan.query_generation.security_review
    lists = [
        item
        for item in review.candidates
        if item.candidate_type is SecurityCandidateType.LIST_BOUNDING_REVIEW
    ]
    assert "query albums" in {item.subject for item in lists}
    assert not {"query albumsLimited", "query albumsPaginated"} & {item.subject for item in lists}
    generated = {item.operation_name: item for item in scan.query_generation.queries}
    assert "limit" not in generated["albumsLimited"].query_text
    assert "options" not in generated["albumsPaginated"].query_text
    report = build_report(scan)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    candidate = next(
        item
        for item in canonical["graphql_security_review"]["candidates"]
        if item["candidate_type"] == "list_bounding_review" and item["subject"] == "query albums"
    )
    assert "Collection path: AlbumsPage.data" in candidate["supporting_facts"]
    assert "Element type: Album" in candidate["supporting_facts"]
    assert candidate["source_evidence_ids"]
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format).replace("\\", "")
        assert "Collection path: AlbumsPage.data" in text and "Element type: Album" in text
        assert "pagination defaults" in text and "not proof of unlimited results" in text
        assert text.count("Safety Notice") == 1
        assert not re.search(r"<h[234]>|^#{2,4} ", text.split("Safety Notice")[1], re.M)
    for verbose in (False, True):
        stream = StringIO()
        render_security_review(
            Console(file=stream, width=120, theme=CONSOLE_THEME), review, verbose=verbose
        )
        text = stream.getvalue()
        assert "Collection without obvious size bound" in text
        if verbose:
            assert "Collection path: AlbumsPage.data" in text


@pytest.mark.parametrize("item_count", [0, 10, 5000])
def test_runtime_collection_counts_cannot_affect_static_review(phase_ten_scan, item_count):
    scan, _ = phase_ten_scan(SDL, mode=ScanMode.SAFE)
    expected = scan.query_generation.security_review

    def handler(request):
        return httpx.Response(200, json={"data": {"albums": {"data": [{"id": "1"}] * item_count}}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        executed = execute_generated_queries(scan.query_generation, client=client)
    assert executed.query_generation.security_review == expected
    assert build_report(executed).graphql_security_review == expected
    assert review_analyzed_schemas(executed.query_generation.operation_analysis) == expected
