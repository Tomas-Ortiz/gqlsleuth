"""Offline report projections, canonical serialization, safe rendering, and filesystem output."""

import base64
import json
from dataclasses import replace
from datetime import UTC, datetime
from html import unescape

import httpx
import pytest
from jinja2 import TemplateError

from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.introspection import introspect_detected_endpoints
from gqlsleuth.application.operation_analysis import analyze_schema_results
from gqlsleuth.application.query_generation import generate_analyzed_queries
from gqlsleuth.application.reporting import generate_reports
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.application.schema_parsing import parse_introspection_schemas
from gqlsleuth.domain.exceptions import ReportingError
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.output import write_reports
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.rules.loader import load_bundled_rules

STAMP = datetime(2026, 9, 8, 23, 15, tzinfo=UTC)
SDL = """
scalar DateTime
input Cycle { children: [Cycle!]! }
type Query { health: String lookup(id: ID!): String readAndBurn: String
             broken(input: Cycle!): String event(when: DateTime!): String }
type Mutation { login(password: String!): Auth createUser(id: ID!): String deleteUser: String }
type Auth { accessToken: String }
"""


@pytest.fixture
def report_results(phase_ten_scan):
    def handler(request):
        query = json.loads(request.content)["query"]
        if "lookup" in query or "login" in query:
            return httpx.Response(
                200, json={"data": None, "errors": [{"message": "Invalid placeholder"}]}
            )
        return httpx.Response(200, json={"data": None})

    safe, _ = phase_ten_scan(SDL, mode=ScanMode.SAFE)
    active_safe, _ = phase_ten_scan(SDL, mode=ScanMode.ACTIVE)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        safe = execute_generated_queries(safe.query_generation, client=client)
        active_safe = execute_generated_queries(active_safe.query_generation, client=client)
        preview = prepare_active_mutations(active_safe)
        active = execute_selected_mutations(
            preview,
            selected_indices=tuple(
                i for i, item in enumerate(preview.candidates, 1) if item.selectable
            ),
            confirmed=True,
            client=client,
        )
    return safe, active


@pytest.mark.parametrize("index", [0, 1])
def test_context_and_all_report_formats_need_no_http_and_do_not_modify_results(
    report_results, monkeypatch, tmp_path, index
):
    result = report_results[index]
    before = result.evidence

    def unexpected(*args, **kwargs):
        raise AssertionError("Reporting attempted HTTP")

    monkeypatch.setattr(HttpClient, "send", unexpected)
    context = build_report(result, generated_at=STAMP)
    paths = write_reports(context, tuple(ReportFormat), tmp_path)
    assert len(paths) == 3
    assert context.report_schema_version == 1
    assert context.evidence == before == result.evidence
    assert context.mode is (ScanMode.SAFE if index == 0 else ScanMode.ACTIVE)


def test_canonical_json_preserves_complete_report_facts(report_results):
    safe, _ = report_results
    context = build_report(safe, generated_at=STAMP)
    text = render_report(context, ReportFormat.JSON)
    assert text == render_report(context, ReportFormat.JSON)
    report = json.loads(text)
    assert report["report_schema_version"] == 1
    assert report["target"]["original_url"] == "https://example.com/graphql"
    assert report["mode"] == "safe"
    assert report["endpoints"][0]["schema_summary"]["query_field_count"] == 5
    assert report["endpoints"][0]["introspection_status"] == "enabled"
    assert report["review_candidates"][0]["priority"] == "critical_interest"
    assert report["review_candidates"][0]["categories"]
    assert report["review_candidates"][0]["matched_rules"]
    assert report["review_candidates"][0]["reasons"]
    queries = {item["generated"]["operation"]["name"]: item for item in report["queries"]}
    assert (
        queries["lookup"]["generated"]["query_text"] == "query ($id: ID!) {\n  lookup(id: $id)\n}"
    )
    assert queries["lookup"]["generated"]["variables"] == {"id": "1"}
    assert queries["lookup"]["execution"]["status"] == "graphql_error"
    assert "Invalid placeholder" in queries["lookup"]["execution"]["reason"]
    assert queries["broken"]["generated"]["failure_reason"]
    assert queries["event"]["generated"]["manual_adjustments"]
    assert report["active"] is None
    assert report["summary"]["query_execution_count"] == 3
    assert report["summary"]["mutation_execution_count"] == 0
    assert report["summary"]["query_safety_skip_count"] == 1
    assert report["errors_and_limitations"]
    assert "findings" not in report


def test_active_json_distinguishes_previews_selection_confirmation_execution_and_evidence(
    report_results,
):
    active = report_results[1]
    report = json.loads(render_report(build_report(active, generated_at=STAMP), ReportFormat.JSON))
    candidates = {
        item["generated"]["operation"]["name"]: item for item in report["active"]["candidates"]
    }
    assert candidates["deleteUser"]["preview_decision"] == "blocked_safety"
    assert "delete" in candidates["deleteUser"]["preview_reason"]
    assert candidates["deleteUser"]["selected"] is False
    assert candidates["deleteUser"]["execution"]["attempted"] is False
    assert candidates["createUser"]["selected"] is True
    assert candidates["createUser"]["execution"]["status"] == "success"
    assert candidates["login"]["execution"]["status"] == "graphql_error"
    assert report["active"]["confirmed"] is True
    assert report["active"]["selected_indices"] == list(active.selected_indices)
    mutations = [
        item for item in report["evidence"] if item["evidence_type"] == "mutation_execution"
    ]
    assert len(mutations) == 2
    assert all(item["execution_mode"] == "active" for item in mutations)
    assert mutations[0]["operation"]["priority"] == "critical_interest"
    assert report["summary"]["mutation_execution_count"] == 2
    assert report["summary"]["successful_mutation_count"] == 1


@pytest.mark.parametrize("selected", [False, True])
def test_unselected_and_declined_active_results_never_imply_execution(report_results, selected):
    preview = report_results[1].preview
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("Unexpected request"))
    ) as client:
        result = execute_selected_mutations(
            preview, selected_indices=(1,) if selected else (), confirmed=False, client=client
        )
    context = build_report(result)
    assert context.summary["mutation_execution_count"] == 0
    assert not any(
        item.evidence_type is EvidenceType.MUTATION_EXECUTION for item in context.evidence
    )
    assert context.active.confirmed is False
    assert context.active.candidates[0].execution.decision == (
        "declined" if selected else "not_selected"
    )
    assert "not_selected" not in {item.code for item in context.errors_and_limitations}


def test_generated_or_recorded_attempt_flags_cannot_fabricate_execution_evidence(report_results):
    safe, active = report_results
    safe = replace(safe, execution_evidence=())
    active = replace(active, execution_evidence=())
    for result in (safe, active):
        context = build_report(result)
        key = "query_execution_count" if result is safe else "mutation_execution_count"
        assert context.summary[key] == 0
        assert any(
            item.code == "missing_execution_evidence" for item in context.errors_and_limitations
        )


def test_json_preserves_arbitrary_response_bytes_and_existing_headers_without_redaction(
    report_results,
):
    safe = report_results[0]
    evidence = safe.execution_evidence[0].model_copy(
        update={
            "response_body": b"\x00\xff\x80raw",
            "response_headers": {"Authorization": "test-token"},
        }
    )
    safe = replace(safe, execution_evidence=(evidence,))
    report = json.loads(render_report(build_report(safe), ReportFormat.JSON))
    item = report["evidence"][-1]
    assert item["response_body"]["encoding"] == "base64"
    assert base64.b64decode(item["response_body"]["data"]) == evidence.response_body
    assert item["response_headers"] == {"Authorization": "test-token"}


MAJOR_SECTIONS = [
    "Scan Overview",
    "Executive Scan Summary",
    "GraphQL Discovery and Confirmation",
    "Introspection",
    "Schema Summary",
    "Security Review Candidates",
    "Generated Queries",
    "Safe Query Execution",
    "Evidence Summary",
    "Errors and Limitations",
    "Manual Review Recommendations",
    "Safety Notice",
]


@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_human_reports_share_sections_interest_labels_and_omit_raw_bodies(report_results, format):
    safe = report_results[0]
    evidence = safe.execution_evidence[0].model_copy(update={"response_body": b"HUGE_BODY" * 10000})
    safe = replace(safe, execution_evidence=(evidence, *safe.execution_evidence[1:]))
    rendered = render_report(build_report(safe), format)
    for title in MAJOR_SECTIONS:
        assert title in rendered
    assert rendered.count("Safety Notice") == 1
    tail = rendered.split("Safety Notice", 1)[1]
    assert "\n## " not in tail and "<h2>" not in tail
    assert "CRITICAL INTEREST" in rendered
    assert "HUGE_BODY" not in rendered
    assert "Active Mutation Analysis" not in rendered
    assert "CRITICAL SEVERITY" not in rendered
    assert "is vulnerable" not in rendered
    assert "Invalid placeholder" in rendered
    assert "query ($id: ID!)" in rendered
    assert "GraphQL endpoint count" in rendered
    assert "Query GraphQL error count" in rendered
    assert "Graphql endpoint count" not in rendered
    assert "Query graphql error count" not in rendered
    if format is ReportFormat.MARKDOWN:
        assert "```graphql\n" in rendered
        assert "```json\n" in rendered
    else:
        assert '<pre><code class="language-graphql">' in rendered
        assert "<script" not in rendered
        assert "<link" not in rendered
        assert "<style>" in rendered


@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_active_human_reports_show_executed_mutation_documents(report_results, format):
    active = report_results[1]
    rendered = render_report(build_report(active), format)
    assert "Active Mutation Analysis" in rendered
    assert "Final batch confirmed" in rendered
    assert "mutation ($id: ID!)" in rendered
    assert "createUser" in rendered
    assert "deleteUser" in rendered
    assert "BLOCKED" in rendered


def test_human_sections_do_not_repeat_rule_or_mutation_reasons(report_results):
    active = build_report(report_results[1])
    sections = {section.title: section for section in human_sections(active)}
    review_entry = sections["Security Review Candidates"].entries[0]
    review_candidate = active.review_candidates[0]
    assert len(review_entry.paragraphs) == len(review_candidate.matched_rules)
    assert all(reason not in review_entry.paragraphs for reason in review_candidate.reasons)
    assert all(
        all(label in paragraph for label in ("Keywords:", "Locations:", "Contribution:"))
        for paragraph in review_entry.paragraphs
    )

    blocked = next(
        entry
        for entry in sections["Active Mutation Analysis"].entries
        if entry.title.endswith("deleteUser")
    )
    assert blocked.paragraphs.count("Destructive action token(s): delete.") == 1


def test_zero_mutation_active_report_and_recommendations_use_actual_state(phase_ten_scan):
    safe, _ = phase_ten_scan("type Query { health: String }")
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("Unexpected request"))
    ) as client:
        active = execute_selected_mutations(prepare_active_mutations(safe), client=client)
    context = build_report(active)
    assert context.active.candidates == ()
    assert context.recommendations == ()
    assert "No Mutation candidates." in render_report(context, ReportFormat.HTML)


def test_deterministic_recommendations_follow_recorded_categories_and_errors(report_results):
    context = build_report(report_results[1], generated_at=STAMP)
    joined = " ".join(context.recommendations)
    assert "CRITICAL INTEREST" in joined
    assert "credential" in joined
    assert "placeholders" in joined
    assert "BLOCKED_SAFETY" in joined
    assert "introspection" not in joined
    assert context == build_report(report_results[1], generated_at=STAMP)


def test_html_escapes_untrusted_text_and_graphql_without_altering_code(report_results):
    context = build_report(report_results[0])
    attack = '</code></pre><script>alert("test")</script>&'
    artifact = replace(context.queries[0].generated, query_text=attack)
    context = replace(
        context,
        queries=(replace(context.queries[0], generated=artifact),),
        recommendations=(attack,),
        target=context.target.model_copy(update={"original_url": attack}),
    )
    rendered = render_report(context, ReportFormat.HTML)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    code = rendered.split('<pre><code class="language-graphql">')[1].split("</code>")[0]
    assert unescape(code) == attack


def test_markdown_fences_cannot_be_closed_by_untrusted_document(report_results):
    context = build_report(report_results[0])
    text = "query { health }\n```\n<script>test</script>"
    artifact = replace(context.queries[0].generated, query_text=text)
    context = replace(context, queries=(replace(context.queries[0], generated=artifact),))
    rendered = render_report(context, ReportFormat.MARKDOWN)
    assert f"````graphql\n{text}\n````" in rendered


def test_templates_load_outside_repository_and_output_conflicts_do_not_overwrite(
    report_results, tmp_path, monkeypatch
):
    context = build_report(report_results[0], generated_at=STAMP)
    monkeypatch.chdir(tmp_path)
    directory = tmp_path / "nested" / "reports"
    first = write_reports(context, tuple(ReportFormat), directory)
    second = write_reports(context, tuple(ReportFormat), directory)
    assert [path.suffix for path in first] == [".json", ".md", ".html"]
    assert first[0].name == "gqlsleuth-example.com-20260908-231500.json"
    assert second[0].name == "gqlsleuth-example.com-20260908-231500-2.json"
    assert first[0].read_bytes() == second[0].read_bytes()
    assert len(list(directory.iterdir())) == 6


@pytest.mark.parametrize(
    "host", ["../../escape", r"..\..\escape", "C:evil/path", "...", "[::1]", "CON"]
)
def test_target_host_cannot_traverse_output_paths(report_results, tmp_path, host):
    context = build_report(report_results[0], generated_at=STAMP)
    context = replace(context, target=context.target.model_copy(update={"host": host}))
    path = write_reports(context, (ReportFormat.JSON,), tmp_path)[0]
    assert path.parent == tmp_path.resolve()
    assert ".." not in path.name
    assert ":" not in path.name


def test_reporting_errors_are_controlled_and_empty_formats_create_nothing(
    report_results, tmp_path, monkeypatch
):
    context = build_report(report_results[0])
    occupied = tmp_path / "file"
    occupied.write_text("existing", encoding="utf-8")
    with pytest.raises(ReportingError, match="Could not write"):
        write_reports(context, (ReportFormat.JSON,), occupied)
    with pytest.raises(ReportingError, match="Unsupported"):
        render_report(context, "pdf")
    with pytest.raises(ReportingError, match="Could not render"):
        render_report(replace(context, summary={"invalid": float("nan")}), ReportFormat.JSON)

    def template_failure(*args, **kwargs):
        raise TemplateError("test")

    monkeypatch.setattr("gqlsleuth.reporting.renderers.Environment.get_template", template_failure)
    with pytest.raises(ReportingError, match="Could not render"):
        render_report(context, ReportFormat.HTML)
    assert (
        generate_reports(report_results[0], formats=(), output_directory=tmp_path / "absent") == ()
    )
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("failure", ["introspection", "schema", "transport"])
def test_partial_scan_failures_are_reported_without_inventing_schema_or_execution(
    phase_ten_scan, failure
):
    safe, _ = phase_ten_scan(mode=ScanMode.SAFE)
    detection = safe.query_generation.operation_analysis.schema_scan.introspection.detection

    def handler(request):
        if failure == "transport":
            raise httpx.ConnectError("Offline test connection failure", request=request)
        if failure == "introspection":
            return httpx.Response(200, json={"errors": [{"message": "Introspection is disabled"}]})
        return httpx.Response(200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        introspection = introspect_detected_endpoints(detection, client=client)
        schemas = parse_introspection_schemas(introspection)
        analysis = analyze_schema_results(schemas, load_bundled_rules())
        result = execute_generated_queries(generate_analyzed_queries(analysis), client=client)
    context = build_report(result)
    assert context.endpoints[0].schema_summary is None
    assert context.summary["query_execution_count"] == 0
    assert context.summary["mutation_execution_count"] == 0
    stage = "schema" if failure == "schema" else "introspection"
    assert any(item.stage == stage for item in context.errors_and_limitations)
    assert any("introspection or schema-parsing" in text for text in context.recommendations)
    for format in ReportFormat:
        assert (
            "Errors and Limitations" in render_report(context, format)
            or format is ReportFormat.JSON
        )


def test_active_limit_and_network_failure_are_retained_in_every_format(phase_ten_scan):
    fields = " ".join(f"createItem{i}: String" for i in range(6))
    safe, _ = phase_ten_scan(f"type Query {{ health: String }} type Mutation {{ {fields} }}")
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            raise httpx.ConnectError("Offline test connection failure", request=request)
        return httpx.Response(200, json={"data": None})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        active = execute_selected_mutations(
            prepare_active_mutations(safe),
            selected_indices=(6, 5, 4, 3, 2, 1),
            confirmed=True,
            client=client,
        )
    context = build_report(active)
    assert len(requests) == context.summary["mutation_execution_count"] == 5
    assert context.summary["successful_mutation_count"] == 4
    assert context.active.candidates[-1].execution.decision == "skipped_limit"
    assert not context.active.candidates[-1].execution.evidence_ids
    assert context.active.candidates[0].execution.status == "network_failure"
    assert context.active.candidates[0].execution.error_message
    for format in ReportFormat:
        rendered = render_report(context, format).lower().replace("\\_", "_")
        assert "skipped_limit" in rendered
        assert "network_failure" in rendered
        assert "http transport request failed" in rendered
