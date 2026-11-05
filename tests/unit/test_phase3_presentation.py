"""Human layouts preserve validated data, attribution and complete prose offline."""

import html
import json
import re
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from html.parser import HTMLParser
from io import BytesIO, StringIO, TextIOWrapper

import pytest
from rich.console import Console

from fixtures.ai_response import reference_items, security_answer_fields
from fixtures.cli_output import plain_cli_output
from fixtures.whole_scan_ai import SDL, assemble
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import (
    AIAnalysisStatus,
    AIInterpretation,
    AIInterpretationResult,
    AIReferenceProjection,
    AIWithheldField,
)
from gqlsleuth.ai.prompt import build_response_schema, build_system_prompt, execution_summary
from gqlsleuth.ai.quality import INCOMPLETE_PROSE, WITHHELD_PROSE
from gqlsleuth.ai.sections import interpretation_sections, operation_label
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.assessment import build_assessment
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.reporting.assessment import assessment_sections
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import ai_section
from gqlsleuth.reporting.renderers import render_report

STAMP = datetime(2026, 11, 3, tzinfo=UTC)


def ai_result(scan):
    context = build_ai_context(scan)
    payload = security_answer_fields(context)
    payload["summary_interpretation"]["text"] = (
        "The supplied operations need scoped manual review. "
        "Untested behavior remains outside this assessment."
    )
    refs = [o.operation for o in context.operations[:2]]
    if len(refs) == 2:
        payload["review_insights"] = [
            {
                "references": reference_items(refs),
                "interpretation": "Review the intended access boundaries for these operations.",
                "manual_follow_up": "Compare documented requirements with authorized test cases.",
            }
        ]
    payload["limitations"] = [
        {
            "references": reference_items(refs[:1]),
            "text": "The supplied context is bounded; untested behavior needs manual validation.",
        }
    ]
    return AIInterpretationResult(
        AIAnalysisStatus.SUCCESS,
        "qwen3:8b",
        STAMP,
        0,
        context.metadata,
        AIInterpretation.model_validate(payload),
        references=AIReferenceProjection(
            operations=context.operations, security_facts=context.security_facts
        ),
        execution_summary=execution_summary(context),
        withheld_fields=(),
    )


@pytest.fixture
def prepared(phase_ten_scan):
    scan, _ = phase_ten_scan(
        "type Query { user(id: ID!): User users(limit: Int): [User] } "
        "type Mutation { createUser(name: String!): User } type User { id: ID }",
        mode=ScanMode.SAFE,
    )
    return scan, ai_result(scan)


def capture_ai(result, *, width=80, verbose=True, terminal=False, no_color=False):
    stream = StringIO()
    console = Console(
        file=stream,
        width=width,
        height=25,  # Keep explicit dimensions even under CI's TERM=dumb fallback.
        force_terminal=terminal,
        color_system="standard" if terminal else None,
        no_color=no_color,
        theme=CONSOLE_THEME,
        legacy_windows=False,
    )
    render_ai(console, result, verbose=verbose)
    return stream.getvalue()


def human_text(document):
    return re.sub(r"\\([\W_])", lambda match: match[1], html.unescape(document))


@pytest.mark.parametrize("width", [45, 80, 120])
@pytest.mark.parametrize("terminal,no_color", [(False, False), (True, False), (True, True)])
def test_operation_blocks_keep_identity_prose_and_terminal_width(
    prepared, width, terminal, no_color
):
    _, result = prepared
    output = capture_ai(result, width=width, terminal=terminal, no_color=no_color)
    plain = plain_cli_output(output)
    text = " ".join(plain.split())
    assert max(map(len, plain.splitlines())) <= width
    assert "Reference Interpretation" not in text
    assert "Query: user" in text and "Mutation: createUser" in text
    assert "Execution: SUCCESS" in text
    assert "Execution: NOT_ATTEMPTED" in text
    assert "Review interest:" in text and "Kind:" not in text
    for item in result.interpretation.operation_interpretations:
        assert item.interpretation in text and item.manual_follow_up in text
        assert item.operation in "".join(plain.split())
    assert text.index("LIMITATIONS") < text.index("AI GENERATION METADATA")
    if not terminal:
        assert "\x1b" not in output


@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_reports_use_prose_sections_preserve_attribution_and_safety(prepared, format):
    scan, result = prepared
    report = build_report(scan, ai_interpretation=result, generated_at=STAMP)
    before = render_report(report, ReportFormat.JSON)
    output = render_report(report, format)
    text = human_text(output)
    assert "Query: user" in text and "Mutation: createUser" in text
    assert "| Reference | Interpretation |" not in output
    for _, blocks in interpretation_sections(result):
        for block in blocks:
            for paragraph in block.paragraphs:
                assert paragraph in text
            for reference in block.references:
                assert reference in text
    assert output.count("Safety Notice") == 1
    assert "<h" not in output.split("Safety Notice")[1]
    assert "\n##" not in output.split("Safety Notice")[1]
    assert "Operation Review" in text and "Operation Analysis" not in text
    assert "\x1b" not in output
    assert render_report(report, ReportFormat.JSON) == before
    if format is ReportFormat.HTML:
        assert "<details><summary>References</summary>" in output
        assert '<details class="technical">\n<summary>AI Generation Metadata' in output
    else:
        assert "Operation Review" in output
        assert "Mutation: createUser" in output


@pytest.mark.parametrize(
    "field,marker",
    [
        ("interpretation", WITHHELD_PROSE),
        ("manual_follow_up", WITHHELD_PROSE),
        ("interpretation", INCOMPLETE_PROSE),
    ],
)
def test_withheld_display_is_short_and_siblings_and_json_unchanged(prepared, field, marker):
    scan, result = prepared
    original = result.interpretation.operation_interpretations[0]
    changed = original.model_copy(update={field: marker})
    result = replace(
        result,
        interpretation=result.interpretation.model_copy(
            update={
                "operation_interpretations": (
                    changed,
                    *result.interpretation.operation_interpretations[1:],
                ),
            }
        ),
        withheld_fields=(AIWithheldField("operation_interpretations", 0, field),),
    )
    snapshot = deepcopy(result)
    expected = (
        "Withheld — incomplete model text"
        if marker == INCOMPLETE_PROSE
        else "Withheld — unsupported by supplied facts"
    )
    sibling = "manual_follow_up" if field == "interpretation" else "interpretation"
    text = " ".join(capture_ai(result).split())
    assert expected in text and getattr(original, sibling) in text
    report = build_report(scan, ai_interpretation=result)
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = human_text(render_report(report, format))
        assert expected in text and marker not in text
        assert getattr(original, sibling) in text
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert (
        canonical["ai_interpretation"]["interpretation"]["operation_interpretations"][0][field]
        == marker
    )
    assert result == snapshot


def test_multiple_endpoints_and_long_untrusted_prose_remain_unambiguous(prepared):
    scan, result = prepared
    operation = result.references.operations[0]
    name = "longOperation" * 10
    operations = tuple(
        operation.model_copy(update={"name": name, "operation": f"endpoint_{i}/query/{name}"})
        for i in (1, 2)
    )
    prose = (
        "Review the café policy with Tomás. <script>unsafe</script> [bold]literal[/bold]. " * 3
    ).strip()
    items = tuple(
        result.interpretation.operation_interpretations[0].model_copy(
            update={
                "operation": operation.operation,
                "interpretation": prose,
            }
        )
        for operation in operations
    )
    summary = (
        "Review the stated access policy and supplied scope before drawing conclusions. " * 9
    ).strip()
    result = replace(
        result,
        references=result.references.model_copy(update={"operations": operations}),
        interpretation=result.interpretation.model_copy(
            update={
                "operation_interpretations": items,
                "review_insights": (),
                "limitations": (),
                "summary_interpretation": result.interpretation.summary_interpretation.model_copy(
                    update={"text": summary, "references": ()}
                ),
            }
        ),
    )
    before = deepcopy(result)
    text = plain_cli_output(capture_ai(result, width=80, terminal=True))
    assert max(map(len, text.splitlines())) <= 80
    compact = "".join(text.split())
    for operation in operations:
        assert "".join(operation_label(result, operation.operation).split()) in compact
    assert "[bold]literal[/bold]" in text
    report = build_report(scan, ai_interpretation=result)
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        document = render_report(report, format)
        text = human_text(document)
        assert prose in text and summary in text
        assert "endpoint_1" in text and "endpoint_2" in text
        if format is ReportFormat.HTML:

            class Tags(HTMLParser):
                def handle_starttag(self, tag, attrs):
                    assert tag != "script"

            Tags().feed(document)
    assert result == before


@pytest.mark.parametrize("status", [AIAnalysisStatus.NOT_RUN, AIAnalysisStatus.UNAVAILABLE])
def test_unavailable_and_not_requested_have_no_empty_ai_sections(prepared, status):
    scan, result = prepared
    result = replace(
        result,
        status=status,
        interpretation=None,
        error_message="Local interpretation unavailable.",
    )
    for verbose in (False, True):
        text = capture_ai(result, verbose=verbose)
        assert status.value in text
        assert "OPERATION ANALYSIS" not in text and "INTERPRETIVE SUMMARY" not in text
        assert "Deterministic scan completed normally" in " ".join(text.split())
    section = ai_section(result)
    assert not any(child.title == "Operation Analysis" for child in section.children)
    assert "AI-Assisted Interpretation" not in render_report(
        build_report(scan), ReportFormat.MARKDOWN
    )


def test_default_preserves_detail_policy_and_adds_visible_truncation(prepared):
    _, result = prepared
    result = replace(
        result,
        context_metadata=result.context_metadata.model_copy(
            update={
                "context_truncated": True,
                "operations_omitted": 20,
                "security_facts_omitted": 2,
            }
        ),
    )
    text = " ".join(capture_ai(result, verbose=False).split())
    assert "Model: qwen3:8b" in text and "AI status: SUCCESS" in text
    assert "AI context truncated: 20 operations and 2 security facts omitted" in text
    assert "Manual follow-up:" in text
    assert "additional AI entries available with --verbose or a report" in text
    assert "OPERATION ANALYSIS" not in text and "AI GENERATION METADATA" not in text


@pytest.mark.parametrize("counts", [(13, 19), (6, 0)])
def test_representative_large_and_query_only_reports_are_local(phase_ten_scan, monkeypatch, counts):
    queries, mutations = counts
    sdl = (
        "type Query { "
        + " ".join(f"lookup{i}(id: ID!): Item" for i in range(queries))
        + " } type Item { id: ID children: [Item] }"
    )
    if mutations:
        sdl += (
            " type Mutation { "
            + " ".join(f"createUser{i}(ownerId: ID!): Item" for i in range(mutations))
            + " }"
        )
    scan, requests = phase_ten_scan(sdl, mode=ScanMode.SAFE)
    result = ai_result(scan)
    report = build_report(scan, ai_interpretation=result)
    if not mutations:
        report = replace(
            report,
            endpoints=tuple(
                replace(e, schema_retrieval_summary="PROGRESSIVE: schema retrieved")
                for e in report.endpoints
            ),
        )
    before = deepcopy(scan), deepcopy(result), len(requests)
    context = build_ai_context(scan)
    contract = (
        serialize_context(context),
        build_system_prompt(context),
        build_response_schema(context),
    )
    canonical = render_report(report, ReportFormat.JSON)
    monkeypatch.setattr(HttpClient, "send", lambda *a, **kw: pytest.fail("Target request"))
    monkeypatch.setattr(OllamaClient, "interpret", lambda *a, **kw: pytest.fail("AI request"))
    for verbose in (False, True):
        render_completed_assessment(
            Console(file=StringIO(), width=80, theme=CONSOLE_THEME), scan, verbose=verbose
        )
        capture_ai(result, verbose=verbose)
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        document = human_text(render_report(report, format))
        assert "does not establish target security" in document
        assert "Prioritized Review" in document
        assert f"{queries}" in document
        assert all(operation.name in document for operation in result.references.operations)
        if not mutations:
            assert "PROGRESSIVE: schema retrieved" in document
    assert render_report(report, ReportFormat.JSON) == canonical
    assert contract == (
        serialize_context(build_ai_context(scan)),
        build_system_prompt(context),
        build_response_schema(context),
    )
    assert before == (scan, result, len(requests))


def test_findings_policy_results_and_review_remain_separate(phase_ten_scan):
    scan = assemble(phase_ten_scan(SDL)[0])
    report = build_report(scan)
    snapshot = deepcopy(report)
    view = build_assessment(report)
    assert len(view.findings) == 6 and view.additional_policy_violations == 3
    sections = assessment_sections(report)
    names = [section.title for section in sections]
    assert names.index("Security Findings") < names.index("Prioritized Review")
    stream = StringIO()
    render_completed_assessment(Console(file=stream, width=80, theme=CONSOLE_THEME), scan)
    output = " ".join(stream.getvalue().split())
    assert output.index("FINDINGS") < output.index("CAPABILITY RESULTS")
    assert "Kind" in output and "Review focus" in output
    assert "VIOLATION" in output and "REVIEW" in output
    assert "Review interest is not vulnerability severity" in output
    assert report == snapshot


def test_zero_validation_rows_are_available_in_verbose(prepared):
    scan, _ = prepared
    view = build_assessment(build_report(scan))
    assert "Findings" in dict(view.compact_validation_rows)
    assert "Prioritized review items" in dict(view.compact_validation_rows)
    assert "Scoped controls observed" not in dict(view.compact_validation_rows)
    assert dict(view.validation_rows)["Scoped controls observed"] == "0"
    stream = StringIO()
    render_completed_assessment(
        Console(file=stream, width=80, theme=CONSOLE_THEME), scan, verbose=True
    )
    assert "Scoped controls observed" in stream.getvalue()


def test_missing_projection_and_empty_categories_do_not_invent_metadata(prepared):
    _, result = prepared
    result = replace(result, references=AIReferenceProjection())
    text = " ".join(capture_ai(result).split())
    assert "Reference projection unavailable" in text
    assert "Execution: NOT_ATTEMPTED" not in text
    operation = prepared[1].references.operations[0].model_copy(update={"categories": ()})
    result = replace(prepared[1], references=AIReferenceProjection(operations=(operation,)))
    blocks = dict(interpretation_sections(result))["Operation Analysis"]
    assert "Categories" not in dict(blocks[0].details)


def test_legacy_windows_redirected_utf8_preserves_identity_and_notices(prepared):
    _, result = prepared
    buffer = BytesIO()
    # Follow the documented UTF-8 redirection setup; cp1252 cannot encode box-drawing rules.
    stream = TextIOWrapper(buffer, encoding="utf-8", write_through=True)
    console = Console(
        file=stream,
        width=80,
        height=25,
        force_terminal=False,
        legacy_windows=True,
        no_color=True,
        theme=CONSOLE_THEME,
    )
    render_ai(console, result, verbose=True)
    text = plain_cli_output(buffer.getvalue().decode("utf-8").replace("\r\n", "\n"))
    assert "Mutation: createUser" in text and "NOT_ATTEMPTED" in text
    assert all(len(line) <= 80 for line in text.splitlines())


def test_theme_preserves_multiple_endpoint_attribution(prepared):
    _, result = prepared
    original = result.references.operations[0]
    operations = tuple(
        original.model_copy(update={"operation": f"endpoint_{i}/query/{original.name}"})
        for i in (1, 2)
    )
    theme = result.interpretation.review_insights[0].model_copy(
        update={
            "references": tuple(
                result.interpretation.review_insights[0]
                .references[0]
                .model_copy(update={"ref": op.operation})
                for op in operations
            ),
        }
    )
    result = replace(
        result,
        references=AIReferenceProjection(operations=operations),
        interpretation=result.interpretation.model_copy(update={"review_insights": (theme,)}),
    )
    block = dict(interpretation_sections(result))["Cross-Operation Review Themes"][0]
    assert f"Query: {original.name} (endpoint_1)" in block.title
    assert f"Query: {original.name} (endpoint_2)" in block.title
    assert block.references == tuple(op.operation for op in operations)
    assert block.paragraphs == (theme.interpretation, "Manual follow-up: " + theme.manual_follow_up)
