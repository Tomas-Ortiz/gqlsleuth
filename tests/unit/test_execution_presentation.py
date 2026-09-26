"""Offline response evidence, priority styling, and immutable AI/scan presentation boundaries."""

import base64
import json
import re
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from html import unescape
from io import StringIO

import httpx
import pytest
from rich.console import Console
from rich.style import Style
from rich.table import Table

from fixtures.ai_response import security_answer_fields
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIAnalysisStatus, AIInterpretationResult
from gqlsleuth.ai.prompt import execution_summary, validate_interpretation
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.domain.analysis import InterestPriority
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.presentation.console import (
    CONSOLE_THEME,
    render_active_execution,
    render_ai,
    render_mutations,
    render_scan,
)
from gqlsleuth.presentation.priorities import PRIORITY_STYLES, priority_label, style_priority_terms
from gqlsleuth.presentation.responses import MAX_HUMAN_RESPONSE_BODY_BYTES, present_response_body
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections, technical_sections
from gqlsleuth.reporting.renderers import render_report

STAMP = datetime(2026, 9, 11, tzinfo=UTC)
SDL = """
type Query { ok: String problem: String plain: String binary: String network: String
             oversized: String readAndBurn: String }
input UserInput { email: String! password: String! username: String! }
type Mutation { createUser(userData: UserInput!): User login(password: String!): Auth
                deleteUser: String }
type Auth { accessToken: String }
type User { id: ID! email: String password: String }
"""
LARGE_BODY = b'{"data":"' + b"BODY_PREFIX" * 7000 + b'UNSHOWN_TAIL"}'


@pytest.fixture
def execution_views(phase_ten_scan, monkeypatch):
    safe, requests = phase_ten_scan(SDL)

    def handler(request):
        query = json.loads(request.content)["query"]
        if "network" in query:
            raise httpx.ConnectError("Offline failure", request=request)
        if "oversized" in query:
            return httpx.Response(200, content=LARGE_BODY)
        if "binary" in query:
            return httpx.Response(200, content=b"\x00\xff\x80")
        if "plain" in query:
            return httpx.Response(
                503, text='</code><script>alert("fake")</script>\n```\nPLAIN_BODY'
            )
        if "problem" in query or "login" in query:
            return httpx.Response(
                200, json={"data": None, "errors": [{"message": "OBSERVED_ERROR"}]}
            )
        marker = "MUTATION_BODY" if query.startswith("mutation") else "QUERY_BODY"
        return httpx.Response(200, json={"data": {"value": marker}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        safe = execute_generated_queries(safe.query_generation, client=client)
        preview = prepare_active_mutations(safe)
        indices = tuple(
            i for i, candidate in enumerate(preview.candidates, 1) if candidate.selectable
        )
        active = execute_selected_mutations(
            preview, selected_indices=indices, confirmed=True, client=client
        )

    def forbidden(*args, **kwargs):
        pytest.fail("Presentation initiated network/inference")

    monkeypatch.setattr(HttpClient, "send", forbidden)
    monkeypatch.setattr(OllamaClient, "interpret", forbidden)
    before = deepcopy((safe, active, requests))
    yield safe, active
    assert (safe, active, requests) == before


def capture(renderer, *args, width=100, **kwargs):
    stream = StringIO()
    console = Console(file=stream, width=width, theme=CONSOLE_THEME, color_system=None)
    renderer(console, *args, **kwargs)
    return stream.getvalue()


@pytest.mark.parametrize(
    "priority,color",
    [
        (InterestPriority.CRITICAL_INTEREST, "magenta"),
        (InterestPriority.HIGH_INTEREST, "red"),
        (InterestPriority.MEDIUM_INTEREST, "yellow"),
        (InterestPriority.LOW_INTEREST, "green"),
        (InterestPriority.INFORMATIONAL, "bright_blue"),
    ],
)
def test_priority_labels_and_ai_terms_share_exact_styles(priority, color):
    label = priority_label(priority)
    compact = priority_label(priority, compact=True)
    prose = style_priority_terms(label.plain.lower())
    assert label.style == compact.style == prose.spans[0].style == PRIORITY_STYLES[priority]
    assert Style.parse(label.style).color.name == color
    assert prose.plain == label.plain


def test_priority_terms_do_not_match_substrings_or_interpret_markup():
    raw = (
        "[bold]high interest[/bold], critical, medium, low, informational; "
        "highly highlight lowly high_value"
    )
    styled = style_priority_terms(raw)
    assert styled.plain == (
        "[bold]HIGH INTEREST[/bold], CRITICAL, MEDIUM, LOW, INFORMATIONAL; "
        "highly highlight lowly high_value"
    )
    assert len(styled.spans) == 5
    assert all(span.style != "bold" for span in styled.spans)


@pytest.mark.parametrize("title", ["Active Mutation candidates:", "Selected Mutations:"])
def test_endpoint_grouping_preserves_indices_documents_and_priorities(execution_views, title):
    candidates = execution_views[1].preview.candidates
    second = replace(
        candidates[1],
        generated_mutation=replace(
            candidates[1].generated_mutation,
            operation=replace(
                candidates[1].generated_mutation.operation, endpoint="https://other.example/graphql"
            ),
        ),
    )
    items = ((1, candidates[0]), (2, second), (3, candidates[2]))
    output = capture(render_mutations, items, title=title)
    assert output.count("Endpoint: https://example.com/graphql") == 1
    assert output.count("Endpoint: https://other.example/graphql") == 1
    assert output.index("[1]") < output.index("[3]") < output.index("[2]")
    for index, candidate in items:
        assert f"[{index}]" in output
        assert candidate.generated_mutation.operation_name in output
        if candidate.selectable:
            assert candidate.generated_mutation.query_text in output
            assert "Variables: " + json.dumps(
                candidate.generated_mutation.variables, sort_keys=True
            ) in " ".join(output.split())
    assert "Destructive action token(s): delete." in output


def test_review_and_preview_use_priority_spans(execution_views):
    safe, active = execution_views
    segments = []
    console = Console(file=StringIO(), theme=CONSOLE_THEME, width=120, force_terminal=True)

    def collect(*objects, **kwargs):
        for value in objects:
            if isinstance(value, str):
                continue
            segments.extend(console.render(value))

    # Inspect actual rendered components, including tables, rather than ANSI snapshots.
    console.print = collect
    render_scan(console, safe, verbose=True)
    render_mutations(
        console, tuple(enumerate(active.preview.candidates, 1)), title="Selected Mutations:"
    )
    for priority in (InterestPriority.CRITICAL_INTEREST, InterestPriority.HIGH_INTEREST):
        word = priority_label(priority, compact=True).plain
        matches = [segment for segment in segments if word in segment.text]
        assert len(matches) >= 3
        assert all(
            segment.style.color == Style.parse(PRIORITY_STYLES[priority]).color
            for segment in matches
        )


@pytest.mark.parametrize(
    "body,language,notice",
    [
        (b'{"b":2,"a":1}', "json", None),
        (b"plain <tag> ``` [bold]text[/bold]", "text", None),
        (b"\xff\x00", "text", "Binary/unrenderable"),
        (b"control\x1b[31m", "text", "Binary/unrenderable"),
        (b"", "text", "Empty response body"),
        (b"[" * 15000 + b"]" * 15000, "text", "exceeds supported nesting"),
        (b'{"value":NaN}', "text", None),
    ],
    ids=["json", "plain", "binary", "control", "empty", "deep", "nan"],
)
def test_response_formatting_is_controlled_and_deterministic(body, language, notice):
    view = present_response_body(body)
    assert view == present_response_body(body)
    assert view.language == language
    if notice:
        assert notice in view.notice
        assert not view.text
    else:
        assert view.notice is None
    if language == "json":
        assert view.text == '{\n  "a": 1,\n  "b": 2\n}'


@pytest.mark.parametrize(
    "body",
    [
        LARGE_BODY,
        b"a" * (MAX_HUMAN_RESPONSE_BODY_BYTES - 1) + "😀tail".encode(),
        json.dumps(list(range(11000)), separators=(",", ":")).encode(),
    ],
    ids=["raw-prefix", "utf8-boundary", "pretty-expansion"],
)
def test_body_limit_bounds_raw_prefix_and_pretty_print_expansion(body):
    view = present_response_body(body)
    assert len(view.text.encode()) <= MAX_HUMAN_RESPONSE_BODY_BYTES
    assert "truncated" in view.notice
    assert "canonical JSON evidence" in view.notice
    assert "UNSHOWN_TAIL" not in view.text
    assert "\ufffd" not in view.text


def test_query_response_console_is_verbose_only_and_mutations_show_actual_responses(
    execution_views,
):
    safe, active = execution_views
    compact = capture(render_scan, safe)
    verbose = capture(render_scan, safe, verbose=True)
    assert "QUERY_BODY" not in compact and "BODY_PREFIX" not in compact
    assert '"value": "QUERY_BODY"' in verbose
    assert "OBSERVED_ERROR" in verbose
    assert "PLAIN_BODY" in verbose and "Binary/unrenderable" in verbose
    assert "No HTTP response was received" in verbose
    assert "truncated" in verbose and "UNSHOWN_TAIL" not in verbose
    assert verbose.count("\nResponse\n") == 6
    assert "readAndBurn - " not in verbose
    output = capture(render_active_execution, active)
    assert "2 executed; 1 SUCCESS; 1 GRAPHQL_ERROR." in output
    assert "MUTATION_BODY" in output and "OBSERVED_ERROR" in output
    assert output.count("\nResponse\n") == 2
    assert "deleteUser" not in output
    for repeated in ("identified", "generated", "blocked for safety", "selected", "confirmed"):
        assert repeated not in output


@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_reports_show_attempted_query_and_mutation_responses_safely(execution_views, format):
    active = execution_views[1]
    context = build_report(active, generated_at=STAMP)
    before = render_report(context, ReportFormat.JSON)
    output = render_report(context, format)
    assert "QUERY_BODY" in output and "MUTATION_BODY" in output
    assert "OBSERVED_ERROR" in output and "PLAIN_BODY" in output
    assert "Binary/unrenderable" in output
    assert "truncated" in output and "UNSHOWN_TAIL" not in output
    assert "Duration" in output
    assert "No HTTP response was received" in output
    sections = {section.title: section for section in technical_sections(context)}
    queries = {entry.title: entry for entry in sections["Safe Query Execution"].entries}
    assert queries["readAndBurn"].response is None
    assert queries["readAndBurn"].request_blocks == ()
    blocked = next(
        entry
        for entry in sections["Active Mutation Analysis"].entries
        if "deleteUser" in entry.title
    )
    assert blocked.response is None and blocked.request_blocks == ()
    if format is ReportFormat.HTML:
        assert output.count("<details>") == 8
        assert "<summary>Server response - HTTP 200 - SUCCESS</summary>" in output
        assert "<script>" not in output and "&lt;script&gt;" in output
        assert '"value": "QUERY_BODY"' in unescape(output)
    else:
        assert output.count("#### Response") == 8
        assert "````text\n</code><script>" in output
        assert '"value": "QUERY_BODY"' in output
    assert render_report(context, ReportFormat.JSON) == before
    canonical = json.loads(before)
    execution = next(
        item["execution"]
        for item in canonical["queries"]
        if item["generated"]["operation"]["name"] == "oversized"
    )
    assert base64.b64decode(execution["response"]["body"]["data"]) == LARGE_BODY
    assert any(
        base64.b64decode(item["response_body"]["data"]) == LARGE_BODY
        for item in canonical["evidence"]
        if item.get("response_body")
    )
    context_text = serialize_context(build_ai_context(active))
    for marker in ("QUERY_BODY", "MUTATION_BODY", "OBSERVED_ERROR", "BODY_PREFIX", "PLAIN_BODY"):
        assert marker not in context_text


@pytest.mark.parametrize("selected", [False, True])
def test_unexecuted_batch_has_no_response_and_decline_is_concise(execution_views, selected):
    active = execute_selected_mutations(
        execution_views[1].preview,
        selected_indices=(1,) if selected else (),
        confirmed=False,
    )
    output = capture(render_active_execution, active)
    assert "0 executed." in output and "Response" not in output
    assert ("Batch confirmation declined" in output) is selected
    for section in technical_sections(build_report(active)):
        if section.title == "Active Mutation Analysis":
            assert all(entry.response is None for entry in section.entries)


@pytest.fixture
def ai_view(execution_views):
    active = execution_views[1]
    context = build_ai_context(active)
    reference = context.operations[0].operation
    prose = (
        "[bold]high-interest[/bold] and highly relevant; critical-interest, medium-interest, "
        "low-interest, informational-interest."
    )
    interpretation = validate_interpretation(
        json.dumps(
            {
                **security_answer_fields(context),
                "scan_summary": {"text": execution_summary(context), "operations": []},
                "operation_review": [{"operation": reference, "explanation": prose}],
                "limitations": [{"operations": [], "text": "Runtime assessment remains limited."}],
            }
        ),
        context,
    )
    return AIInterpretationResult(
        AIAnalysisStatus.SUCCESS, "qwen3:8b", STAMP, 0.1, context.metadata, interpretation
    )


@pytest.mark.parametrize("width", [45, 100])
def test_ai_tables_preserve_stored_prose_and_validated_facts(execution_views, ai_view, width):
    active = execution_views[1]
    context = build_ai_context(active)
    result = ai_view
    interpretation = result.interpretation
    prose = interpretation.operation_review[0].explanation
    report = build_report(active, generated_at=STAMP, ai_interpretation=result)
    before = tuple(render_report(report, format) for format in ReportFormat)
    output = capture(render_ai, result, width=width, verbose=True)
    assert max(map(len, output.splitlines())) <= width
    assert "AI-Assisted Interpretation" in output
    assert "Model-generated interpretation" in output
    assert "Execution Summary" in output and "Review Focus" not in output
    assert "Operation Review" in output
    assert "Operation Explanations" not in output and "Manual Review Suggestions" not in output
    assert "Limitations" in output
    assert "HIGH" in output and "CRITICAL" in output
    assert "[bold]" in output
    assert "highly" in output
    normalized = " ".join(output.split())
    assert "6 attempted" in normalized and "1 SUCCESS" in normalized
    assert interpretation.scan_summary.text == execution_summary(context)
    assert interpretation.operation_review[0].explanation == prose
    assert tuple(render_report(report, format) for format in ReportFormat) == before
    if width == 100:
        segments = []
        console = Console(file=StringIO(), width=width, theme=CONSOLE_THEME)

        def collect(*objects, **kwargs):
            for value in objects:
                if not isinstance(value, str):
                    segments.extend(console.render(value))

        console.print = collect
        render_ai(console, result, verbose=True)
        references = [segment for segment in segments if "endpoint_1" in segment.text]
        assert len(references) == 1
        assert all(segment.style.color.name == "cyan" for segment in references)


def assert_separated(output, label):
    prefix = output[: output.index(label)]
    assert prefix.endswith("\n\n")
    assert not prefix.endswith("\n\n\n")


def test_heading_reference_and_response_hierarchy():
    console = Console(theme=CONSOLE_THEME)
    heading = console.get_style("gql.section")
    reference = console.get_style("gql.metadata")
    response = console.get_style("gql.response")
    assert heading.bold and heading.color.name == "bright_white"
    assert reference.color.name == "cyan"
    assert heading != reference and heading != response
    assert response.bold and response.dim
    assert all(heading.color != Style.parse(style).color for style in PRIORITY_STYLES.values())


def test_rendered_titles_and_tables_use_structural_styles(execution_views, ai_view, monkeypatch):
    console = Console(file=StringIO(), theme=CONSOLE_THEME, width=100)
    titles = []
    tables = []
    original_print = console.print

    def collect(*objects, **kwargs):
        if kwargs.get("style") == "gql.section":
            titles.extend(objects)
        tables.extend(item for item in objects if isinstance(item, Table))
        original_print(*objects, **kwargs)

    monkeypatch.setattr(console, "print", collect)
    safe, active = execution_views
    render_scan(console, safe)
    for title in ("Active Mutation candidates:", "Selected Mutations:"):
        render_mutations(console, tuple(enumerate(active.preview.candidates, 1)), title=title)
    render_active_execution(console, active)
    render_ai(console, ai_view, verbose=True)
    assert titles == [
        "Security Review",
        "Generated Queries",
        "Query Execution",
        "Active Mutation candidates:",
        "Selected Mutations:",
        "Mutation Execution",
        "AI-Assisted Interpretation",
        "Execution Summary (validated facts)",
        "Security Summary",
        "Security Fact Reviews",
        "Security Controls Observed",
        "Cross-Capability Analysis",
        "Operation Review",
        "Limitations",
    ]
    for table in tables:
        stream = StringIO()
        Console(file=stream, theme=CONSOLE_THEME, width=100).print(table)
        assert all(line.strip() for line in stream.getvalue().splitlines())


@pytest.mark.parametrize("width", [45, 100])
def test_structural_console_spacing(execution_views, ai_view, width):
    safe, active = execution_views
    compact = capture(render_scan, safe, width=width)
    for title in ("Security Review", "Generated Queries", "Query Execution"):
        assert_separated(compact, title)
    assert re.search(r"\n\n +Operation +Outcome", compact)
    assert len(compact.splitlines()) < 65
    assert "QUERY_BODY" not in compact

    output = capture(render_ai, ai_view, width=width, verbose=True)
    for title in (
        "Execution Summary",
        "Operation Review",
        "Limitations",
    ):
        assert_separated(output, title)
    assert "Model: qwen3:8b\nAI status: SUCCESS\n\nExecution Summary" in output
    assert "Operation Review\n\n" in output
    for rendered in (compact, output):
        assert "\n\n\n" not in rendered
        assert max(map(len, rendered.splitlines())) <= width
        assert all(not line or line.strip() for line in rendered.splitlines())

    for title in ("Active Mutation candidates:", "Selected Mutations:"):
        candidates = tuple(enumerate(active.preview.candidates, 1))
        preview = capture(render_mutations, candidates, title=title, width=100)
        for index, _candidate in candidates[1:]:
            assert_separated(preview, f"[{index}]")
        for _, candidate in candidates:
            if candidate.selectable:
                assert candidate.generated_mutation.query_text in preview
        assert "\n\n\n" not in preview

    for renderer, result, kwargs in (
        (render_active_execution, active, {}),
        (render_scan, safe, {"verbose": True}),
    ):
        output = capture(renderer, result, width=100, **kwargs)
        for item in result.executions:
            if item.attempted:
                name = (
                    item.preview.generated_mutation.operation_name
                    if renderer is render_active_execution
                    else item.operation_name
                )
                assert_separated(output, f"{name} - ")
        marker = "MUTATION_BODY" if renderer is render_active_execution else "QUERY_BODY"
        assert '{\n  "data": {\n    "value": "' + marker + '"\n  }\n}' in output


@pytest.mark.parametrize("with_ai", [False, True])
@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_safety_notice_is_the_only_final_human_section(execution_views, ai_view, with_ai, format):
    report = build_report(
        execution_views[1], generated_at=STAMP, ai_interpretation=ai_view if with_ai else None
    )
    canonical = render_report(report, ReportFormat.JSON)
    sections = human_sections(report)
    assert sections[-1].title == "Safety Notice"
    assert sections[-1].paragraphs[0] == report.safety_notice
    output = render_report(report, format)
    assert output.count("Safety Notice") == 1
    if with_ai:
        assert output.index("AI-Assisted Interpretation") < output.index("Safety Notice")
    if format is ReportFormat.HTML:
        assert re.findall(r"<h2>(.*?)</h2>", output)[-1] == "Safety Notice"
        tail = output.split("<h2>Safety Notice</h2>")[1]
        assert tail.count("<p>") == 2
        assert tail.rstrip().endswith("</section>\n</main>\n</body>\n</html>")
        assert re.sub(r"<p>.*?</p>|</(?:section|main|body|html)>|\s", "", tail, flags=re.S) == ""
    else:
        assert re.findall(r"^## (.+)$", output, flags=re.M)[-1] == "Safety Notice"
        tail = output.split("## Safety Notice\n")[1]
        assert len(tail.strip().split("\n\n")) == 2
        assert tail.rstrip().endswith("potentially sensitive pentest artifact\\.")
    assert render_report(report, ReportFormat.JSON) == canonical
