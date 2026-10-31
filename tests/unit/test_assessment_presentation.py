"""Completed assessment disclosure never changes deterministic results or AI inputs."""

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO

import pytest
from rich.console import Console

from fixtures.ai_response import reference_items, security_answer_fields
from fixtures.whole_scan_ai import SDL, SECRET, assemble
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIAnalysisStatus, AIInterpretation, AIInterpretationResult
from gqlsleuth.ai.prompt import build_system_prompt
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.models import ConfidenceLevel, ScanMode, Target
from gqlsleuth.domain.subscriptions import SubscriptionOutcome
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.infrastructure.websocket import WebSocketClient
from gqlsleuth.presentation.assessment import CAPABILITY_ORDER, build_assessment
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.presentation.multiplicity import render_multiplicity
from gqlsleuth.presentation.query_depth import render_query_depth
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat, ReportIssue
from gqlsleuth.reporting.presentation import human_sections, technical_sections
from gqlsleuth.reporting.renderers import render_report

STAMP = datetime(2026, 9, 25, tzinfo=UTC)


@pytest.fixture
def whole(phase_ten_scan):
    result = assemble(phase_ten_scan(SDL)[0])
    # The AI fixture deliberately embeds a canary in generated business variables,
    # which exact-request human views already display. Use the real generator's
    # placeholder here; keep request-header canaries in retained evidence.
    abuse = result.rate_limiting_abuse_controls
    candidate = replace(abuse.selected, variables={"password": "TestPass123!"})
    return replace(
        result,
        rate_limiting_abuse_controls=replace(abuse, candidates=(candidate,), selected=candidate),
    )


def capture(result, *, verbose=False, width=100):
    output = StringIO()
    render_completed_assessment(
        Console(file=output, width=width, theme=CONSOLE_THEME), result, verbose=verbose
    )
    return output.getvalue()


def test_summary_counts_only_existing_facts_in_explicit_order(whole):
    summary = build_assessment(build_report(whole))
    assert len(summary.findings) == 6
    assert summary.additional_policy_violations == 3
    assert summary.scoped_controls_observed == 1
    assert summary.unresolved_checks == 0
    assert [item.state for item in summary.manual_review[:3]] == ["VIOLATION"] * 3
    assert all(item.state == "REVIEW" for item in summary.manual_review[3:])
    assert summary.review_candidate_count == len(summary.manual_review) - 3
    caps = [name for name, _ in summary.capabilities]
    assert caps == [name for name in CAPABILITY_ORDER if name in caps]
    assert ("Query Multiplicity", "OBSERVED") in summary.capabilities
    assert ("Query Depth", "CONTROL") in summary.capabilities
    assert dict(summary.overview)["Upload surface"] == "Detected"
    assert summary.mutations == ()  # Separate capability Mutations are not ordinary executions.


def test_compact_capability_and_manual_review_status_colors(whole):
    console = Console(file=StringIO(), theme=CONSOLE_THEME, force_terminal=True, width=160)
    segments = []

    def collect(*objects, **kwargs):
        for value in objects:
            if not isinstance(value, str):
                segments.extend(console.render(value))

    console.print = collect
    render_completed_assessment(console, whole)
    for word, color in (("OBSERVED", "green"), ("CONTROL", "green"), ("REVIEW", "yellow")):
        matches = [segment for segment in segments if segment.text.strip() == word]
        assert matches and all(segment.style.color.name == color for segment in matches)


@pytest.mark.parametrize(
    "renderer,attribute,word,color",
    [
        (render_multiplicity, "multiplicity", "ACCEPTED", "green"),
        (render_query_depth, "query_depth", "REJECTED", "yellow"),
    ],
)
def test_compact_active_runtime_observation_colors(whole, renderer, attribute, word, color):
    console = Console(file=StringIO(), theme=CONSOLE_THEME, force_terminal=True, width=160)
    segments = []

    def collect(*objects, **kwargs):
        for value in objects:
            if not isinstance(value, str):
                segments.extend(console.render(value))

    console.print = collect
    renderer(console, getattr(whole, attribute))
    matches = [segment for segment in segments if segment.text.strip() == word]
    assert matches and all(segment.style.color.name == color for segment in matches)


@pytest.mark.parametrize(
    "outcome,policy,controls,unresolved",
    [
        ("explicit_denial", "satisfied", 2, 0),
        ("no_event_before_timeout", None, 1, 1),
        ("network_failure", "unresolved", 1, 1),
        ("indeterminate", "unresolved", 1, 1),
    ],
)
def test_scoped_denial_and_unresolved_are_not_findings(
    whole, outcome, policy, controls, unresolved
):
    subs = whole.subscription_security
    evidence = subs.attempts[0].model_copy(
        update={
            "outcome": SubscriptionOutcome(outcome),
            "evaluation": PolicyStatus(policy) if policy else None,
        }
    )
    updated = replace(whole, subscription_security=replace(subs, attempts=(evidence,), findings=()))
    summary = build_assessment(build_report(updated))
    assert len(summary.findings) == 5
    assert summary.scoped_controls_observed == controls
    assert summary.unresolved_checks == unresolved
    if unresolved:
        assert summary.manual_review[3].state == "UNRESOLVED"
        assert summary.manual_review[3].operation.startswith("subscription ")


@pytest.mark.parametrize("prepared", [False, True])
def test_unexecuted_capability_and_local_candidates_are_not_unresolved(whole, prepared):
    result = replace(
        whole,
        subscription_security=(
            replace(whole.subscription_security, attempts=(), findings=()) if prepared else None
        ),
    )
    summary = build_assessment(build_report(result))
    assert summary.unresolved_checks == 0
    assert summary.review_candidate_count > 0


def test_distinct_endpoint_overview_and_findings_remain_visible(whole):
    report = build_report(whole)
    report = replace(
        report,
        endpoints=(
            *report.endpoints,
            replace(report.endpoints[0], endpoint="https://second.example/graphql"),
        ),
    )
    summary = build_assessment(report)
    assert dict(summary.overview)["GraphQL endpoints"] == "2 confirmed / probable"
    assert len(summary.findings) == 6


@pytest.mark.parametrize(
    "coverage", ["full", "partial", "missing", "parse_failure", "mixed", "none"]
)
def test_human_operation_counts_distinguish_unknown_partial_and_zero(phase_ten_scan, coverage):
    report = build_report(phase_ten_scan("type Query { ping: String }")[0])
    endpoint = report.endpoints[0]
    if coverage == "partial":
        endpoints = (replace(endpoint, schema_retrieval_status="partial"),)
    elif coverage in {"missing", "parse_failure"}:
        endpoints = (
            replace(
                endpoint,
                schema_summary=None,
                schema_retrieval_status=("blocked" if coverage == "missing" else "retrieved"),
            ),
        )
    elif coverage == "mixed":
        endpoints = (
            endpoint,
            replace(
                endpoint,
                endpoint="https://other.example/graphql",
                schema_summary=None,
                schema_retrieval_status="blocked",
            ),
        )
    elif coverage == "none":
        endpoints = ()
    else:
        endpoints = (endpoint,)
    report = replace(report, endpoints=endpoints)
    canonical_before = render_report(report, ReportFormat.JSON)
    overview = dict(build_assessment(report).overview)
    expected_queries = "1"
    expected_absent_roots = "0"
    if coverage in {"missing", "parse_failure", "none"}:
        expected_queries = expected_absent_roots = "Not assessed"
    elif coverage in {"partial", "mixed"}:
        expected_queries = "1 (partial coverage)"
        expected_absent_roots = "0 (partial coverage)"
    assert overview["Queries"] == expected_queries
    assert overview["Mutations"] == overview["Subscriptions"] == expected_absent_roots
    executive = next(s for s in technical_sections(report) if s.title == "Executive Scan Summary")
    assert dict(executive.rows)["Query count"] == expected_queries
    assert dict(executive.rows)["Mutation count"] == expected_absent_roots
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format)
        assert expected_queries in rendered.replace("\\", "")
        assert rendered.count("Safety Notice") == 1
    assert render_report(report, ReportFormat.JSON) == canonical_before
    assert isinstance(report.summary["query_count"], int)


@pytest.mark.parametrize("mode", [ScanMode.SAFE, ScanMode.ACTIVE])
@pytest.mark.parametrize("width", [40, 100])
@pytest.mark.parametrize("endpoint_count", [0, 1, 2])
def test_compact_target_and_discovered_endpoints(
    phase_ten_scan, monkeypatch, mode, width, endpoint_count
):
    import gqlsleuth.presentation.completed as completed

    safe, _ = phase_ten_scan(mode=mode)
    report = build_report(safe)
    target = "https://Example.test:5013/"
    urls = ("https://example.test:5013/graphql", "https://example.test:5013/api/graphql")
    confidences = (ConfidenceLevel.CONFIRMED, ConfidenceLevel.PROBABLE)
    report = replace(
        report,
        target=Target.parse(target),
        endpoints=tuple(
            replace(report.endpoints[0], endpoint=url, confidence=confidence)
            for url, confidence in zip(urls[:endpoint_count], confidences, strict=False)
        )
        + tuple(
            replace(
                report.endpoints[0],
                endpoint=f"https://example.test/{confidence.value}",
                confidence=confidence,
            )
            for confidence in (ConfidenceLevel.POSSIBLE, ConfidenceLevel.NOT_DETECTED)
        ),
    )
    monkeypatch.setattr(completed, "build_report", lambda *args, **kwargs: report)
    text = capture(safe, width=width)
    header = text.split("GraphQL Overview", 1)[0]
    # Rich may fold long URLs on narrow terminals, but must preserve every character.
    compact_header = "".join(header.split())
    assert "Target:" + target in compact_header
    assert "Mode:" + mode.value.upper() in compact_header
    assert header.count("GraphQL endpoint:") == endpoint_count
    for url in urls[:endpoint_count]:
        assert "GraphQLendpoint:" + url in compact_header
    assert "possible" not in header and "not_detected" not in header
    if endpoint_count == 2:
        assert compact_header.index(urls[0]) < compact_header.index(urls[1])
    assert f"{endpoint_count} confirmed / probable" in " ".join(text.split())
    assert max(map(len, text.splitlines())) <= width


@pytest.mark.parametrize("width", [45, 80, 120])
@pytest.mark.parametrize("verbose", [False, True])
def test_rendering_is_local_and_preserves_result_json_and_ai(whole, monkeypatch, width, verbose):
    before = deepcopy(whole)
    report = build_report(whole, generated_at=STAMP)
    canonical = render_report(report, ReportFormat.JSON)
    ai = build_ai_context(whole)
    serialized = serialize_context(ai)
    prompt = build_system_prompt(ai)

    def forbidden(*args, **kwargs):
        pytest.fail("Presentation invoked a transport or model")

    monkeypatch.setattr(HttpClient, "send", forbidden)
    monkeypatch.setattr(OllamaClient, "interpret", forbidden)
    monkeypatch.setattr(WebSocketClient, "__enter__", forbidden)
    text = capture(whole, width=width, verbose=verbose)
    assert max(map(len, text.splitlines())) <= width
    assert "GQLSLEUTH ASSESSMENT" in text and "SECURITY VALIDATION" in text
    assert SECRET not in text
    if not verbose:
        assert "Variables:" not in text and "\nRESPONSE\n" not in text
        assert "Evidence Summary" not in text
        assert "Use --verbose" in text
    else:
        for title in ("Discovery & Schema", "Operations & Execution", "Specialized Surfaces"):
            assert title.upper() in text
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        render_report(report, format)
    assert whole == before
    assert render_report(build_report(whole, generated_at=STAMP), ReportFormat.JSON) == canonical
    after = build_ai_context(whole)
    assert serialize_context(after) == serialized and build_system_prompt(after) == prompt


def test_caps_report_exact_omissions_and_verbose_is_bounded(whole):
    auth = whole.authentication_token_security
    expanded = replace(
        whole, authentication_token_security=replace(auth, findings=auth.findings * 12)
    )
    compact = capture(expanded)
    assert "Showing 10 of 17 findings" in compact
    assert "Showing 10 of 17 findings" not in capture(expanded, verbose=True)
    review = expanded.safe_execution.query_generation.security_review
    generation = replace(
        expanded.safe_execution.query_generation,
        security_review=replace(review, candidates=review.candidates * 4),
    )
    expanded = replace(
        expanded,
        preview=replace(
            expanded.preview,
            safe_execution=replace(expanded.safe_execution, query_generation=generation),
        ),
    )
    view = build_assessment(build_report(expanded))
    assert f"Showing 8 of {len(view.manual_review)} prioritized review items" in capture(expanded)


@pytest.mark.parametrize("format", [ReportFormat.MARKDOWN, ReportFormat.HTML])
def test_human_hierarchy_retains_every_technical_section_and_safety_last(whole, format):
    report = build_report(whole)
    output = render_report(report, format)
    assert output.index("Assessment Summary") < output.index("Security Findings")
    assert output.index("Security Findings") < output.index("Detailed Technical Results")
    for section in technical_sections(report):
        # HTML escapes ampersands; the projection itself preserves exact headings.
        assert (
            section.title.replace("&", "&amp;") in output
            if format is ReportFormat.HTML
            else section.title in output
        )
    assert output.count("Safety Notice") == 1
    assert human_sections(report)[-1].title == "Safety Notice"
    tail = output.split("Safety Notice", 1)[1]
    assert "<h" not in tail and "\n##" not in tail
    if format is ReportFormat.HTML:
        assert '<details class="technical">' in output
        assert '<details class="technical" open' not in output
        assert "<script" not in output


def test_ai_compact_caps_insights_and_verbose_retains_complete_answer(whole):
    context = build_ai_context(whole)
    fields = security_answer_fields(context)
    fields["review_insights"] = [
        {
            "references": reference_items([], ["SF1", "SF2"]),
            "interpretation": f"Scoped manual correlation {index}.",
            "manual_follow_up": "Manually compare the intended policy.",
        }
        for index in range(3)
    ]
    interpretation = AIInterpretation.model_validate(fields)
    result = AIInterpretationResult(
        AIAnalysisStatus.SUCCESS, "qwen3:8b", STAMP, 1.0, context.metadata, interpretation
    )
    output = StringIO()
    render_ai(Console(file=output, width=120, theme=CONSOLE_THEME), result)
    text = output.getvalue()
    assert "INTERPRETIVE SUMMARY" in text and "AI-generated interpretation" in text
    assert "EXECUTION SUMMARY" not in text and "SECURITY FACT REVIEWS" not in text
    assert f"{len(context.operations)} additional AI entries" in text
    output = StringIO()
    render_ai(Console(file=output, width=120, theme=CONSOLE_THEME), result, verbose=True)
    assert "EXECUTION SUMMARY (VALIDATED FACTS)" in output.getvalue()
    report = build_report(whole, ai_interpretation=result)
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert (
            text.index("AI-Assisted Interpretation")
            < text.index("Detailed Technical Results")
            < text.index("Safety Notice")
        )


@pytest.mark.parametrize("sdl", ["type Query { ping: String }", SDL])
def test_safe_default_has_no_mutation_execution_or_disabled_capability_rows(phase_ten_scan, sdl):
    safe, _ = phase_ten_scan(sdl, mode=ScanMode.SAFE)
    view = build_assessment(build_report(safe))
    text = capture(safe)
    assert not view.findings and not view.unresolved_checks
    assert not view.mutations and "Mutation Execution" not in text
    assert "NOT_RUN" not in text


def test_limitations_cap_and_query_classifications_are_not_successes(whole, monkeypatch):
    import gqlsleuth.presentation.completed as completed

    report = build_report(whole)
    statuses = ("success", "graphql_error", "skipped_safety")
    report = replace(
        report,
        queries=tuple(
            replace(query, execution=replace(query.execution, status=status))
            for query, status in zip(report.queries, statuses, strict=True)
        ),
        errors_and_limitations=tuple(
            ReportIssue("generation", "https://example.com/graphql", None, f"failure_{i}", "Detail")
            for i in range(8)
        ),
    )
    view = build_assessment(report)
    assert view.query_outcomes == (("SUCCESS", 1), ("GRAPHQL_ERROR", 1), ("SKIPPED_SAFETY", 1))
    monkeypatch.setattr(completed, "build_report", lambda *args, **kwargs: report)
    text = capture(whole)
    assert "Showing 5 of 9 limitations" in text
    assert "classified SUCCESS contained top-level GraphQL data: null" in " ".join(text.split())
    assert "FAILURE 3" in text and "FAILURE 4" not in text
    assert "FAILURE 7" in capture(whole, verbose=True)


def test_unusable_upload_baseline_is_unresolved_even_when_file_was_rejected(whole):
    from gqlsleuth.domain.file_upload import UploadBaselineStatus, UploadOutcome, UploadProbe

    upload = whole.file_upload_security
    attempt = upload.attempts[0].model_copy(
        update={
            "probe": UploadProbe.BASELINE,
            "outcome": UploadOutcome.EXPLICIT_FILE_REJECTION,
            "evaluation": UploadBaselineStatus.BASELINE_UNUSABLE,
        }
    )
    result = replace(whole, file_upload_security=replace(upload, attempts=(attempt,), findings=()))
    summary = build_assessment(build_report(result))
    assert summary.unresolved_checks == 1
    assert summary.scoped_controls_observed == 1  # Existing depth rejection only.
    assert ("File Upload Security", "UNRESOLVED") in summary.capabilities
