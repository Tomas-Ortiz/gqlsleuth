"""Completed assessment disclosure never changes deterministic results or AI inputs."""

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO

import pytest
from rich.console import Console

from fixtures.ai_response import security_answer_fields
from fixtures.whole_scan_ai import SDL, SECRET, assemble
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIAnalysisStatus, AIInterpretation, AIInterpretationResult
from gqlsleuth.ai.prompt import build_system_prompt, execution_summary
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.subscriptions import SubscriptionOutcome
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.infrastructure.websocket import WebSocketClient
from gqlsleuth.presentation.assessment import CAPABILITY_ORDER, build_assessment
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
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
    caps = [name for name, _ in summary.capabilities]
    assert caps == [name for name in CAPABILITY_ORDER if name in caps]
    assert ("Query Multiplicity", "OBSERVED") in summary.capabilities
    assert ("Query Depth", "CONTROL") in summary.capabilities
    assert dict(summary.overview)["Upload surface"] == "Detected"
    assert summary.mutations == ()  # Separate capability Mutations are not ordinary executions.


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
    assert "GQLSleuth Assessment" in text and "Security Validation" in text
    assert SECRET not in text
    if not verbose:
        assert "Variables:" not in text and "Response" not in text
        assert "Evidence Summary" not in text
        assert "Use --verbose" in text
    else:
        for title in ("Discovery & Schema", "Operations & Execution", "Specialized Surfaces"):
            assert title in text
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        render_report(report, format)
    assert whole == before
    assert render_report(build_report(whole, generated_at=STAMP), ReportFormat.JSON) == canonical
    after = build_ai_context(whole)
    assert serialize_context(after) == serialized and build_system_prompt(after) == prompt


def test_caps_report_exact_omissions_and_verbose_keeps_every_item(whole):
    auth = whole.authentication_token_security
    expanded = replace(
        whole, authentication_token_security=replace(auth, findings=auth.findings * 12)
    )
    compact = capture(expanded)
    assert "7 additional findings" in compact
    assert "additional findings" not in capture(expanded, verbose=True)
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
    assert f"{len(view.manual_review) - 8} additional manual review items" in capture(expanded)


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
    fields["cross_capability_insights"] = [
        {"security_facts": ["SF1", "SF2"], "text": f"Scoped manual correlation {index}."}
        for index in range(4)
    ]
    interpretation = AIInterpretation.model_validate(
        {
            **fields,
            "scan_summary": {
                "text": execution_summary(context),
                "operations": [],
                "security_facts": [],
            },
            "operation_review": [],
            "limitations": [],
        }
    )
    result = AIInterpretationResult(
        AIAnalysisStatus.SUCCESS, "qwen3:8b", STAMP, 1.0, context.metadata, interpretation
    )
    output = StringIO()
    render_ai(Console(file=output, width=120, theme=CONSOLE_THEME), result)
    text = output.getvalue()
    assert "Security Summary" in text and "Model-generated interpretation" in text
    assert "Execution Summary" not in text and "Security Fact Reviews" not in text
    assert "1 additional AI entries" in text
    output = StringIO()
    render_ai(Console(file=output, width=120, theme=CONSOLE_THEME), result, verbose=True)
    assert "Execution Summary (validated facts)" in output.getvalue()
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
    assert "3 additional limitations; use --verbose." in text
    assert "FAILURE 4" in text and "FAILURE 5" not in text
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
