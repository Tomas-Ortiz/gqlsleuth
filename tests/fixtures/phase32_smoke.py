"""Offline presentation samples: uv run python tests/fixtures/phase32_smoke.py."""

import sys
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AIAnalysisStatus, AIInterpretation, AIInterpretationResult
from gqlsleuth.ai.prompt import execution_summary
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.subscriptions import SubscriptionOutcome
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.websocket import WebSocketClient
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


def main():
    # Test-only fixture reuse; its entire scanning transport is httpx.MockTransport.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from conftest import phase_ten_scan
    from fixtures.ai_response import security_answer_fields
    from fixtures.whole_scan_ai import SDL, assemble

    scan = phase_ten_scan.__wrapped__()
    simple, _ = scan("type Query { ping: String }", mode=ScanMode.SAFE)
    review, _ = scan(SDL, mode=ScanMode.SAFE)
    active_safe, _ = scan(SDL)
    active = execute_selected_mutations(prepare_active_mutations(active_safe), confirmed=False)
    whole = assemble(active_safe)
    abuse = whole.rate_limiting_abuse_controls
    candidate = replace(abuse.selected, variables={"password": "TestPass123!"})
    fed = whole.federation_security
    whole = replace(
        whole,
        rate_limiting_abuse_controls=replace(abuse, candidates=(candidate,), selected=candidate),
        federation_security=replace(
            fed,
            findings=(replace(fed.findings[0], label="Federation entity authorization weakness"),),
        ),
    )
    subs = whole.subscription_security
    attempt = subs.attempts[0].model_copy(
        update={
            "outcome": SubscriptionOutcome.NO_EVENT_BEFORE_TIMEOUT,
            "evaluation": PolicyStatus.UNRESOLVED,
        }
    )
    unresolved = replace(
        whole, subscription_security=replace(subs, attempts=(attempt,), findings=())
    )
    context = build_ai_context(whole)
    answer = AIInterpretation.model_validate(
        {
            **security_answer_fields(context),
            "scan_summary": {
                "text": execution_summary(context),
                "operations": [],
                "security_facts": [],
            },
            "operation_review": [],
            "limitations": [],
        }
    )
    ai = AIInterpretationResult(
        AIAnalysisStatus.SUCCESS, "qwen3:8b", datetime.now(UTC), 0, context.metadata, answer
    )
    samples = (
        ("safe-simple", simple, False, 100, None),
        ("safe-review", review, False, 100, None),
        ("active-no-findings", active, False, 100, None),
        ("active-findings", whole, False, 100, None),
        ("active-unresolved", unresolved, False, 100, None),
        ("active-ai", whole, False, 100, ai),
        ("active-verbose", whole, True, 100, None),
        ("active-narrow", whole, False, 45, None),
    )
    destination = Path("reports/phase32")
    destination.mkdir(parents=True, exist_ok=True)

    def forbidden(*args, **kwargs):
        raise AssertionError("Presentation attempted networking")

    with (
        patch.object(HttpClient, "send", forbidden),
        patch.object(WebSocketClient, "__enter__", forbidden),
    ):
        for name, result, verbose, width, interpretation in samples:
            stream = StringIO()
            console = Console(file=stream, theme=CONSOLE_THEME, width=width)
            render_completed_assessment(console, result, verbose=verbose, ai_result=interpretation)
            if interpretation:
                render_ai(console, interpretation, verbose=verbose)
            text = stream.getvalue()
            assert max(map(len, text.splitlines())) <= width
            (destination / f"{name}.txt").write_text(text, encoding="utf-8")
            print(f"{name}: {len(text.splitlines())} lines, width {width}")
        report = build_report(whole, ai_interpretation=ai)
        for format, suffix in ((ReportFormat.MARKDOWN, "md"), (ReportFormat.HTML, "html")):
            text = render_report(report, format)
            assert text.count("Safety Notice") == 1
            assert text.index("AI-Assisted Interpretation") < text.index("Safety Notice")
            (destination / f"assessment.{suffix}").write_text(text, encoding="utf-8")
    print(f"Artifacts: {destination.resolve()}; presentation HTTP/WS requests: 0; model calls: 0")


if __name__ == "__main__":
    main()
