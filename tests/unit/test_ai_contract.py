"""V2 exact operation coverage and bounded referenced interpretation, entirely offline."""

import json
from copy import deepcopy

import pytest

from fixtures.ai_response import reference_items, security_answer_fields
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIValidationError
from gqlsleuth.ai.prompt import build_response_schema, validate_interpretation


@pytest.fixture
def context(phase_ten_scan):
    return build_ai_context(phase_ten_scan()[0])


@pytest.mark.parametrize("count", [0, 1, 5, 8, 12])
def test_exact_operation_coverage_and_schema(context, count):
    operation = context.operations[0]
    context = context.model_copy(
        update={
            "operations": tuple(
                operation.model_copy(
                    update={"operation": f"endpoint_1/query/item{i}", "name": f"item{i}"}
                )
                for i in range(count)
            )
        }
    )
    before = serialize_context(context)
    payload = security_answer_fields(context)
    result = validate_interpretation(json.dumps(payload), context)
    assert [i.operation for i in result.operation_interpretations] == [
        o.operation for o in context.operations
    ]
    schema = build_response_schema(context)
    assert schema["properties"]["operation_interpretations"]["minItems"] == count
    assert schema["properties"]["operation_interpretations"]["maxItems"] == count
    assert set(schema["properties"]) == {
        "summary_interpretation",
        "operation_interpretations",
        "review_insights",
        "limitations",
    }
    assert serialize_context(context) == before


@pytest.mark.parametrize(
    "change,code",
    [
        ("missing", "incomplete_operation_interpretation_set"),
        ("duplicate", "incomplete_operation_interpretation_set"),
        ("invented", "unknown_operation_reference"),
        ("multiple_refs", "invalid_schema"),
        ("extra", "invalid_schema"),
    ],
)
def test_invalid_operation_coverage(context, change, code):
    payload = security_answer_fields(context)
    entries = payload["operation_interpretations"]
    if change == "missing":
        entries.pop()
    elif change == "duplicate":
        entries[1] = deepcopy(entries[0])
    elif change == "invented":
        entries[0]["operation"] = "endpoint_1/query/UNKNOWN"
    elif change == "multiple_refs":
        entries[0]["operation"] = [entries[0]["operation"]]
    else:
        payload["scan_summary"] = {"text": "Invented copied metadata."}
    with pytest.raises(AIValidationError, match=code):
        validate_interpretation(json.dumps(payload), context)


@pytest.mark.parametrize(
    "change,code",
    [
        ("unknown", "unknown_operation_reference"),
        ("duplicate", "invalid_security_references"),
        ("single", "invalid_schema"),
        ("four_refs", "invalid_schema"),
        ("four_insights", "invalid_schema"),
        ("three_limitations", "invalid_schema"),
    ],
)
def test_global_reference_and_item_bounds(context, change, code):
    payload = security_answer_fields(context)
    refs = [o.operation for o in context.operations[:2]]
    insight = {
        "references": reference_items(refs, []),
        "interpretation": "Review the related operation roles together.",
        "manual_follow_up": "Manually compare their intended access policies.",
    }
    payload["review_insights"] = [insight]
    if change == "unknown":
        insight["references"][0]["ref"] = "endpoint_1/query/UNKNOWN"
    elif change == "duplicate":
        insight["references"][1] = insight["references"][0]
    elif change == "single":
        insight["references"].pop()
    elif change == "four_refs":
        insight["references"] += reference_items(security_facts=["SF999", "SF998"])
    elif change == "four_insights":
        payload["review_insights"] *= 4
    else:
        payload["limitations"] = [
            {
                "text": "Untested behavior remains outside scope.",
                "references": reference_items([], []),
            }
        ] * 3
    with pytest.raises(AIValidationError, match=code):
        validate_interpretation(json.dumps(payload), context)


@pytest.mark.parametrize("format", ["json", "markdown", "html"])
def test_report_resolves_every_operation_and_safe_usage(phase_ten_scan, format):
    import httpx

    from gqlsleuth.application.ai_assistance import interpret_completed_scan
    from gqlsleuth.infrastructure.ollama import OllamaClient
    from gqlsleuth.reporting.builder import build_report
    from gqlsleuth.reporting.models import ReportFormat
    from gqlsleuth.reporting.renderers import render_report

    scan = phase_ten_scan()[0]
    context = build_ai_context(scan)
    before = deepcopy(scan)
    payload = security_answer_fields(context)
    # The human report must not reintroduce visible clipping below the schema ceiling.
    summary = "Manually review the intended business policy and the scope of supplied facts. " * 9
    payload["summary_interpretation"]["text"] = summary.strip()
    assert 600 < len(summary) < 800
    client = OllamaClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "model": "qwen3:8b",
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 1700,
                    "eval_count": 713,
                    "message": {"role": "assistant", "content": json.dumps(payload)},
                },
            )
        )
    )
    result = interpret_completed_scan(scan, client=client)
    report = render_report(build_report(scan, ai_interpretation=result), ReportFormat(format))
    assert scan == before and scan.evidence == before.evidence
    assert result.references.operations == context.operations
    if format == "json":
        document = json.loads(report)
        assert document["report_schema_version"] == 2
        ai = document["ai_interpretation"]
        assert ai["ai_contract_version"] == 2
        assert set(ai["interpretation"]) == set(payload)
        assert ai["interpretation"]["summary_interpretation"] == payload["summary_interpretation"]
        assert set(ai["interpretation"]["summary_interpretation"]) == {"text", "references"}
        assert ai["references"]["operations"] == [
            o.model_dump(mode="json") for o in context.operations
        ]
        assert ai["attempts"][0]["usage"]["completion_tokens"] == 713
        assert ai["usage"]["total_completion_tokens"] == 713
    else:
        for operation in context.operations:
            assert operation.name in report
        assert (
            "see JSON for full text"
            not in report.split("Interpretive Summary", 1)[1].split("Operation Analysis", 1)[0]
        )
        assert "Operation Analysis" in report and "AI Generation Metadata" in report
        assert "Completion tokens remaining" in report
        assert "1,335" in report and "Review interest" in report
        assert report.count("Safety Notice") == 1
        tail = report.split("Safety Notice")[1]
        assert "<h" not in tail and "\n##" not in tail


def test_compact_hides_usage_verbose_resolves_all_operations(phase_ten_scan):
    from datetime import UTC, datetime
    from io import StringIO

    from rich.console import Console

    from gqlsleuth.ai.models import AIAnalysisStatus, AIInterpretationResult, AIReferenceProjection
    from gqlsleuth.ai.prompt import execution_summary
    from gqlsleuth.presentation.console import CONSOLE_THEME, render_ai

    context = build_ai_context(phase_ten_scan()[0])
    interpretation = validate_interpretation(json.dumps(security_answer_fields(context)), context)
    result = AIInterpretationResult(
        AIAnalysisStatus.SUCCESS,
        "qwen3:8b",
        datetime.now(UTC),
        0,
        context.metadata,
        interpretation,
        references=AIReferenceProjection(
            operations=context.operations, security_facts=context.security_facts
        ),
        execution_summary=execution_summary(context),
    )
    compact, verbose = StringIO(), StringIO()
    render_ai(Console(file=compact, width=120, theme=CONSOLE_THEME), result)
    render_ai(Console(file=verbose, width=120, theme=CONSOLE_THEME), result, verbose=True)
    assert "tokens" not in compact.getvalue() and "Generation Metadata" not in compact.getvalue()
    for operation in context.operations:
        assert operation.operation in verbose.getvalue()
    assert "Review interest" in verbose.getvalue() and "Manual follow-up" in verbose.getvalue()
