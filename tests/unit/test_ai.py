"""Offline allowlist, inference, reference-validation, and additive-report boundaries."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime

import httpx
import pytest

from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import MAX_AI_OPERATIONS, MAX_CONTEXT_BYTES, AIAnalysisStatus
from gqlsleuth.ai.prompt import execution_summary, validate_interpretation
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.domain.analysis import InterestPriority, OperationCategory
from gqlsleuth.domain.models import Evidence, ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import MAX_AI_RESPONSE_BYTES, OllamaClient
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


def answer(context):
    operation = context.operations[0].operation if context.operations else None
    return {
        "scan_summary": {"text": execution_summary(context), "operations": []},
        "operation_review": [
            {
                "operation": operation,
                "explanation": "The apparent role needs manual review against the schema; "
                "only the recorded execution outcome is known.",
            }
        ]
        if operation
        else [],
        "limitations": [{"text": "No vulnerability is confirmed.", "operations": []}],
    }


def envelope(content):
    return {
        "model": "qwen3:8b",
        "done": True,
        "done_reason": "stop",
        "message": {
            "role": "assistant",
            "content": content,
            "thinking": "THINKING_CANARY_DO_NOT_KEEP",
        },
    }


@pytest.fixture
def completed(phase_ten_scan):
    safe, _ = phase_ten_scan(mode=ScanMode.ACTIVE)
    with HttpClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"data": None}))
    ) as client:
        active = execute_selected_mutations(
            prepare_active_mutations(safe), selected_indices=(1,), confirmed=True, client=client
        )
    return active


def test_allowlisted_context_preserves_order_and_normalized_states(completed):
    before = deepcopy(completed)
    context = build_ai_context(completed)
    assert context == build_ai_context(completed)
    assert context.mode is ScanMode.ACTIVE
    assert context.final_batch_confirmed
    assert context.schemas[0].query_root == "Query"
    assert context.schemas[0].mutation_root == "Mutation"
    assert context.schemas[0].queries == 2
    assert context.schemas[0].mutations == 6
    assert context.counts["query_requests"] == 1
    assert context.counts["mutation_requests"] == 1
    operations = {item.name: item for item in context.operations}
    assert operations["createUser"].kind.value == "mutation"
    assert operations["createUser"].interest_score > 0
    assert OperationCategory.USER_MANAGEMENT in operations["createUser"].categories
    assert operations["deleteUser"].mutation_safety.value == "blocked_safety"
    assert not operations["deleteUser"].attempted
    assert operations["health"].execution_status.value == "success"
    assert operations["health"].http_status == 200
    assert operations["readAndBurn"].execution_status.value == "skipped_safety"
    assert completed == before


def test_context_is_prioritized_and_bounded_by_count_and_bytes(phase_ten_scan):
    fields = " ".join(f"field{i}: String" for i in range(30))
    safe, _ = phase_ten_scan(f"type Query {{ {fields} login: String admin: String }}")
    context = build_ai_context(safe)
    assert context.metadata.operations_total == 32
    assert context.metadata.operations_included <= MAX_AI_OPERATIONS
    assert context.metadata.operations_omitted == 32 - len(context.operations)
    assert context.metadata.context_truncated
    assert context.operations[0].interest_score > 0
    assert len(serialize_context(context).encode("utf-8")) <= MAX_CONTEXT_BYTES
    assert context.counts["query_success"] == 20
    assert context.counts["query_skipped_limit"] == 12
    assert "20 SUCCESS" in execution_summary(context)
    assert "12 SKIPPED_LIMIT" in execution_summary(context)

    analysis = safe.query_generation.operation_analysis
    long_operations = tuple(
        replace(
            item,
            name=f"long{i}" + "X" * 110,
            categories=tuple(OperationCategory),
            priority=InterestPriority.CRITICAL_INTEREST,
        )
        for i, item in enumerate(analysis.endpoints[0].operations)
    )
    expanded = replace(
        safe,
        query_generation=replace(
            safe.query_generation,
            operation_analysis=replace(
                analysis, endpoints=(replace(analysis.endpoints[0], operations=long_operations),)
            ),
        ),
    )
    large = build_ai_context(expanded)
    assert len(large.operations) < MAX_AI_OPERATIONS
    assert large.metadata.operations_included + large.metadata.operations_omitted == 32
    assert len(serialize_context(large).encode("utf-8")) <= MAX_CONTEXT_BYTES


def test_empty_context_still_accepts_valid_structured_interpretation(phase_ten_scan):
    safe, _ = phase_ten_scan("type Query { health: String }")
    analysis = safe.query_generation.operation_analysis
    safe = replace(
        safe,
        query_generation=replace(
            safe.query_generation, operation_analysis=replace(analysis, endpoints=())
        ),
    )
    context = build_ai_context(safe)
    assert context.operations == ()
    assert validate_interpretation(json.dumps(answer(context)), context)


def test_same_named_query_and_mutation_keep_independent_states(phase_ten_scan):
    safe, _ = phase_ten_scan("type Query { login: String } type Mutation { login: String }")
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("Unselected Mutation executed"))
    ) as client:
        active = execute_selected_mutations(prepare_active_mutations(safe), client=client)
    context = build_ai_context(active)
    query = next(item for item in context.operations if item.kind.value == "query")
    mutation = next(item for item in context.operations if item.kind.value == "mutation")
    assert query.attempted
    assert query.execution_status.value == "success"
    assert query.mutation_decision is None
    assert not mutation.attempted
    assert mutation.execution_status is None
    assert mutation.mutation_decision.value == "not_selected"
    assert query.operation != mutation.operation


CANARIES = (
    "AUTH_CANARY_DO_NOT_SEND",
    "COOKIE_CANARY_DO_NOT_SEND",
    "PASSWORD_CANARY_DO_NOT_SEND",
    "TOKEN_CANARY_DO_NOT_SEND",
    "RESPONSE_BODY_CANARY_DO_NOT_SEND",
    "DATABASE_ERROR_CANARY_DO_NOT_SEND",
    "EVIDENCE_CANARY_DO_NOT_SEND",
    "GRAPHQL_ERROR_CANARY_DO_NOT_SEND",
    "STACK_TRACE_CANARY_DO_NOT_SEND",
    "DESCRIPTION_CANARY_DO_NOT_SEND",
)


def test_canaries_are_excluded_from_exact_ollama_request_by_construction(completed, monkeypatch):
    headers = {"Authorization": CANARIES[0], "Cookie": CANARIES[1]}
    variables = {"password": CANARIES[2], "token": CANARIES[3]}
    raw = " ".join(CANARIES[4:])

    def taint_artifact(item):
        return replace(
            item,
            variables=variables,
            query_text=raw,
            manual_adjustments=(raw,),
            operation=replace(item.operation, reasons=(raw,)),
        )

    safe = completed.safe_execution
    tainted_queries = tuple(taint_artifact(item) for item in safe.query_generation.queries)
    safe = replace(
        safe,
        query_generation=replace(safe.query_generation, queries=tainted_queries),
        executions=tuple(
            replace(
                item,
                error_message=raw,
                reason=raw,
                response=item.response.model_copy(update={"headers": headers, "body": raw.encode()})
                if item.response
                else None,
            )
            for item in safe.executions
        ),
    )
    active = replace(
        completed,
        preview=replace(
            completed.preview,
            safe_execution=safe,
            candidates=tuple(
                replace(
                    item, generated_mutation=taint_artifact(item.generated_mutation), reason=raw
                )
                for item in completed.preview.candidates
            ),
        ),
        executions=tuple(
            replace(
                item,
                error_message=raw,
                reason=raw,
                response=item.response.model_copy(update={"headers": headers, "body": raw.encode()})
                if item.response
                else None,
            )
            for item in completed.executions
        ),
        execution_evidence=tuple(
            item.model_copy(
                update={
                    "summary": raw,
                    "notes": (raw,),
                    "response_body": raw.encode(),
                    "response_headers": headers,
                    "variables": variables,
                }
            )
            for item in completed.execution_evidence
        ),
    )
    before = deepcopy(active)
    requests = []

    def handler(request):
        requests.append(request)
        assert all(canary not in request.content.decode() for canary in CANARIES)
        payload = json.loads(request.content)
        assert request.url == "http://127.0.0.1:11434/api/chat"
        assert request.method == "POST"
        assert payload["model"] == "qwen3:8b"
        assert payload["stream"] is False
        assert payload["think"] is False
        assert payload["messages"][1]["content"] == serialize_context(build_ai_context(active))
        assert payload["format"]["properties"]["scan_summary"]["properties"]["text"]["enum"] == [
            execution_summary(build_ai_context(active))
        ]
        assert set(payload["format"]["properties"]) == {
            "scan_summary",
            "operation_review",
            "limitations",
        }
        prompt = payload["messages"][0]["content"]
        assert "operation_review: Write one concise paragraph per operation" in prompt
        assert "relevant observed execution/result context" in prompt
        assert "manual review direction" in prompt
        assert "why it deserves attention" in prompt
        assert "Always express priority as review" in prompt
        assert "CRITICAL-interest, HIGH-interest, MEDIUM-interest" in prompt
        assert 'Never write "this operation is CRITICAL"' in prompt
        assert '"this mutation is HIGH"' in prompt
        assert "review_focus" not in prompt
        assert "operation_explanations" not in prompt
        assert "manual_review_suggestions" not in prompt
        assert "tools" not in payload
        return httpx.Response(200, json=envelope(json.dumps(answer(build_ai_context(active)))))

    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("AI called target client"))
    result = interpret_completed_scan(
        active, client=OllamaClient(transport=httpx.MockTransport(handler))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert len(requests) == 1
    assert result.duration_seconds >= 0
    assert not isinstance(result, Evidence)
    assert active == before
    assert "THINKING_CANARY" not in str(result)


@pytest.mark.parametrize(
    "section",
    [
        "scan_summary",
        "operation_review",
        "limitations",
    ],
)
def test_unknown_operation_references_reject_the_whole_response(completed, section):
    context = build_ai_context(completed)
    payload = answer(context)
    invented = "endpoint_1/mutation/totallyInventedAdminBackdoor"
    if section == "scan_summary":
        payload[section]["operations"] = [invented]
    elif section == "operation_review":
        payload[section][0]["operation"] = invented
    else:
        payload[section][0]["operations"] = [invented]
    client = OllamaClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=envelope(json.dumps(payload)))
        )
    )
    result = interpret_completed_scan(completed, client=client)
    assert result.status is AIAnalysisStatus.INVALID_RESPONSE
    assert result.interpretation is None
    assert invented not in result.error_message


@pytest.mark.parametrize(
    "invalid", ["not json", "{}", "[]", "null", '<think>private</think>{"scan_summary":"test"}']
)
def test_malformed_model_responses_are_controlled(completed, invalid):
    client = OllamaClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=envelope(invalid)))
    )
    result = interpret_completed_scan(completed, client=client)
    assert result.status is AIAnalysisStatus.INVALID_RESPONSE
    assert result.interpretation is None


@pytest.mark.parametrize("change", ["extra", "long_text", "too_many", "wrong_type"])
def test_output_structure_is_strict_and_bounded(completed, change):
    context = build_ai_context(completed)
    payload = answer(context)
    if change == "extra":
        payload["execute_mutations"] = True
    elif change == "long_text":
        payload["scan_summary"]["text"] = "x" * 601
    elif change == "too_many":
        payload["operation_review"] *= 11
    else:
        payload["scan_summary"]["text"] = 42
    with pytest.raises(ValueError):
        validate_interpretation(json.dumps(payload), context)


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "review_focus",
        "operation_explanations",
        "manual_review_suggestions",
        "long_text",
        "too_many",
    ],
)
def test_operation_review_replaces_obsolete_fields_and_retains_bounds(completed, change):
    context = build_ai_context(completed)
    payload = answer(context)
    if change == "missing":
        del payload["operation_review"]
    elif change == "long_text":
        payload["operation_review"][0]["explanation"] = "x" * 601
    elif change == "too_many":
        payload["operation_review"] *= 11
    else:
        payload[change] = []
    with pytest.raises(ValueError):
        validate_interpretation(json.dumps(payload), context)


@pytest.mark.parametrize(
    "failure, expected, code",
    [
        ("connection", AIAnalysisStatus.UNAVAILABLE, "connection_failed"),
        ("timeout", AIAnalysisStatus.UNAVAILABLE, "timeout"),
        ("missing_model", AIAnalysisStatus.UNAVAILABLE, "model_not_found"),
        ("http", AIAnalysisStatus.HTTP_ERROR, "http_error"),
        ("redirect", AIAnalysisStatus.HTTP_ERROR, "http_error"),
        ("envelope", AIAnalysisStatus.INVALID_RESPONSE, "invalid_response"),
        ("oversized", AIAnalysisStatus.INVALID_RESPONSE, "invalid_response"),
    ],
)
def test_adapter_failures_are_nonfatal_without_retry_or_raw_error_leaks(
    completed, failure, expected, code
):
    calls = []
    before = deepcopy(completed)

    def handler(request):
        calls.append(request)
        if failure == "connection":
            raise httpx.ConnectError("SECRET error dump", request=request)
        if failure == "timeout":
            raise httpx.ReadTimeout("SECRET error dump", request=request)
        if failure == "missing_model":
            return httpx.Response(404, json={"error": 'model "qwen3:8b" not found SECRET'})
        if failure == "http":
            return httpx.Response(500, text="SECRET error dump")
        if failure == "redirect":
            return httpx.Response(307, headers={"location": "https://remote.example.com/"})
        if failure == "oversized":
            return httpx.Response(200, content=b"x" * (MAX_AI_RESPONSE_BYTES + 1))
        return httpx.Response(200, json={"done": False, "error": "SECRET error dump"})

    result = interpret_completed_scan(
        completed, client=OllamaClient(transport=httpx.MockTransport(handler))
    )
    assert result.status is expected
    assert result.error_code == code
    assert len(calls) == 1
    assert result.interpretation is None
    assert "SECRET" not in str(result)
    assert completed == before


@pytest.mark.parametrize("seconds", [0, -1, float("inf"), float("nan"), 181])
def test_inference_timeout_must_remain_finite_and_bounded(seconds):
    with pytest.raises(ValueError):
        OllamaClient(timeout_seconds=seconds)


def test_ai_reports_are_additive_escaped_and_exclude_thinking(completed, monkeypatch):
    context = build_ai_context(completed)
    payload = answer(context)
    payload["operation_review"][0]["explanation"] = (
        '<script>alert("test")</script> Model interpretation.'
    )
    client = OllamaClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=envelope(json.dumps(payload)))
        )
    )
    result = interpret_completed_scan(completed, client=client)
    stamp = datetime(2026, 9, 10, tzinfo=UTC)
    before = build_report(completed, generated_at=stamp)
    after = build_report(completed, generated_at=stamp, ai_interpretation=result)
    monkeypatch.setattr(
        OllamaClient, "interpret", lambda *args: pytest.fail("Report performed inference")
    )
    deterministic = json.loads(render_report(before, ReportFormat.JSON))
    additive = json.loads(render_report(after, ReportFormat.JSON))
    assert "ai_interpretation" not in deterministic
    ai_json = additive.pop("ai_interpretation")
    assert ai_json["status"] == "success"
    assert ai_json["interpretation"] == payload
    assert additive == deterministic
    for format in ReportFormat:
        rendered = render_report(after, format)
        assert "THINKING_CANARY" not in rendered
        if format is not ReportFormat.JSON:
            assert "AI-Assisted Interpretation" in rendered
            assert "Model-generated interpretation" in rendered.replace("\\-", "-")
            assert "AI-Assisted Interpretation" not in render_report(before, format)
            assert "Operation Explanations" not in rendered
            assert "Manual Review Suggestions" not in rendered
            assert "Review Focus" not in rendered
            titles = (
                "Execution Summary (validated facts)",
                "Operation Review",
                "Limitations",
                "Safety Notice",
            )
            ai_section = rendered[rendered.index("AI-Assisted Interpretation") :]
            # Markdown escapes parentheses, but preserves the section labels otherwise.
            ai_section = ai_section.replace("\\(", "(").replace("\\)", ")")
            positions = [ai_section.index(title) for title in titles]
            assert positions == sorted(positions)
            assert ai_section.count("Operation Review") == 1
            assert "<script>" not in rendered
            assert "&lt;script&gt;" in rendered


@pytest.fixture
def mixed_query_outcomes(phase_ten_scan):
    fields = " ".join(f"health{i}: String" for i in range(7))
    safe, _ = phase_ten_scan(
        f"type Query {{ {fields} profile: String info: String "
        "deleteAll: String readAndBurn: String removeItem: String }"
    )

    def handler(request):
        document = json.loads(request.content)["query"]
        if "profile" in document or "info" in document:
            return httpx.Response(200, json={"errors": [{"message": "Fake application error"}]})
        return httpx.Response(200, json={"data": None})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        return execute_generated_queries(safe.query_generation, client=client)


def test_execution_summary_separates_attempts_success_errors_and_skips(mixed_query_outcomes):
    context = build_ai_context(mixed_query_outcomes)
    assert context.counts["query_requests"] == 9
    assert context.counts["query_success"] == 7
    assert context.counts["query_graphql_error"] == 2
    assert context.counts["query_skipped_safety"] == 3
    expected = (
        "Query requests: 9 attempted; 7 SUCCESS; 2 GRAPHQL_ERROR. "
        "Mutation requests: 0 attempted; 0 SUCCESS. "
        "Query skips: 3 SKIPPED_SAFETY; 0 SKIPPED_LIMIT. Unexecuted Mutation candidates: 0."
    )
    assert execution_summary(context) == expected
    assert (
        validate_interpretation(json.dumps(answer(context)), context).scan_summary.text == expected
    )
    # Summary totals must not be recounted from only the included operations.
    omitted = context.model_copy(
        update={
            "operations": (),
            "metadata": context.metadata.model_copy(
                update={
                    "operations_included": 0,
                    "operations_omitted": 12,
                    "context_truncated": True,
                }
            ),
        }
    )
    assert execution_summary(omitted) == expected


@pytest.mark.parametrize(
    "claim",
    [
        "All 9 Query requests executed successfully.",
        "All 12 Queries were successful, including safety skips.",
        "HTTP 200 means the two GraphQL errors executed successfully.",
        "Query requests: 9 attempted; 9 SUCCESS.",
    ],
)
def test_false_execution_summary_is_rejected_without_retry(mixed_query_outcomes, claim):
    context = build_ai_context(mixed_query_outcomes)
    payload = answer(context)
    payload["scan_summary"]["text"] = claim
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=envelope(json.dumps(payload)))

    result = interpret_completed_scan(
        mixed_query_outcomes, client=OllamaClient(transport=httpx.MockTransport(handler))
    )
    assert result.status is AIAnalysisStatus.INVALID_RESPONSE
    assert result.interpretation is None
    assert len(calls) == 1


@pytest.mark.parametrize(
    "status", ["graphql_error", "http_error", "invalid_response", "network_failure"]
)
def test_unsuccessful_attempts_are_never_counted_as_success(phase_ten_scan, status):
    safe, _ = phase_ten_scan()

    def handler(request):
        if status == "graphql_error":
            return httpx.Response(200, json={"data": None, "errors": [{"message": "Fake error"}]})
        if status == "http_error":
            return httpx.Response(500, text="Fake server error")
        if status == "network_failure":
            raise httpx.ConnectError("Fake connection failure", request=request)
        return httpx.Response(200, text="Not a GraphQL response")

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        safe = execute_generated_queries(safe.query_generation, client=client)
        active = execute_selected_mutations(
            prepare_active_mutations(safe), selected_indices=(1,), confirmed=True, client=client
        )
    context = build_ai_context(active)
    assert context.counts["query_requests"] == 1
    assert context.counts["query_success"] == 0
    assert context.counts[f"query_{status}"] == 1
    assert f"Query requests: 1 attempted; 0 SUCCESS; 1 {status.upper()}." in execution_summary(
        context
    )
    assert context.counts["mutation_requests"] == 1
    assert context.counts["mutation_success"] == 0
    assert context.counts[f"mutation_{status}"] == 1
    assert context.counts["mutation_not_attempted"] == 5
    assert f"Mutation requests: 1 attempted; 0 SUCCESS; 1 {status.upper()}." in execution_summary(
        context
    )
