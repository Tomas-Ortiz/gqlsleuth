"""Bounded content regeneration cannot become transport or target-request retrying."""

import json
from copy import deepcopy
from dataclasses import asdict

import httpx
import pytest

from fixtures.ai_response import reference_items, security_answer_fields
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import MAX_AI_ATTEMPTS, AIAnalysisStatus, AIServiceError
from gqlsleuth.ai.prompt import build_response_schema, build_system_prompt
from gqlsleuth.ai.regeneration import corrective_instruction
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def scan(phase_ten_scan):
    return phase_ten_scan()[0]


def answer(context):
    return security_answer_fields(context)


def test_initial_prompt_and_schema_keep_inference_and_limitations_calibrated(scan):
    context = build_ai_context(scan)
    prompt = " ".join(build_system_prompt(context).split())
    assert "Scanner safety skips describe GQLSleuth's own restraint" in prompt
    assert "Do not speculate about query structure, data access or exposure" in prompt
    assert "Not observed, not tested, not supplied and not established do NOT mean absent" in prompt
    assert "Missing facts never establish missing controls" in prompt
    assert "Match each fact's endpoint/kind/name to the exact operation reference" in prompt
    assert (
        "context_truncated describe ONLY bounded AI input, never partial schema retrieval" in prompt
    )
    assert "no security cause, misconfiguration or data exposure" in prompt
    schema = build_response_schema(context)
    limitation = schema["$defs"]["AIInterpretiveLimitation"]["properties"]["text"]
    assert limitation["maxLength"] == 500
    assert "finish naturally" in limitation["description"]
    assert schema["$defs"]["AISummaryInterpretation"]["properties"]["text"]["maxLength"] == 800


def envelope(content):
    return {"model": "qwen3:8b", "done": True, "message": {"role": "assistant", "content": content}}


@pytest.mark.parametrize("invalid_count", [0, 1, 5, 9, 10])
def test_bounded_regeneration_same_context_final_only_and_reports(scan, invalid_count, monkeypatch):
    assert MAX_AI_ATTEMPTS == 10
    context = build_ai_context(scan)
    before = deepcopy(scan)
    requests = []
    progress = []
    bad = answer(context)
    bad["extra"] = "REJECTED_PROSE_CANARY"
    good = answer(context)

    def handler(request):
        assert request.url.host == "127.0.0.1"
        assert request.extensions["timeout"]["read"] == 77
        requests.append(json.loads(request.content))
        reply = bad if len(requests) <= invalid_count else good
        return httpx.Response(200, json=envelope(json.dumps(reply)))

    monkeypatch.setattr(HttpClient, "send", lambda *a, **k: pytest.fail("Extra target request"))
    result = interpret_completed_scan(
        scan,
        client=OllamaClient(transport=httpx.MockTransport(handler), timeout_seconds=77),
        on_progress=progress.append,
    )
    attempts = min(invalid_count + 1, MAX_AI_ATTEMPTS)
    assert len(requests) == result.attempt_count == attempts
    assert result.validation_failures == ("invalid_schema",) * invalid_count
    assert scan == before and scan.evidence == before.evidence
    assert all(p["messages"][1]["content"] == serialize_context(context) for p in requests)
    assert all(p["format"] == requests[0]["format"] for p in requests)
    assert len({p["messages"][0]["content"] for p in requests}) == attempts
    for payload in requests:
        assert len(payload["messages"]) == 2
        assert "REJECTED_PROSE_CANARY" not in json.dumps(payload)
        assert payload["think"] is False and payload["stream"] is False
    assert "REJECTED_PROSE_CANARY" not in str(asdict(result))
    assert [(e.attempt, e.state) for e in progress] == [
        pair
        for n in range(1, attempts + 1)
        for pair in [(n, "started"), (n, "rejected" if n <= invalid_count else "accepted")]
    ]
    if invalid_count == MAX_AI_ATTEMPTS:
        assert result.status is AIAnalysisStatus.INVALID_RESPONSE
        assert result.interpretation is None
        assert "after 10 attempts" in result.error_message
    else:
        assert result.status is AIAnalysisStatus.SUCCESS
        assert (
            result.interpretation.summary_interpretation.text
            == good["summary_interpretation"]["text"]
        )
    report = build_report(scan, ai_interpretation=result)
    for format in ReportFormat:
        text = render_report(report, format)
        assert "REJECTED_PROSE_CANARY" not in text
    canonical = json.loads(render_report(report, ReportFormat.JSON))["ai_interpretation"]
    assert canonical["attempt_count"] == attempts
    assert canonical["validation_failures"] == list(result.validation_failures)
    assert len(requests) == attempts  # Rendering never calls inference.


@pytest.mark.parametrize(
    "code,phrase",
    [
        ("incomplete_operation_interpretation_set", "exactly one interpretation"),
        ("invalid_json", "complete JSON"),
        ("invalid_schema", "field types"),
        ("invalid_response", "complete JSON"),
        ("unknown_operation_reference", "exact supplied references"),
        ("invalid_security_references", "exact supplied references"),
        ("missing_summary_references", "exact supplied references"),
        ("incomplete_operation_interpretation_set", "every supplied operation"),
        ("insufficient_insight_references", "two or three distinct"),
        ("output_token_limit_reached", "output generation limit"),
    ],
)
def test_each_known_content_failure_has_safe_distinct_correction(scan, code, phrase):
    seen = []
    context = build_ai_context(scan)

    class Client:
        def interpret(self, supplied, **options):
            seen.append((supplied, options))
            if len(seen) == 1:
                raise AIServiceError(AIAnalysisStatus.INVALID_RESPONSE, code, "PRIVATE_CANARY")
            return OllamaClient(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, json=envelope(json.dumps(answer(context))))
                )
            ).interpret(supplied, **options)

    result = interpret_completed_scan(scan, client=Client())
    assert result.status is AIAnalysisStatus.SUCCESS and result.attempt_count == 2
    assert seen[0][0] is seen[1][0]
    assert {k: v for k, v in seen[1][1].items() if k != "on_usage"} == {
        "validation_codes": (code,),
        "attempt": 2,
    }
    correction = corrective_instruction(code, 2)
    assert phrase in correction and "COMPLETE" in correction
    assert "PRIVATE_CANARY" not in correction
    assert "PRIVATE_CANARY" not in str(result)
    assert corrective_instruction("PRIVATE_CANARY", 2) is None


@pytest.mark.parametrize("failure", ["connect", "timeout", "transport", "missing", "http"])
def test_provider_errors_stop_without_regeneration(scan, failure):
    calls = []

    def handler(request):
        calls.append(request)
        if failure == "missing":
            return httpx.Response(404, json={"error": "model qwen3:8b not found"})
        if failure == "http":
            return httpx.Response(500, text="PRIVATE_CANARY")
        error = {
            "connect": httpx.ConnectError,
            "timeout": httpx.ReadTimeout,
            "transport": httpx.RemoteProtocolError,
        }[failure]
        raise error("PRIVATE_CANARY", request=request)

    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(handler))
    )
    assert len(calls) == result.attempt_count == 1
    assert result.validation_failures == ()
    assert result.interpretation is None and "PRIVATE_CANARY" not in str(result)


@pytest.mark.parametrize("interrupt_at", [1, 2])
def test_interrupt_never_starts_another_attempt(scan, interrupt_at):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == interrupt_at:
            raise KeyboardInterrupt
        return httpx.Response(200, json=envelope("not json"))

    with pytest.raises(KeyboardInterrupt):
        interpret_completed_scan(scan, client=OllamaClient(transport=httpx.MockTransport(handler)))
    assert len(calls) == interrupt_at


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_configuration_never_attempts(scan, timeout):
    result = interpret_completed_scan(scan, timeout_seconds=timeout)
    assert result.attempt_count == 0 and result.error_code == "invalid_configuration"
    assert result.validation_failures == ()


@pytest.mark.parametrize(
    "failure,code",
    [
        ("json", "invalid_json"),
        ("schema", "invalid_schema"),
        ("reference", "unknown_operation_reference"),
        ("execution", "incomplete_operation_interpretation_set"),
    ],
)
def test_real_content_validation_drives_correction_then_success(scan, failure, code):
    context = build_ai_context(scan)
    good = answer(context)
    invalid = deepcopy(good)
    if failure == "schema":
        invalid["extra"] = "PRIVATE_CANARY"
    elif failure == "reference":
        invalid["summary_interpretation"]["references"] = reference_items(
            ["endpoint_1/query/invented"]
        )
    elif failure == "execution":
        invalid["operation_interpretations"].pop()
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        content = json.dumps(good if len(calls) > 1 else invalid)
        if failure == "json" and len(calls) == 1:
            content = "not JSON PRIVATE_CANARY"
        return httpx.Response(200, json=envelope(content))

    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(handler))
    )
    assert result.status is AIAnalysisStatus.SUCCESS and result.attempt_count == 2
    assert result.validation_failures == (code,)
    assert calls[1]["messages"][0]["content"].endswith(corrective_instruction(code, 2))
    assert "PRIVATE_CANARY" not in json.dumps(calls[1])


def test_transport_failure_during_regeneration_stops_immediately(scan):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, json=envelope("not JSON"))
        raise httpx.ReadError("PRIVATE_CANARY", request=request)

    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(handler))
    )
    assert result.status is AIAnalysisStatus.UNAVAILABLE and result.attempt_count == 2
    assert result.error_code == "transport_failed"
    assert result.validation_failures == ("invalid_json",)
    assert result.interpretation is None and len(calls) == 2


def test_unknown_validation_code_is_not_retried(scan):
    class Client:
        calls = 0

        def interpret(self, context, **options):
            self.calls += 1
            raise AIServiceError(
                AIAnalysisStatus.INVALID_RESPONSE, "future_category", "Controlled error"
            )

    client = Client()
    result = interpret_completed_scan(scan, client=client)
    assert result.attempt_count == client.calls == 1
    assert result.validation_failures == ()


def test_distinct_corrections_accumulate_without_repeated_paragraphs(scan):
    context = build_ai_context(scan)
    good = answer(context)
    codes = (
        "invalid_schema",
        "unknown_operation_reference",
        "incomplete_operation_interpretation_set",
        "incomplete_operation_interpretation_set",
        "incomplete_operation_interpretation_set",
    )
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        reply = deepcopy(good)
        if len(calls) <= len(codes):
            code = codes[len(calls) - 1]
            if code == "invalid_schema":
                reply["extra"] = "REJECTED_CANARY"
            elif code == "unknown_operation_reference":
                reply["summary_interpretation"]["references"] = reference_items(["REJECTED_CANARY"])
            else:
                reply["operation_interpretations"].pop()
        return httpx.Response(200, json=envelope(json.dumps(reply)))

    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(handler))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(calls) == 6
    assert result.validation_failures == codes
    for attempt, request in enumerate(calls[1:], 2):
        distinct = tuple(dict.fromkeys(codes[: attempt - 1]))
        prompt = request["messages"][0]["content"]
        assert prompt.endswith(corrective_instruction(distinct, attempt))
        assert "REJECTED_CANARY" not in json.dumps(request)
        assert request["messages"][1] == calls[0]["messages"][1]
        assert request["format"] == calls[0]["format"]
        assert prompt.count("Provide exactly one interpretation") == int(attempt >= 4)
    assert len(calls[3]["messages"][0]["content"]) == len(calls[5]["messages"][0]["content"])
    assert corrective_instruction(("incomplete_prose", "PRIVATE_CANARY"), 2) is None
