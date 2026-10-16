"""Provider counters are diagnostic metadata, never prompt/reply persistence."""

import json
from dataclasses import asdict

import httpx
import pytest

from fixtures.ai_response import security_answer_fields
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AIAnalysisStatus
from gqlsleuth.ai.regeneration import corrective_instruction
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.infrastructure.ollama import OllamaClient, provider_usage


@pytest.mark.parametrize("completion,remaining", [(0, 2048), (713, 1335), (2048, 0), (2050, 0)])
def test_provider_counts_and_distinct_budgets(completion, remaining):
    usage = provider_usage(
        {"prompt_eval_count": 1700, "eval_count": completion, "done_reason": "stop"},
        completion_limit=2048,
        context_limit=8192,
    )
    assert usage.prompt_tokens == 1700 and usage.completion_tokens == completion
    assert usage.completion_tokens_remaining == remaining
    assert usage.approx_context_tokens_remaining == max(8192 - 1700 - completion, 0)
    assert usage.done_reason == "stop"


@pytest.mark.parametrize("bad", [True, -1, "123", 2**64, 1.5, None])
def test_invalid_counters_and_unknown_context_are_not_guessed(bad):
    usage = provider_usage(
        {"prompt_eval_count": bad, "eval_count": bad, "done_reason": "SECRET_CANARY"},
        completion_limit=2048,
        context_limit=None,
    )
    assert usage.prompt_tokens is usage.completion_tokens is None
    assert usage.context_token_limit is usage.approx_context_tokens_remaining is None
    assert usage.completion_tokens_remaining is None
    assert usage.done_reason == "unknown"
    assert "SECRET_CANARY" not in str(asdict(usage))


@pytest.mark.parametrize("content", ["{TRUNCATED_CANARY", "valid"])
def test_length_termination_precedes_content_validation_and_regenerates(phase_ten_scan, content):
    scan = phase_ten_scan()[0]
    context = build_ai_context(scan)
    answer = json.dumps(security_answer_fields(context))
    calls = []

    def respond(request):
        calls.append(json.loads(request.content))
        limited = len(calls) < 3
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "done_reason": "length" if limited else "stop",
                "prompt_eval_count": 1700,
                "eval_count": 2048 if limited else 713,
                "message": {
                    "role": "assistant",
                    "content": answer if content == "valid" or not limited else content,
                },
                "thinking": "PRIVATE_THINKING_CANARY",
            },
        )

    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert result.attempt_count == len(calls) == 3
    assert result.validation_failures == ("output_token_limit_reached",) * 2
    assert all(c["options"]["num_predict"] == 2048 for c in calls)
    assert result.usage.total_prompt_tokens == 5100
    assert result.usage.total_completion_tokens == 4809
    assert result.usage.max_completion_tokens == 2048
    assert result.usage.output_limit_hit_count == 2
    assert result.usage.accepted_attempt == 3
    assert result.usage.accepted_attempt_completion_tokens == 713
    assert dict(result.usage.done_reason_counts) == {"length": 2, "stop": 1}
    assert result.attempts[0].validation_failure == "output_token_limit_reached"
    assert result.references.operations == context.operations
    assert result.references.security_facts == context.security_facts
    assert "CANARY" not in str(asdict(result))
    assert "TRUNCATED_CANARY" not in json.dumps(calls)
    correction = corrective_instruction(("output_token_limit_reached",) * 2, 3)
    assert correction.count("previous response reached") == 1


def test_provider_failure_is_terminal_and_counts_remain_unknown(phase_ten_scan):
    scan = phase_ten_scan()[0]
    calls = []

    def respond(request):
        calls.append(request)
        raise httpx.ConnectError("SECRET_CANARY")

    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.UNAVAILABLE
    assert len(calls) == result.attempt_count == len(result.attempts) == 1
    assert result.validation_failures == ()
    assert result.usage.total_prompt_tokens is None
    assert result.usage.total_completion_tokens is None
    assert result.usage.accepted_attempt is None
    assert result.attempts[0].usage.completion_token_limit == 2048
    assert "SECRET_CANARY" not in str(result)
