"""Content-free session accounting; unknown provider counts remain unknown."""

from collections import Counter

from gqlsleuth.ai.models import AIAttemptUsage, AISessionUsage


def summarize_usage(attempts: tuple[AIAttemptUsage, ...], *, accepted: bool) -> AISessionUsage:
    prompts = [item.usage.prompt_tokens for item in attempts]
    completions = [item.usage.completion_tokens for item in attempts]
    final = attempts[-1] if accepted and attempts else None
    return AISessionUsage(
        total_prompt_tokens=sum(v for v in prompts if v is not None)
        if prompts and all(v is not None for v in prompts)
        else None,
        total_completion_tokens=sum(v for v in completions if v is not None)
        if completions and all(v is not None for v in completions)
        else None,
        max_completion_tokens=max(v for v in completions if v is not None)
        if any(v is not None for v in completions)
        else None,
        output_limit_hit_count=sum(item.usage.done_reason == "length" for item in attempts),
        done_reason_counts=tuple(
            sorted(Counter(item.usage.done_reason or "unknown" for item in attempts).items())
        ),
        accepted_attempt=final.attempt if final else None,
        accepted_attempt_prompt_tokens=final.usage.prompt_tokens if final else None,
        accepted_attempt_completion_tokens=final.usage.completion_tokens if final else None,
    )
