"""One non-streaming inference against local Ollama, independent of target HTTP/evidence."""

import math
from collections.abc import Callable

import httpx

from gqlsleuth.ai.context import serialize_context
from gqlsleuth.ai.models import (
    DEFAULT_AI_MODEL,
    DEFAULT_AI_TIMEOUT_SECONDS,
    MAX_CONTEXT_BYTES,
    AIAnalysisStatus,
    AIContext,
    AIInterpretation,
    AIProviderUsage,
    AIServiceError,
    AIValidationError,
)
from gqlsleuth.ai.prompt import build_response_schema, build_system_prompt, validate_interpretation
from gqlsleuth.ai.regeneration import corrective_instruction
from gqlsleuth.graphql.response_json import decode_response_json, response_json_object

OLLAMA_ENDPOINT = "http://127.0.0.1:11434"
MAX_AI_RESPONSE_BYTES = 131_072
COMPLETION_TOKEN_LIMIT = 2048
CONTEXT_TOKEN_LIMIT = 8192


def provider_usage(
    envelope: object, *, completion_limit: int | None, context_limit: int | None
) -> AIProviderUsage:
    """Project only provider counters and allowlisted reasons, never arbitrary strings."""
    metadata = envelope if isinstance(envelope, dict) else {}

    def count(key: str) -> int | None:
        value = metadata.get(key)
        return value if type(value) is int and 0 <= value <= 2**63 - 1 else None

    prompt = count("prompt_eval_count")
    completion = count("eval_count")
    reason = metadata.get("done_reason")
    return AIProviderUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        completion_token_limit=completion_limit,
        completion_tokens_remaining=max(completion_limit - completion, 0)
        if completion_limit is not None and completion is not None
        else None,
        context_token_limit=context_limit,
        approx_context_tokens_remaining=max(context_limit - prompt - completion, 0)
        if context_limit is not None and prompt is not None and completion is not None
        else None,
        done_reason=reason
        if reason in ("stop", "length")
        else "unknown"
        if reason is not None
        else None,
    )


class OllamaClient:
    """Fixed loopback destination; no redirects, proxies, retries, downloads, or tools."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = DEFAULT_AI_TIMEOUT_SECONDS,
    ) -> None:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("AI timeout must be finite and positive.")
        self._transport = transport
        self._timeout = timeout_seconds

    def interpret(
        self,
        context: AIContext,
        *,
        validation_codes: tuple[str, ...] = (),
        attempt: int = 1,
        on_usage: Callable[[AIProviderUsage], None] | None = None,
    ) -> AIInterpretation:
        serialized = serialize_context(context)
        if len(serialized.encode("utf-8")) > MAX_CONTEXT_BYTES:
            raise AIServiceError(
                AIAnalysisStatus.INVALID_RESPONSE,
                "context_too_large",
                "AI context exceeds its size limit.",
            )
        system_prompt = build_system_prompt(context)
        if validation_codes:
            correction = corrective_instruction(validation_codes, attempt)
            if correction is None:
                raise ValueError("Unknown AI validation category.")
            system_prompt += "\n\n" + correction
        payload = {
            "model": DEFAULT_AI_MODEL,
            "stream": False,
            "think": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": serialized},
            ],
            "format": build_response_schema(context),
            "options": {
                "temperature": 0,
                "num_ctx": CONTEXT_TOKEN_LIMIT,
                "num_predict": COMPLETION_TOKEN_LIMIT,
            },
        }
        if on_usage:
            on_usage(
                provider_usage(
                    None, completion_limit=COMPLETION_TOKEN_LIMIT, context_limit=CONTEXT_TOKEN_LIMIT
                )
            )
        try:
            with (
                httpx.Client(
                    timeout=httpx.Timeout(self._timeout, connect=5.0),
                    follow_redirects=False,
                    trust_env=False,
                    transport=self._transport,
                ) as client,
                client.stream("POST", OLLAMA_ENDPOINT + "/api/chat", json=payload) as response,
            ):
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > MAX_AI_RESPONSE_BYTES:
                        raise ValueError("Oversized Ollama response.")
                    body.extend(chunk)
                if response.status_code != 200:
                    _raise_http_error(response.status_code, body)
                envelope = decode_response_json(body)
                usage = provider_usage(
                    envelope,
                    completion_limit=COMPLETION_TOKEN_LIMIT,
                    context_limit=CONTEXT_TOKEN_LIMIT,
                )
                if on_usage:
                    on_usage(usage)
                # Explicit provider length termination takes precedence over parsing the
                # generated content, even if its truncated payload happens to be valid JSON.
                if usage.done_reason == "length":
                    raise AIServiceError(
                        AIAnalysisStatus.INVALID_RESPONSE,
                        "output_token_limit_reached",
                        "Local Ollama reached the output generation limit.",
                    )
            if not isinstance(envelope, dict) or envelope.get("done") is not True:
                raise ValueError("Incomplete Ollama response.")
            if envelope.get("model") != DEFAULT_AI_MODEL or envelope.get("error"):
                raise ValueError("Unexpected Ollama model or error.")
            message = envelope.get("message")
            if (
                not isinstance(message, dict)
                or message.get("role") != "assistant"
                or message.get("tool_calls")
            ):
                raise ValueError("Invalid Ollama message.")
            content = message.get("content")
            if not isinstance(content, str):
                raise ValueError("Missing or incomplete final answer.")
            # Apart from the allowlisted counters above, ignore provider metadata and
            # thinking. Never retain the raw envelope.
            return validate_interpretation(content, context)
        except (httpx.ConnectError, httpx.ConnectTimeout) as error:
            raise AIServiceError(
                AIAnalysisStatus.UNAVAILABLE,
                "connection_failed",
                "Could not connect to local Ollama.",
            ) from error
        except httpx.TimeoutException as error:
            raise AIServiceError(
                AIAnalysisStatus.UNAVAILABLE, "timeout", "Local Ollama inference timed out."
            ) from error
        except httpx.RequestError as error:
            # Read/write/protocol failures do not imply the initial connection failed.
            raise AIServiceError(
                AIAnalysisStatus.UNAVAILABLE,
                "transport_failed",
                "Local Ollama request failed or the service became unavailable during inference.",
            ) from error
        except AIValidationError as error:
            raise AIServiceError(
                AIAnalysisStatus.INVALID_RESPONSE,
                error.code,
                "Local Ollama returned an invalid structured interpretation.",
            ) from error
        except (ValueError, RecursionError) as error:
            raise AIServiceError(
                AIAnalysisStatus.INVALID_RESPONSE,
                "invalid_response",
                "Local Ollama returned an invalid structured interpretation.",
            ) from error


def _raise_http_error(status: int, body: bytearray) -> None:
    if status == 404:
        # A malformed diagnostic body must not override the HTTP failure. Only a
        # recognizable model-not-found object receives the special classification.
        envelope = response_json_object(bytes(body))
        message = envelope.get("error", "") if isinstance(envelope, dict) else ""
        if (
            isinstance(message, str)
            and "model" in message.lower()
            and "not found" in message.lower()
        ):
            raise AIServiceError(
                AIAnalysisStatus.UNAVAILABLE,
                "model_not_found",
                f"{DEFAULT_AI_MODEL} is not available locally.",
            )
    raise AIServiceError(
        AIAnalysisStatus.HTTP_ERROR, "http_error", f"Local Ollama returned HTTP {status}."
    )
