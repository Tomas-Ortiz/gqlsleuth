"""One non-streaming inference against local Ollama, independent of target HTTP/evidence."""

import json
import math

import httpx

from gqlsleuth.ai.context import serialize_context
from gqlsleuth.ai.models import (
    DEFAULT_AI_MODEL,
    MAX_CONTEXT_BYTES,
    AIAnalysisStatus,
    AIContext,
    AIInterpretation,
    AIServiceError,
)
from gqlsleuth.ai.prompt import build_system_prompt, execution_summary, validate_interpretation

OLLAMA_ENDPOINT = "http://127.0.0.1:11434"
AI_TIMEOUT_SECONDS = 180.0
MAX_AI_RESPONSE_BYTES = 131_072


class OllamaClient:
    """Fixed loopback destination; no redirects, proxies, retries, downloads, or tools."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = AI_TIMEOUT_SECONDS,
    ) -> None:
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= AI_TIMEOUT_SECONDS:
            raise ValueError("AI timeout must be finite, positive, and at most 180 seconds.")
        self._transport = transport
        self._timeout = timeout_seconds

    def interpret(self, context: AIContext) -> AIInterpretation:
        serialized = serialize_context(context)
        if len(serialized.encode("utf-8")) > MAX_CONTEXT_BYTES:
            raise AIServiceError(
                AIAnalysisStatus.INVALID_RESPONSE,
                "context_too_large",
                "AI context exceeds its size limit.",
            )
        response_schema = AIInterpretation.model_json_schema()
        # Constrain the summary at generation time as well as validating it afterward.
        # Other AIStatement fields retain their ordinary bounded interpretation text.
        response_schema["properties"]["scan_summary"] = {
            "type": "object",
            "additionalProperties": False,
            "required": ["text", "operations"],
            "properties": {
                "text": {"type": "string", "enum": [execution_summary(context)]},
                "operations": {"type": "array", "items": {"type": "string"}, "maxItems": 0},
            },
        }
        payload = {
            "model": DEFAULT_AI_MODEL,
            "stream": False,
            "think": False,
            "messages": [
                {"role": "system", "content": build_system_prompt(context)},
                {"role": "user", "content": serialized},
            ],
            "format": response_schema,
            "options": {"temperature": 0, "num_ctx": 8192, "num_predict": 2048},
        }
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
                envelope = json.loads(body)
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
            if not isinstance(content, str) or envelope.get("done_reason") == "length":
                raise ValueError("Missing or incomplete final answer.")
            # Ignore thinking and all other model metadata. Never retain the raw envelope.
            return validate_interpretation(content, context)
        except httpx.TimeoutException as error:
            raise AIServiceError(
                AIAnalysisStatus.UNAVAILABLE, "timeout", "Local Ollama inference timed out."
            ) from error
        except httpx.RequestError as error:
            raise AIServiceError(
                AIAnalysisStatus.UNAVAILABLE,
                "connection_failed",
                "Could not connect to local Ollama.",
            ) from error
        except (ValueError, RecursionError) as error:
            raise AIServiceError(
                AIAnalysisStatus.INVALID_RESPONSE,
                "invalid_response",
                "Local Ollama returned an invalid structured interpretation.",
            ) from error


def _raise_http_error(status: int, body: bytearray) -> None:
    if status == 404:
        try:
            envelope = json.loads(body)
        except ValueError:
            envelope = None
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
