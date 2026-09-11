"""Bounded human views of response bytes; never alter evidence or classify execution."""

import codecs
import json
from dataclasses import dataclass

from gqlsleuth.infrastructure.http import HttpResponse

MAX_HUMAN_RESPONSE_BODY_BYTES = 64 * 1024
TRUNCATION_NOTICE = (
    "Response truncated for human-readable presentation. "
    "Full response is preserved in canonical JSON evidence."
)


@dataclass(frozen=True)
class HumanResponseBody:
    text: str
    language: str
    notice: str | None = None


@dataclass(frozen=True)
class ResponsePresentation:
    classification: str
    http_status: int | None
    duration_seconds: float | None
    body: HumanResponseBody | None

    @property
    def summary(self) -> str:
        http = f"HTTP {self.http_status}" if self.http_status is not None else "No HTTP response"
        return f"Server response - {http} - {self.classification}"

    @property
    def details(self) -> tuple[tuple[str, str], ...]:
        rows: tuple[tuple[str, str], ...] = (
            ("HTTP status", str(self.http_status) if self.http_status is not None else "None"),
            ("Classification", self.classification),
        )
        if self.duration_seconds is not None:
            rows += (("Duration", f"{self.duration_seconds * 1000:.3f} ms"),)
        return rows


def present_response(
    response: HttpResponse | None,
    classification: str,
    *,
    duration_seconds: float | None = None,
) -> ResponsePresentation:
    """Call only for recorded attempts; absence of an HTTP response stays explicit."""
    return ResponsePresentation(
        classification=classification.upper(),
        http_status=response.status_code if response is not None else None,
        duration_seconds=response.duration_seconds if response is not None else duration_seconds,
        body=present_response_body(response.body) if response is not None else None,
    )


def present_response_body(body: bytes) -> HumanResponseBody:
    """Bound input and formatted output, avoiding broken UTF-8 and terminal controls."""
    truncated = len(body) > MAX_HUMAN_RESPONSE_BODY_BYTES
    try:
        # An incomplete final code point at a truncation boundary is simply omitted.
        text = codecs.getincrementaldecoder("utf-8")().decode(
            body[:MAX_HUMAN_RESPONSE_BODY_BYTES], final=not truncated
        )
    except UnicodeDecodeError:
        return HumanResponseBody(
            "", "text", "Binary/unrenderable response body; exact bytes remain in JSON evidence."
        )
    if any(not char.isprintable() and char not in "\n\r\t" for char in text):
        return HumanResponseBody(
            "", "text", "Binary/unrenderable response body; exact bytes remain in JSON evidence."
        )
    language = "text"
    if not truncated and text:
        try:
            parsed = json.loads(text)
            formatted = json.dumps(
                parsed, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
            )
        except (ValueError, RecursionError):
            pass
        else:
            text = formatted
            language = "json"
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_HUMAN_RESPONSE_BODY_BYTES:
        text = encoded[:MAX_HUMAN_RESPONSE_BODY_BYTES].decode("utf-8", errors="ignore")
        truncated = True
    return HumanResponseBody(
        text,
        language,
        TRUNCATION_NOTICE if truncated else (None if text else "Empty response body."),
    )
