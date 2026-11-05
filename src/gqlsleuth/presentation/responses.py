"""Bounded human views of response bytes; never alter evidence or classify execution."""

import codecs
import json
from dataclasses import dataclass

from gqlsleuth.graphql.response_json import (
    JsonNestingError,
    decode_response_json,
    response_json_object,
)
from gqlsleuth.infrastructure.http import HttpResponse

MAX_HUMAN_RESPONSE_BODY_BYTES = 64 * 1024
TRUNCATION_NOTICE = (
    "Response truncated for human-readable presentation. "
    "Full response is preserved in canonical JSON evidence."
)
SUCCESS_NOTICE = (
    "SUCCESS means no execution error was classified. It does not establish meaningful "
    "application data or business success, and is not a vulnerability finding."
)
NULL_DATA_NOTICE = (
    "The response contained top-level GraphQL data: null. No GraphQL error was classified, "
    "but this does not establish a meaningful application result."
)


def success_with_null_data(status: str | None, body: bytes | None) -> bool:
    """Qualify an existing SUCCESS only; never classify outcomes or inspect field truthiness."""
    if status is None or status.upper() != "SUCCESS" or body is None:
        return False
    document = response_json_object(body)
    return document is not None and "data" in document and document["data"] is None


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
            parsed = decode_response_json(text)
            formatted = json.dumps(
                parsed, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
            )
        except (JsonNestingError, RecursionError):
            return HumanResponseBody(
                "",
                "text",
                "Response JSON exceeds supported nesting for human-readable presentation. "
                "Exact bytes remain in canonical JSON evidence.",
            )
        except ValueError:
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


def compact_mutation_body(body: bytes) -> HumanResponseBody:
    """Show small identifier-only GraphQL results; omit other values as a whole.

    This is a conservative display allowlist, not redaction or a claim that response
    values are safe. Canonical bytes remain untouched. Do not render error messages,
    extensions, arbitrary scalar outputs, tokens or personal profile values here.
    """
    omission = (
        "Response values omitted from compact preview; "
        "exact response remains in canonical JSON evidence."
    )
    if not body:
        return HumanResponseBody("", "text", "Empty response body.")
    if len(body) > 4096:
        return HumanResponseBody(
            "", "text", "Response exceeds the 4 KiB compact preview limit. " + omission
        )
    document = response_json_object(body)
    if document is None:
        return HumanResponseBody("", "text", "No renderable GraphQL JSON object. " + omission)
    remaining = 80

    def identifier_only(value: object, depth: int = 0, key: str = "") -> bool:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 6:
            return False
        if value is None:
            return True
        if isinstance(value, dict):
            return all(identifier_only(v, depth + 1, k) for k, v in value.items())
        if isinstance(value, list):
            return all(identifier_only(v, depth + 1, key) for v in value)
        return (
            key in {"id", "__typename"} and isinstance(value, (str, int)) and len(str(value)) <= 96
        )

    errors = document.get("errors")
    error_count = len(errors) if isinstance(errors, list) else None
    if set(document) <= {"data"} and "data" in document and identifier_only(document["data"]):
        text = json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False)
        if len(text) <= 4096:
            return HumanResponseBody(
                text, "json", "Observed response, not generated preview values."
            )
    structure = "GraphQL data: " + (
        "null"
        if document.get("data") is None and "data" in document
        else "present"
        if "data" in document
        else "absent"
    )
    if error_count is not None:
        structure += f"; GraphQL errors: {error_count} (message values not displayed)"
    return HumanResponseBody(structure + ".", "text", omission)
