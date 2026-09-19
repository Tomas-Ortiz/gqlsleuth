"""Explicit abuse signals and status-only consistency; no body/timing/threshold inference."""

import json
from dataclasses import dataclass

from gqlsleuth.domain.abuse_controls import (
    AbuseControlKind,
    AbuseControlOutcome,
    AbuseControlSignal,
)
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.graphql.safe_execution import classify_execution_response
from gqlsleuth.rules.operation_analysis import normalize_terms

_CODES = {
    ("rate", "limited"): AbuseControlKind.RATE_LIMIT,
    ("too", "many", "requests"): AbuseControlKind.RATE_LIMIT,
    ("throttled",): AbuseControlKind.RATE_LIMIT,
    ("account", "locked"): AbuseControlKind.LOCKOUT,
    ("user", "locked"): AbuseControlKind.LOCKOUT,
    ("captcha", "required"): AbuseControlKind.CHALLENGE,
    ("challenge", "required"): AbuseControlKind.CHALLENGE,
}
_MESSAGES = {
    ("too", "many", "requests"): AbuseControlKind.RATE_LIMIT,
    ("rate", "limit", "exceeded"): AbuseControlKind.RATE_LIMIT,
    ("too", "many", "attempts"): AbuseControlKind.RATE_LIMIT,
    ("try", "again", "later"): AbuseControlKind.RATE_LIMIT,
    ("account", "locked"): AbuseControlKind.LOCKOUT,
    ("temporarily", "locked"): AbuseControlKind.LOCKOUT,
    ("captcha", "required"): AbuseControlKind.CHALLENGE,
}


@dataclass(frozen=True)
class AbuseControlResponse:
    outcome: AbuseControlOutcome
    repeat_status: QueryExecutionStatus
    signal: AbuseControlSignal | None = None


def _document(body: bytes) -> dict[str, object] | None:
    try:
        value: object = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _signal(status: int, document: dict[str, object] | None) -> AbuseControlSignal | None:
    if status == 429:
        return AbuseControlSignal(AbuseControlKind.RATE_LIMIT, "http_status", "429")
    errors = document.get("errors") if document else None
    if not isinstance(errors, list):
        return None
    for error in errors:
        if not isinstance(error, dict):
            continue
        extensions = error.get("extensions")
        code = extensions.get("code") if isinstance(extensions, dict) else None
        if isinstance(code, str):
            terms = normalize_terms(code)
            if terms in _CODES:
                return AbuseControlSignal(_CODES[terms], "graphql_code", "_".join(terms).upper())
    for error in errors:
        if not isinstance(error, dict):
            continue
        extensions = error.get("extensions")
        if isinstance(extensions, dict) and extensions.get("code") is not None:
            continue  # Message fallback is for errors without an explicit code.
        message = error.get("message")
        if isinstance(message, str):
            terms = normalize_terms(message)
            if terms in _MESSAGES:
                return AbuseControlSignal(_MESSAGES[terms], "graphql_message", " ".join(terms))
    return None


def _usable(document: dict[str, object] | None, status: QueryExecutionStatus) -> bool:
    if not document:
        return False
    if status is QueryExecutionStatus.SUCCESS:
        return "data" in document and isinstance(document["data"], (dict, type(None)))
    if status is QueryExecutionStatus.GRAPHQL_ERROR:
        errors = document.get("errors")
        return (
            isinstance(errors, list)
            and bool(errors)
            and all(
                isinstance(error, dict) and isinstance(error.get("message"), str)
                for error in errors
            )
        )
    return status is QueryExecutionStatus.HTTP_ERROR


def eligible_baseline(status: QueryExecutionStatus, http_status: int, body: bytes) -> bool:
    """Exclude outages, malformed responses and already-signalled controls without traffic."""
    if not (200 <= http_status < 300 or http_status in {400, 401, 403}):
        return False
    if status is QueryExecutionStatus.HTTP_ERROR and http_status not in {401, 403}:
        return False
    document = _document(body)
    return (
        document is not None
        and classify_execution_response(http_status, body).status is status
        and _usable(document, status)
        and _signal(http_status, document) is None
    )


def classify_abuse_response(
    http_status: int,
    body: bytes,
    *,
    baseline_status: QueryExecutionStatus,
    baseline_http_status: int,
) -> AbuseControlResponse:
    document = _document(body)
    # The existing classifier owns execution status; errors are never called successes here.
    try:
        repeat_status = classify_execution_response(http_status, body).status
    except RecursionError:
        repeat_status = QueryExecutionStatus.INVALID_RESPONSE
    signal = _signal(http_status, document)
    if signal:
        return AbuseControlResponse(
            AbuseControlOutcome.CONTROL_SIGNAL_OBSERVED, repeat_status, signal
        )
    consistent = (
        repeat_status is baseline_status
        and http_status == baseline_http_status
        and _usable(document, repeat_status)
    )
    return AbuseControlResponse(
        AbuseControlOutcome.NO_CONTROL_SIGNAL if consistent else AbuseControlOutcome.INDETERMINATE,
        repeat_status,
    )
