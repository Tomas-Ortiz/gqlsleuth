"""Explicit abuse signals and status-only consistency; no body/timing/threshold inference."""

import json
import re
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

# These codes describe request processing, not failed authentication/business decisions.
_STRUCTURAL_CODES = frozenset({"GRAPHQL_PARSE_FAILED", "GRAPHQL_VALIDATION_FAILED"})
_APPLICATION_CODES = frozenset(
    {
        "UNAUTHENTICATED",
        "UNAUTHORIZED",
        "FORBIDDEN",
        "INVALID_CREDENTIALS",
        "AUTHENTICATION_FAILED",
        "ACCESS_DENIED",
        "ACCOUNT_DISABLED",
        "INVALID_TOKEN",
        "SESSION_EXPIRED",
    }
)
_APPLICATION_MESSAGES = frozenset(
    normalize_terms(message)
    for message in (
        "Invalid credentials",
        "Authentication failed",
        "Incorrect username or password",
        "Account disabled",
        "Login failed",
        "Access denied",
        "Invalid token",
        "Session expired",
        "Unauthorized",
        "Forbidden",
    )
)
# A structural message wins even if a server attaches an authentication code.
# Unknown messages/codes are not evidence of meaningful application handling.
_STRUCTURAL_MESSAGE = re.compile(
    r"^(?:syntax error\b|graphql (?:parse|validation) error\b|cannot query field\b|"
    r"unknown (?:field|argument|type)\b|variable\s+['\"]?\$|"
    r"must provide (?:operation name|an operation)\b|unknown operation named\b)"
    r"|^(?:field|argument)\b.*\brequired\b.*\b(?:not provided|missing)\b"
    r"|\bmissing (?:\d+ )?required (?:positional|keyword-only) arguments?\b"
    r"|\bunexpected keyword argument\b",
    re.IGNORECASE,
)


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


def _application_error(error: object) -> bool:
    """Require an explicit application outcome; never infer it from GRAPHQL_ERROR alone."""
    if not isinstance(error, dict) or not isinstance(error.get("message"), str):
        return False
    message = " ".join(error["message"].split())
    extensions = error.get("extensions")
    code = extensions.get("code") if isinstance(extensions, dict) else None
    normalized_code = "_".join(normalize_terms(code)).upper() if isinstance(code, str) else ""
    if normalized_code in _STRUCTURAL_CODES or _STRUCTURAL_MESSAGE.search(message):
        return False
    # BAD_USER_INPUT and unknown codes are not intrinsically structural or application-level.
    return (
        normalized_code in _APPLICATION_CODES or normalize_terms(message) in _APPLICATION_MESSAGES
    )


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
            and all(_application_error(error) for error in errors)
        )
    return status is QueryExecutionStatus.HTTP_ERROR


def eligible_baseline(status: QueryExecutionStatus, http_status: int, body: bytes) -> bool:
    """Require meaningful retained outcomes, excluding structural/ambiguous errors locally."""
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
