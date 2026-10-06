"""Console-only status colors; observations never acquire new security meaning."""

import re

from rich.text import Text

STATUS_STYLES = {
    **dict.fromkeys(
        (
            "SUCCESS",
            "ACCEPTED",
            "OBSERVED",
            "CONTROL",
            "SATISFIED",
            "ENABLED",
            "CONFIRMED",
            "PROBABLE",
            "PARSED",
            "RETRIEVED",
            "RETURNED",
            "ACCESS_RETURNED",
            "UPLOAD_ACCEPTED",
            "BASELINE_CONFIRMED",
            "EVENT_RETURNED",
            "SDL_RETURNED",
            "ENTITY_RETURNED",
        ),
        "green",
    ),
    **dict.fromkeys(
        (
            "GRAPHQL_ERROR",
            "REVIEW",
            "UNRESOLVED",
            "INDETERMINATE",
            "REJECTED",
            "EXPLICIT_DENIAL",
            "EXPLICIT_FILE_REJECTION",
            "NO_EVENT_BEFORE_TIMEOUT",
            "BASELINE_UNUSABLE",
            "BLOCKED",
            "DISABLED",
            "AUTHORIZATION_DENIED",
            "POSSIBLE",
        ),
        "yellow",
    ),
    **dict.fromkeys(
        (
            "FAILED",
            "NETWORK_FAILURE",
            "HTTP_ERROR",
            "INVALID_RESPONSE",
            "ENDPOINT_ERROR",
            "GENERATION_FAILED",
            "INVALID_ARTIFACT",
            "TIMEOUT",
            "CONNECTION_FAILURE",
            "TRANSPORT_FAILURE",
            "FINDING",
            "VIOLATION",
        ),
        "bold red",
    ),
    **dict.fromkeys(("BLOCKED_SAFETY", "SKIPPED_SAFETY"), "magenta"),
    **dict.fromkeys(
        (
            "NOT_RUN",
            "NOT_SELECTED",
            "NOT_ATTEMPTED",
            "NOT_EXECUTED",
            "NOT_EVALUATED",
            "NOT_RECORDED",
            "NOT_DETECTED",
            "DECLINED",
            "SKIPPED_LIMIT",
            "MODE_DISABLED",
        ),
        "dim",
    ),
}
_STATUS_TERMS = re.compile(r"\b[A-Z][A-Z_]+\b")


def status_text(value: str) -> Text:
    """Style a known status, preserving its spelling and leaving unknown values neutral."""
    return Text(value, style=STATUS_STYLES.get(value.upper().replace(" ", "_"), ""))


def style_status_terms(value: str) -> Text:
    """Style exact uppercase status tokens in a compound status cell without parsing markup."""
    text = Text(value)
    for match in _STATUS_TERMS.finditer(value):
        if style := STATUS_STYLES.get(match.group()):
            text.stylize(style, match.start(), match.end())
    return text
