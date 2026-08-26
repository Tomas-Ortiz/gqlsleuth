"""Extract deterministic GraphQL signals from an HTTP response."""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from gqlsleuth.domain.models import ConfidenceLevel

GRAPHQL_RESPONSE_MEDIA_TYPES = {
    "application/graphql",
    "application/graphql+json",
    "application/graphql-response+json",
}
GRAPHQL_ERROR_MESSAGE_MARKERS = (
    "must provide query string",
    "syntax error",
    "cannot query field",
    "unknown operation named",
    "operation name is required",
    "anonymous operation must be the only defined operation",
)
GRAPHQL_ERROR_CODES = {
    "GRAPHQL_PARSE_FAILED",
    "GRAPHQL_VALIDATION_FAILED",
}


class GraphQLSignal(StrEnum):
    """GraphQL-specific response characteristics used by Phase 4 rules."""

    GRAPHQL_CONTENT_TYPE = "graphql_content_type"
    DATA_OBJECT = "data_object"
    TYPENAME_STRING = "typename_string"
    ERRORS_ARRAY = "errors_array"
    GRAPHQL_ERROR_MESSAGE = "graphql_error_message"
    GRAPHQL_ERROR_CODE = "graphql_error_code"


@dataclass(frozen=True)
class GraphQLResponseAnalysis:
    """Signals, confidence, and a concise deterministic explanation."""

    signals: tuple[GraphQLSignal, ...]
    confidence: ConfidenceLevel
    reason: str


def analyze_graphql_response(
    body: bytes,
    headers: Mapping[str, str],
) -> GraphQLResponseAnalysis:
    """Classify response content without using HTTP status as a signal."""
    signals: list[GraphQLSignal] = []
    content_type = _content_type(headers)
    if content_type in GRAPHQL_RESPONSE_MEDIA_TYPES:
        signals.append(GraphQLSignal.GRAPHQL_CONTENT_TYPE)

    document = _json_object(body)
    strong_error_reason: str | None = None
    if document is not None:
        data = document.get("data")
        if isinstance(data, dict):
            signals.append(GraphQLSignal.DATA_OBJECT)
            typed_data = cast(dict[str, object], data)
            typename = typed_data.get("__typename")
            if isinstance(typename, str) and re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", typename):
                signals.append(GraphQLSignal.TYPENAME_STRING)

        error_signals, strong_error_reason = _analyze_errors(document)
        signals.extend(error_signals)

    unique_signals = tuple(dict.fromkeys(signals))
    return _classify(unique_signals, strong_error_reason)


def no_response_analysis(reason: str) -> GraphQLResponseAnalysis:
    """Represent a candidate for which no analyzable response exists."""
    return GraphQLResponseAnalysis(
        signals=(),
        confidence=ConfidenceLevel.NOT_DETECTED,
        reason=reason,
    )


def select_final_analysis(
    get_analysis: GraphQLResponseAnalysis,
    post_analysis: GraphQLResponseAnalysis,
) -> GraphQLResponseAnalysis:
    """Select the strongest result using explicit confidence precedence."""
    if get_analysis.confidence is ConfidenceLevel.CONFIRMED:
        return get_analysis
    if post_analysis.confidence is ConfidenceLevel.CONFIRMED:
        return post_analysis
    if get_analysis.confidence is ConfidenceLevel.PROBABLE:
        return get_analysis
    if post_analysis.confidence is ConfidenceLevel.PROBABLE:
        return post_analysis
    if post_analysis.confidence is ConfidenceLevel.POSSIBLE:
        return post_analysis
    if get_analysis.confidence is ConfidenceLevel.POSSIBLE:
        return get_analysis
    return post_analysis


def _classify(
    signals: tuple[GraphQLSignal, ...],
    strong_error_reason: str | None,
) -> GraphQLResponseAnalysis:
    signal_set = set(signals)
    if GraphQLSignal.TYPENAME_STRING in signal_set:
        return GraphQLResponseAnalysis(
            signals=signals,
            confidence=ConfidenceLevel.CONFIRMED,
            reason="Valid data.__typename string.",
        )
    if strong_error_reason is not None:
        return GraphQLResponseAnalysis(
            signals=signals,
            confidence=ConfidenceLevel.PROBABLE,
            reason=strong_error_reason,
        )

    graphql_shape = bool(signal_set & {GraphQLSignal.DATA_OBJECT, GraphQLSignal.ERRORS_ARRAY})
    if GraphQLSignal.GRAPHQL_CONTENT_TYPE in signal_set and graphql_shape:
        return GraphQLResponseAnalysis(
            signals=signals,
            confidence=ConfidenceLevel.PROBABLE,
            reason="GraphQL-specific content type with GraphQL-shaped JSON.",
        )
    if GraphQLSignal.GRAPHQL_CONTENT_TYPE in signal_set:
        reason = "GraphQL-specific response content type."
    elif GraphQLSignal.ERRORS_ARRAY in signal_set:
        reason = "GraphQL-style errors array without a specific parser or validation signal."
    elif GraphQLSignal.DATA_OBJECT in signal_set:
        reason = "JSON data object without __typename confirmation."
    else:
        return GraphQLResponseAnalysis(
            signals=signals,
            confidence=ConfidenceLevel.NOT_DETECTED,
            reason="No deterministic GraphQL signal detected.",
        )
    return GraphQLResponseAnalysis(
        signals=signals,
        confidence=ConfidenceLevel.POSSIBLE,
        reason=reason,
    )


def _analyze_errors(
    document: dict[str, object],
) -> tuple[tuple[GraphQLSignal, ...], str | None]:
    errors = document.get("errors")
    if not isinstance(errors, list) or not errors:
        return (), None

    messages: list[str] = []
    strong_message: str | None = None
    strong_code: str | None = None
    for raw_error in errors:
        if not isinstance(raw_error, dict):
            continue
        error = cast(dict[str, object], raw_error)
        message = error.get("message")
        if isinstance(message, str):
            messages.append(message)
            lowered = message.casefold()
            if strong_message is None and any(
                marker in lowered for marker in GRAPHQL_ERROR_MESSAGE_MARKERS
            ):
                strong_message = message

        extensions = error.get("extensions")
        if isinstance(extensions, dict):
            typed_extensions = cast(dict[str, object], extensions)
            code = typed_extensions.get("code")
            if isinstance(code, str) and code.upper() in GRAPHQL_ERROR_CODES:
                strong_code = code.upper()

    if not messages:
        return (), None

    signals = [GraphQLSignal.ERRORS_ARRAY]
    if strong_message is not None:
        signals.append(GraphQLSignal.GRAPHQL_ERROR_MESSAGE)
        return tuple(signals), f'GraphQL-style errors: "{_short_message(strong_message)}"'
    if strong_code is not None:
        signals.append(GraphQLSignal.GRAPHQL_ERROR_CODE)
        return tuple(signals), f"GraphQL error code: {strong_code}."
    return tuple(signals), None


def _content_type(headers: Mapping[str, str]) -> str:
    for name, value in headers.items():
        if name.casefold() == "content-type":
            return value.partition(";")[0].strip().casefold()
    return ""


def _json_object(body: bytes) -> dict[str, object] | None:
    try:
        value: object = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    return cast(dict[str, object], value)


def _short_message(message: str) -> str:
    compact = " ".join(message.split())
    return compact if len(compact) <= 120 else f"{compact[:117]}..."
