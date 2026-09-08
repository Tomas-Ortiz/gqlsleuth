"""Project-owned status values for safe Query execution."""

from enum import StrEnum


class QueryExecutionStatus(StrEnum):
    """Deterministic outcome of one generated Query artifact."""

    SUCCESS = "success"
    GRAPHQL_ERROR = "graphql_error"
    HTTP_ERROR = "http_error"
    INVALID_RESPONSE = "invalid_response"
    NETWORK_FAILURE = "network_failure"
    SKIPPED_SAFETY = "skipped_safety"
    SKIPPED_LIMIT = "skipped_limit"
