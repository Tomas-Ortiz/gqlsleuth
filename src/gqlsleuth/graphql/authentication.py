"""Authentication outcome interpretation using existing success and exact denial rules."""

import json

from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.nested_authorization import NestedOutcome
from gqlsleuth.graphql.authorization_response import explicit_authorization_error
from gqlsleuth.graphql.safe_execution import classify_execution_response


def classify_authentication_response(status: int, body: bytes, operation: str) -> NestedOutcome:
    if status in {401, 403}:
        return NestedOutcome.EXPLICIT_DENIAL
    try:
        document = json.loads(body)
        classification = classify_execution_response(status, body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return NestedOutcome.INDETERMINATE
    if not isinstance(document, dict):
        return NestedOutcome.INDETERMINATE
    errors = document.get("errors")
    if errors:
        return (
            NestedOutcome.EXPLICIT_DENIAL
            if isinstance(errors, list)
            and all(explicit_authorization_error(error, (operation,)) for error in errors)
            else NestedOutcome.INDETERMINATE
        )
    data = document.get("data")
    # Phase 9 data:null remains SUCCESS. It does not establish access for this policy test.
    if (
        200 <= status < 300
        and classification.status is QueryExecutionStatus.SUCCESS
        and isinstance(data, dict)
        and operation in data
        and data[operation] is not None
    ):
        return NestedOutcome.RETURNED
    return NestedOutcome.INDETERMINATE
