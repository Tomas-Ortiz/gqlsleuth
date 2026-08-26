"""Focused tests for deterministic introspection response classification."""

import pytest

from gqlsleuth.graphql.introspection import (
    IntrospectionStatus,
    classify_introspection_response,
)


def test_schema_object_enables_introspection() -> None:
    classification = classify_introspection_response(
        200,
        b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
    )

    assert classification.status is IntrospectionStatus.ENABLED


def test_clear_graphql_denial_disables_introspection() -> None:
    classification = classify_introspection_response(
        400,
        b'{"errors":[{"message":"GraphQL introspection is disabled."}]}',
    )

    assert classification.status is IntrospectionStatus.DISABLED
    assert "introspection is disabled" in classification.reason


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, IntrospectionStatus.AUTHENTICATION_REQUIRED),
        (403, IntrospectionStatus.AUTHORIZATION_DENIED),
    ],
)
def test_authentication_and_authorization_statuses(
    status_code: int,
    expected: IntrospectionStatus,
) -> None:
    classification = classify_introspection_response(status_code, b"not-json")

    assert classification.status is expected


@pytest.mark.parametrize(
    "body",
    [
        b'{"data":{"__schema":null}}',
        b'{"data": malformed',
    ],
)
def test_structurally_invalid_and_malformed_responses_are_safe(body: bytes) -> None:
    classification = classify_introspection_response(200, body)

    assert classification.status is IntrospectionStatus.INVALID_RESPONSE


def test_other_graphql_errors_are_endpoint_errors() -> None:
    classification = classify_introspection_response(
        200,
        b'{"errors":[{"message":"Internal execution failure"}]}',
    )

    assert classification.status is IntrospectionStatus.ENDPOINT_ERROR


def test_generic_server_error_is_an_endpoint_error() -> None:
    classification = classify_introspection_response(500, b"<html>Server error</html>")

    assert classification.status is IntrospectionStatus.ENDPOINT_ERROR
