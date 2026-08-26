"""Focused tests for deterministic GraphQL response signals."""

import pytest

from gqlsleuth.domain.models import ConfidenceLevel
from gqlsleuth.graphql.detection import GraphQLSignal, analyze_graphql_response


def test_clear_graphql_error_is_probable() -> None:
    analysis = analyze_graphql_response(
        b'{"errors":[{"message":"Must provide query string."}]}',
        {"content-type": "application/json"},
    )

    assert analysis.confidence is ConfidenceLevel.PROBABLE
    assert analysis.signals == (
        GraphQLSignal.ERRORS_ARRAY,
        GraphQLSignal.GRAPHQL_ERROR_MESSAGE,
    )
    assert analysis.reason == 'GraphQL-style errors: "Must provide query string."'


def test_valid_typename_data_is_confirmed() -> None:
    analysis = analyze_graphql_response(
        b'{"data":{"__typename":"Query"}}',
        {"content-type": "application/json"},
    )

    assert analysis.confidence is ConfidenceLevel.CONFIRMED
    assert GraphQLSignal.DATA_OBJECT in analysis.signals
    assert GraphQLSignal.TYPENAME_STRING in analysis.signals


def test_generic_json_does_not_create_a_false_positive() -> None:
    analysis = analyze_graphql_response(
        b'{"status":"ok","query":"saved","graphql":"label"}',
        {"content-type": "application/json"},
    )

    assert analysis.confidence is ConfidenceLevel.NOT_DETECTED
    assert analysis.signals == ()


@pytest.mark.parametrize(
    "body",
    [
        b"<html><h1>Generic server error</h1></html>",
        b'{"errors": malformed',
    ],
)
def test_non_json_and_malformed_responses_are_handled_safely(body: bytes) -> None:
    analysis = analyze_graphql_response(body, {"content-type": "text/html"})

    assert analysis.confidence is ConfidenceLevel.NOT_DETECTED
    assert analysis.signals == ()


def test_graphql_specific_content_type_is_a_possible_signal() -> None:
    analysis = analyze_graphql_response(
        b"not-json",
        {"Content-Type": "application/graphql-response+json; charset=utf-8"},
    )

    assert analysis.confidence is ConfidenceLevel.POSSIBLE
    assert analysis.signals == (GraphQLSignal.GRAPHQL_CONTENT_TYPE,)


def test_graphql_validation_error_code_is_probable() -> None:
    analysis = analyze_graphql_response(
        b'{"errors":[{"message":"Request rejected","extensions":'
        b'{"code":"GRAPHQL_VALIDATION_FAILED"}}]}',
        {"content-type": "application/json"},
    )

    assert analysis.confidence is ConfidenceLevel.PROBABLE
    assert GraphQLSignal.GRAPHQL_ERROR_CODE in analysis.signals
