"""The JSON acceptance boundary must not depend on the interpreter's decoder stack."""

import json

import pytest

from gqlsleuth.domain.exceptions import SchemaParsingError
from gqlsleuth.graphql import response_json
from gqlsleuth.graphql.detection import analyze_graphql_response
from gqlsleuth.graphql.introspection import classify_introspection_response
from gqlsleuth.graphql.safe_execution import classify_execution_response
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.presentation.responses import present_response_body


def nested_value(depth, shape):
    value = "brackets [] and braces {} are text"
    for level in range(depth):
        value = (
            {"child": value} if shape == "objects" or (shape == "mixed" and level % 2) else [value]
        )
    return value


@pytest.mark.parametrize("shape", ["arrays", "objects", "mixed"])
@pytest.mark.parametrize("depth", [127, 128, 129])
def test_decoded_nesting_boundary(depth, shape):
    assert response_json.MAX_JSON_NESTING == 128
    value = nested_value(depth, shape)
    if depth <= response_json.MAX_JSON_NESTING:
        response_json.validate_json_nesting(value)
        assert response_json.decode_response_json(json.dumps(value)) == value
    else:
        with pytest.raises(response_json.JsonNestingError):
            response_json.validate_json_nesting(value)
        with pytest.raises(response_json.JsonNestingError):
            response_json.decode_response_json(json.dumps(value))


@pytest.mark.parametrize("shape", ["arrays", "objects", "mixed"])
def test_successfully_decoded_excessive_value_is_rejected_without_recursion(monkeypatch, shape):
    value = {"data": nested_value(5000, shape)}
    monkeypatch.setattr(response_json.json, "loads", lambda body: value)
    assert response_json.response_json_object(b"decoder accepted this input") is None
    assert analyze_graphql_response(b"", {}).confidence.value == "not_detected"
    assert classify_introspection_response(200, b"").status.value == "invalid_response"
    assert classify_execution_response(200, b"").status.value == "invalid_response"
    assert classify_execution_response(500, b"").status.value == "http_error"
    with pytest.raises(SchemaParsingError, match="exceeds supported JSON nesting"):
        parse_introspection_response(b"")
    view = present_response_body(b"{}")
    assert view.text == "" and "exceeds supported nesting" in view.notice


def test_decoder_recursion_error_remains_controlled(monkeypatch):
    def fail(body):
        raise RecursionError("PRIVATE decoder details")

    monkeypatch.setattr(response_json.json, "loads", fail)
    assert response_json.response_json_object(b"{}") is None
    with pytest.raises(
        response_json.JsonNestingError, match="^Response JSON exceeds supported nesting.$"
    ):
        response_json.decode_response_json(b"{}")


def test_strings_and_wide_containers_do_not_consume_nesting_budget():
    value = {"data": ["[{}]" * 5000] * 500}
    response_json.validate_json_nesting(value)
    assert response_json.decode_response_json('{"text": "' + "[{}]" * 5000 + '"}') == {
        "text": "[{}]" * 5000
    }
