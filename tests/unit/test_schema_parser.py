"""Focused tests for deterministic GraphQL introspection schema parsing."""

from pathlib import Path

import pytest

from gqlsleuth.domain.exceptions import SchemaParsingError
from gqlsleuth.domain.schema import ParsedSchema, SchemaTypeKind, TypeReferenceKind
from gqlsleuth.graphql.schema_parser import parse_introspection_response

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_query_only_schema_parses_with_optional_roots_absent() -> None:
    schema = _parse_fixture("introspection_query_only.json")

    assert schema.query_root == "Query"
    assert schema.mutation_root is None
    assert schema.subscription_root is None
    assert schema.summary.query_field_count == 1
    assert schema.summary.mutation_field_count == 0
    assert schema.summary.subscription_field_count == 0


def test_schema_roots_summary_and_application_types_are_deterministic() -> None:
    schema = _parse_fixture("introspection_schema.json")
    summary = schema.summary

    assert (schema.query_root, schema.mutation_root, schema.subscription_root) == (
        "Query",
        "Mutation",
        "Subscription",
    )
    assert summary.total_type_count == 13
    assert summary.object_type_count == 5
    assert summary.input_object_type_count == 1
    assert summary.scalar_type_count == 4
    assert summary.custom_scalar_type_count == 1
    assert summary.enum_type_count == 1
    assert summary.interface_type_count == 1
    assert summary.union_type_count == 1
    assert summary.query_field_count == 3
    assert summary.mutation_field_count == 1
    assert summary.subscription_field_count == 1
    date_time = schema.type_named("DateTime")
    assert date_time is not None
    assert date_time.kind is SchemaTypeKind.SCALAR
    assert all(not schema_type.name.startswith("__") for schema_type in schema.types)


def test_fields_arguments_and_type_wrappers_preserve_graphql_semantics() -> None:
    schema = _parse_fixture("introspection_schema.json")
    query = schema.type_named("Query")
    assert query is not None
    fields = {field.name: field for field in query.fields}

    user = fields["user"]
    assert user.description == "Find one user by identifier."
    assert user.type.named_type == "User"
    assert user.arguments[0].name == "id"
    assert user.arguments[0].description == "Stable user identifier."
    assert user.arguments[0].type.render() == "ID!"

    search_type = fields["search"].type
    assert search_type.render() == "[SearchResult!]!"
    assert search_type.named_type == "SearchResult"
    assert search_type.outer_non_null is True
    assert search_type.is_list is True
    assert search_type.list_item is not None
    assert search_type.list_item.kind is TypeReferenceKind.NON_NULL
    assert search_type.list_item.outer_non_null is True
    assert search_type.list_item.named_type == "SearchResult"


def test_input_enum_descriptions_and_deprecations_are_preserved() -> None:
    schema = _parse_fixture("introspection_schema.json")
    user_filter = schema.type_named("UserFilter")
    role = schema.type_named("Role")
    user = schema.type_named("User")
    assert user_filter is not None
    assert role is not None
    assert user is not None

    input_fields = {field.name: field for field in user_filter.input_fields}
    assert input_fields["role"].default_value == "USER"
    assert input_fields["role"].type.named_type == "Role"
    assert input_fields["names"].type.render() == "[String!]"

    enum_values = {value.name: value for value in role.enum_values}
    assert enum_values["ADMIN"].is_deprecated is True
    assert enum_values["ADMIN"].deprecation_reason == "Use SUPERUSER."
    assert user.description == "Application user."
    legacy_name = next(field for field in user.fields if field.name == "legacyName")
    assert legacy_name.is_deprecated is True
    assert legacy_name.deprecation_reason == "Use name."


def test_interfaces_unions_and_directives_use_named_relationships() -> None:
    schema = _parse_fixture("introspection_schema.json")
    node = schema.type_named("Node")
    user = schema.type_named("User")
    search_result = schema.type_named("SearchResult")
    assert node is not None
    assert user is not None
    assert search_result is not None

    assert node.possible_types == ("Admin", "User")
    assert user.interfaces == ("Node",)
    assert search_result.possible_types == ("Admin", "User")
    assert {directive.name for directive in schema.directives} >= {"deprecated", "include", "skip"}


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"{malformed", "not valid JSON"),
        (b"[]", "must be a JSON object"),
        (b'{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}', "Invalid"),
    ],
)
def test_invalid_or_incomplete_schema_data_raises_controlled_error(
    body: bytes,
    message: str,
) -> None:
    with pytest.raises(SchemaParsingError, match=message):
        parse_introspection_response(body)


def _parse_fixture(name: str) -> ParsedSchema:
    return parse_introspection_response((FIXTURES / name).read_bytes())
