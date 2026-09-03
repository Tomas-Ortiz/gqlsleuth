"""Focused tests for deterministic Phase 8 query generation."""

import pytest
from graphql import parse

from gqlsleuth.domain.analysis import (
    InterestPriority,
    OperationAnalysis,
    OperationCategory,
    OperationKind,
)
from gqlsleuth.domain.exceptions import QueryGenerationError
from gqlsleuth.domain.schema import (
    ParsedSchema,
    SchemaArgument,
    SchemaEnumValue,
    SchemaField,
    SchemaInputField,
    SchemaNamedType,
    SchemaSummary,
    SchemaTypeKind,
    TypeReference,
)
from gqlsleuth.graphql.query_generation import generate_query

ENDPOINT = "https://example.com/graphql"


def test_scalar_query_without_arguments_is_valid_and_deterministic() -> None:
    schema = _schema((SchemaField(name="ping", type=_named("String")),))
    operation = _operation("ping", _named("String"))

    first = generate_query(schema, operation)
    second = generate_query(schema, operation)

    assert first.success
    assert first.query_text == "query {\n  ping\n}"
    assert first.variables == {}
    assert first == second
    parse(first.query_text or "")


def test_object_query_prefers_direct_id_then_first_deterministic_leaf() -> None:
    user = SchemaNamedType(
        name="User",
        kind=SchemaTypeKind.OBJECT,
        fields=(
            SchemaField(name="username", type=_named("String")),
            SchemaField(name="id", type=_non_null(_named("ID"))),
        ),
    )
    profile = SchemaNamedType(
        name="Profile",
        kind=SchemaTypeKind.OBJECT,
        fields=(
            SchemaField(name="zeta", type=_named("String")),
            SchemaField(name="alpha", type=_named("String")),
        ),
    )
    schema = _schema(
        (
            SchemaField(name="user", type=_named("User")),
            SchemaField(name="profile", type=_named("Profile")),
        ),
        extra_types=(user, profile),
    )

    user_query = generate_query(schema, _operation("user", _named("User")))
    profile_query = generate_query(schema, _operation("profile", _named("Profile")))

    assert user_query.query_text == "query {\n  user {\n    id\n  }\n}"
    assert profile_query.query_text == "query {\n  profile {\n    alpha\n  }\n}"


def test_required_builtin_arguments_get_variables_and_optional_arguments_are_omitted() -> None:
    field = SchemaField(
        name="lookup",
        type=_named("String"),
        arguments=(
            SchemaArgument(name="text", type=_non_null(_named("String"))),
            SchemaArgument(name="id", type=_non_null(_named("ID"))),
            SchemaArgument(name="count", type=_non_null(_named("Int"))),
            SchemaArgument(name="ratio", type=_non_null(_named("Float"))),
            SchemaArgument(name="enabled", type=_non_null(_named("Boolean"))),
            SchemaArgument(name="optional", type=_named("String")),
            SchemaArgument(name="withDefault", type=_non_null(_named("Int")), default_value="1"),
        ),
    )
    schema = _schema((field,))

    result = generate_query(schema, _operation("lookup", _named("String")))

    assert result.variables == {
        "count": 1,
        "enabled": False,
        "id": "1",
        "ratio": 1.0,
        "text": "test",
    }
    assert result.query_text is not None
    assert "$optional" not in result.query_text
    assert "$withDefault" not in result.query_text
    assert (
        "query ($count: Int!, $enabled: Boolean!, $id: ID!, $ratio: Float!, $text: String!)"
        in result.query_text
    )
    parse(result.query_text)


def test_enum_input_object_list_and_custom_scalar_placeholders_are_minimal() -> None:
    status = SchemaNamedType(
        name="Status",
        kind=SchemaTypeKind.ENUM,
        enum_values=(
            SchemaEnumValue(name="ARCHIVED", is_deprecated=True),
            SchemaEnumValue(name="OPEN"),
        ),
    )
    filter_input = SchemaNamedType(
        name="FilterInput",
        kind=SchemaTypeKind.INPUT_OBJECT,
        input_fields=(
            SchemaInputField(name="status", type=_non_null(_named("Status"))),
            SchemaInputField(name="limit", type=_named("Int")),
        ),
    )
    custom_scalar = SchemaNamedType(name="DateTime", kind=SchemaTypeKind.SCALAR)
    field = SchemaField(
        name="events",
        type=_named("String"),
        arguments=(
            SchemaArgument(name="filter", type=_non_null(_named("FilterInput"))),
            SchemaArgument(
                name="ids",
                type=_non_null(TypeReference.list_of(_non_null(_named("ID")))),
            ),
            SchemaArgument(name="when", type=_non_null(_named("DateTime"))),
        ),
    )
    schema = _schema((field,), extra_types=(status, filter_input, custom_scalar))

    result = generate_query(schema, _operation("events", _named("String")))

    assert result.variables == {
        "filter": {"status": "OPEN"},
        "ids": ["1"],
        "when": "test",
    }
    assert result.query_text is not None
    assert "$ids: [ID!]!" in result.query_text
    assert result.manual_adjustments == ("Custom scalar 'DateTime' may require manual adjustment.",)
    parse(result.query_text)


def test_required_recursive_input_object_fails_cleanly() -> None:
    recursive_input = SchemaNamedType(
        name="RecursiveInput",
        kind=SchemaTypeKind.INPUT_OBJECT,
        input_fields=(SchemaInputField(name="child", type=_non_null(_named("RecursiveInput"))),),
    )
    field = SchemaField(
        name="recursive",
        type=_named("String"),
        arguments=(SchemaArgument(name="input", type=_non_null(_named("RecursiveInput"))),),
    )
    schema = _schema((field,), extra_types=(recursive_input,))

    with pytest.raises(QueryGenerationError, match="Required input object cycle"):
        generate_query(schema, _operation("recursive", _named("String")))


def test_nested_selection_respects_depth_cycles_and_required_child_arguments() -> None:
    wrapper = SchemaNamedType(
        name="Wrapper",
        kind=SchemaTypeKind.OBJECT,
        fields=(
            SchemaField(
                name="blocked",
                type=_named("Child"),
                arguments=(SchemaArgument(name="id", type=_non_null(_named("ID"))),),
            ),
            SchemaField(name="child", type=_named("Child")),
        ),
    )
    child = SchemaNamedType(
        name="Child",
        kind=SchemaTypeKind.OBJECT,
        fields=(SchemaField(name="wrapper", type=_named("Wrapper")),),
    )
    field = SchemaField(name="nested", type=_named("Wrapper"))
    schema = _schema((field,), extra_types=(wrapper, child))

    limited = generate_query(
        schema,
        _operation("nested", _named("Wrapper")),
        max_selection_depth=1,
    )
    recursive = generate_query(schema, _operation("nested", _named("Wrapper")))

    assert limited.query_text == "query {\n  nested {\n    __typename\n  }\n}"
    assert recursive.query_text is not None
    assert "blocked" not in recursive.query_text
    assert "child {\n      wrapper {\n        __typename" in recursive.query_text
    parse(recursive.query_text)


@pytest.mark.parametrize("kind", [SchemaTypeKind.INTERFACE, SchemaTypeKind.UNION])
def test_interface_and_union_returns_use_typename(kind: SchemaTypeKind) -> None:
    abstract = SchemaNamedType(name="Result", kind=kind)
    schema = _schema(
        (SchemaField(name="result", type=_named("Result")),),
        extra_types=(abstract,),
    )

    result = generate_query(schema, _operation("result", _named("Result")))

    assert result.query_text == "query {\n  result {\n    __typename\n  }\n}"
    parse(result.query_text or "")


def test_mutation_is_rejected_by_the_query_generator() -> None:
    schema = _schema((SchemaField(name="health", type=_named("String")),))

    with pytest.raises(QueryGenerationError, match="Only Query-root"):
        generate_query(
            schema,
            _operation("deleteUser", _named("String"), kind=OperationKind.MUTATION),
        )


def _operation(
    name: str,
    return_type: TypeReference,
    *,
    kind: OperationKind = OperationKind.QUERY,
) -> OperationAnalysis:
    return OperationAnalysis(
        endpoint=ENDPOINT,
        kind=kind,
        name=name,
        return_type=return_type,
        categories=(OperationCategory.READ_ONLY_BUSINESS_DATA,),
        interest_score=0,
        priority=InterestPriority.INFORMATIONAL,
        matched_rules=(),
        reasons=(),
    )


def _schema(
    query_fields: tuple[SchemaField, ...],
    *,
    extra_types: tuple[SchemaNamedType, ...] = (),
) -> ParsedSchema:
    builtins = tuple(
        SchemaNamedType(name=name, kind=SchemaTypeKind.SCALAR)
        for name in ("Boolean", "Float", "ID", "Int", "String")
        if all(item.name != name for item in extra_types)
    )
    types = (
        SchemaNamedType(name="Query", kind=SchemaTypeKind.OBJECT, fields=query_fields),
        *extra_types,
        *builtins,
    )
    return ParsedSchema(
        query_root="Query",
        mutation_root=None,
        subscription_root=None,
        types=types,
        directives=(),
        summary=SchemaSummary(
            query_root="Query",
            mutation_root=None,
            subscription_root=None,
            total_type_count=len(types),
            object_type_count=1,
            input_object_type_count=0,
            scalar_type_count=len(builtins),
            custom_scalar_type_count=0,
            enum_type_count=0,
            interface_type_count=0,
            union_type_count=0,
            directive_count=0,
            query_field_count=len(query_fields),
            mutation_field_count=0,
            subscription_field_count=0,
        ),
    )


def _named(name: str) -> TypeReference:
    return TypeReference.named(name)


def _non_null(reference: TypeReference) -> TypeReference:
    return TypeReference.non_null(reference)
