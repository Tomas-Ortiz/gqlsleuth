"""Build and map GraphQL introspection data into GQLSleuth schema models."""

import json
from collections.abc import Mapping
from typing import cast

from graphql import (
    GraphQLArgument,
    GraphQLDirective,
    GraphQLEnumType,
    GraphQLError,
    GraphQLField,
    GraphQLInputField,
    GraphQLInputObjectType,
    GraphQLInputType,
    GraphQLInterfaceType,
    GraphQLList,
    GraphQLNamedType,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLSchema,
    GraphQLType,
    GraphQLUnionType,
    Undefined,
    assert_valid_schema,
    ast_from_value,
    build_client_schema,
    is_named_type,
    print_ast,
)
from graphql.utilities.get_introspection_query import IntrospectionQuery

from gqlsleuth.domain.exceptions import SchemaParsingError
from gqlsleuth.domain.schema import (
    ParsedSchema,
    SchemaArgument,
    SchemaDirective,
    SchemaEnumValue,
    SchemaField,
    SchemaInputField,
    SchemaNamedType,
    SchemaSummary,
    SchemaTypeKind,
    TypeReference,
)

BUILTIN_SCALAR_NAMES = frozenset({"Boolean", "Float", "ID", "Int", "String"})


def parse_introspection_response(body: bytes) -> ParsedSchema:
    """Validate and map a complete GraphQL introspection HTTP response body."""
    data = _introspection_data(body)
    try:
        schema = build_client_schema(cast(IntrospectionQuery, data))
        assert_valid_schema(schema)
        return _map_schema(schema)
    except (GraphQLError, KeyError, TypeError, ValueError) as error:
        raise SchemaParsingError(
            f"Invalid or incomplete introspection schema: {_short_error(error)}"
        ) from error


def _introspection_data(body: bytes) -> dict[str, object]:
    try:
        document: object = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SchemaParsingError("Full introspection response is not valid JSON.") from error
    if not isinstance(document, dict):
        raise SchemaParsingError("Full introspection response must be a JSON object.")

    typed_document = cast(dict[str, object], document)
    errors = typed_document.get("errors")
    if isinstance(errors, list) and errors:
        raise SchemaParsingError("Full introspection response contains GraphQL errors.")

    data = typed_document.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("__schema"), dict):
        raise SchemaParsingError("Full introspection response is missing data.__schema.")
    return cast(dict[str, object], data)


def _map_schema(schema: GraphQLSchema) -> ParsedSchema:
    if schema.query_type is None:
        raise SchemaParsingError("Introspection schema does not define a query root.")

    represented_types = tuple(
        _map_named_type(schema, schema_type)
        for name, schema_type in sorted(schema.type_map.items())
        if not name.startswith("__")
    )
    directives = tuple(
        _map_directive(directive) for directive in sorted(schema.directives, key=_name)
    )
    summary = _summarize(schema, represented_types, directives)
    return ParsedSchema(
        query_root=schema.query_type.name,
        mutation_root=schema.mutation_type.name if schema.mutation_type is not None else None,
        subscription_root=(
            schema.subscription_type.name if schema.subscription_type is not None else None
        ),
        types=represented_types,
        directives=directives,
        summary=summary,
    )


def _map_named_type(schema: GraphQLSchema, schema_type: GraphQLNamedType) -> SchemaNamedType:
    if isinstance(schema_type, GraphQLObjectType):
        return SchemaNamedType(
            name=schema_type.name,
            kind=SchemaTypeKind.OBJECT,
            description=schema_type.description,
            fields=_map_fields(schema_type.fields),
            interfaces=tuple(sorted(interface.name for interface in schema_type.interfaces)),
        )
    if isinstance(schema_type, GraphQLInputObjectType):
        return SchemaNamedType(
            name=schema_type.name,
            kind=SchemaTypeKind.INPUT_OBJECT,
            description=schema_type.description,
            input_fields=_map_input_fields(schema_type.fields),
        )
    if isinstance(schema_type, GraphQLScalarType):
        return SchemaNamedType(
            name=schema_type.name,
            kind=SchemaTypeKind.SCALAR,
            description=schema_type.description,
        )
    if isinstance(schema_type, GraphQLEnumType):
        values = tuple(
            SchemaEnumValue(
                name=name,
                description=value.description,
                is_deprecated=value.deprecation_reason is not None,
                deprecation_reason=value.deprecation_reason,
            )
            for name, value in sorted(schema_type.values.items())
        )
        return SchemaNamedType(
            name=schema_type.name,
            kind=SchemaTypeKind.ENUM,
            description=schema_type.description,
            enum_values=values,
        )
    if isinstance(schema_type, GraphQLInterfaceType):
        return SchemaNamedType(
            name=schema_type.name,
            kind=SchemaTypeKind.INTERFACE,
            description=schema_type.description,
            fields=_map_fields(schema_type.fields),
            interfaces=tuple(sorted(interface.name for interface in schema_type.interfaces)),
            possible_types=tuple(
                sorted(possible.name for possible in schema.get_possible_types(schema_type))
            ),
        )
    if isinstance(schema_type, GraphQLUnionType):
        return SchemaNamedType(
            name=schema_type.name,
            kind=SchemaTypeKind.UNION,
            description=schema_type.description,
            possible_types=tuple(sorted(possible.name for possible in schema_type.types)),
        )
    raise SchemaParsingError(f"Unsupported GraphQL named type: {schema_type.name}.")


def _map_fields(fields: Mapping[str, GraphQLField]) -> tuple[SchemaField, ...]:
    return tuple(
        SchemaField(
            name=name,
            type=_map_type_reference(field.type),
            arguments=_map_arguments(field.args),
            description=field.description,
            is_deprecated=field.deprecation_reason is not None,
            deprecation_reason=field.deprecation_reason,
        )
        for name, field in sorted(fields.items())
    )


def _map_arguments(arguments: Mapping[str, GraphQLArgument]) -> tuple[SchemaArgument, ...]:
    return tuple(
        SchemaArgument(
            name=name,
            type=_map_type_reference(argument.type),
            description=argument.description,
            default_value=_format_default(argument.default_value, argument.type),
        )
        for name, argument in sorted(arguments.items())
    )


def _map_input_fields(fields: Mapping[str, GraphQLInputField]) -> tuple[SchemaInputField, ...]:
    return tuple(
        SchemaInputField(
            name=name,
            type=_map_type_reference(field.type),
            description=field.description,
            default_value=_format_default(field.default_value, field.type),
        )
        for name, field in sorted(fields.items())
    )


def _map_directive(directive: GraphQLDirective) -> SchemaDirective:
    return SchemaDirective(
        name=directive.name,
        description=directive.description,
        locations=tuple(sorted(location.name for location in directive.locations)),
        arguments=_map_arguments(directive.args),
    )


def _map_type_reference(type_: GraphQLType) -> TypeReference:
    if isinstance(type_, GraphQLNonNull):
        return TypeReference.non_null(_map_type_reference(type_.of_type))
    if isinstance(type_, GraphQLList):
        return TypeReference.list_of(_map_type_reference(type_.of_type))
    if is_named_type(type_):
        return TypeReference.named(cast(GraphQLNamedType, type_).name)
    raise SchemaParsingError("Unsupported GraphQL type reference.")


def _format_default(value: object, type_: GraphQLInputType) -> str | None:
    if value is Undefined:
        return None
    value_node = ast_from_value(value, type_)
    return print_ast(value_node) if value_node is not None else None


def _summarize(
    schema: GraphQLSchema,
    types: tuple[SchemaNamedType, ...],
    directives: tuple[SchemaDirective, ...],
) -> SchemaSummary:
    query_type = schema.query_type
    if query_type is None:
        raise SchemaParsingError("Introspection schema does not define a query root.")
    counts = {kind: sum(item.kind is kind for item in types) for kind in SchemaTypeKind}
    custom_scalars = sum(
        item.kind is SchemaTypeKind.SCALAR and item.name not in BUILTIN_SCALAR_NAMES
        for item in types
    )
    return SchemaSummary(
        query_root=query_type.name,
        mutation_root=schema.mutation_type.name if schema.mutation_type is not None else None,
        subscription_root=(
            schema.subscription_type.name if schema.subscription_type is not None else None
        ),
        total_type_count=len(types),
        object_type_count=counts[SchemaTypeKind.OBJECT],
        input_object_type_count=counts[SchemaTypeKind.INPUT_OBJECT],
        scalar_type_count=counts[SchemaTypeKind.SCALAR],
        custom_scalar_type_count=custom_scalars,
        enum_type_count=counts[SchemaTypeKind.ENUM],
        interface_type_count=counts[SchemaTypeKind.INTERFACE],
        union_type_count=counts[SchemaTypeKind.UNION],
        directive_count=len(directives),
        query_field_count=len(query_type.fields),
        mutation_field_count=(
            len(schema.mutation_type.fields) if schema.mutation_type is not None else 0
        ),
        subscription_field_count=(
            len(schema.subscription_type.fields) if schema.subscription_type is not None else 0
        ),
    )


def _name(value: GraphQLDirective) -> str:
    return value.name


def _short_error(error: Exception) -> str:
    compact = " ".join(str(error).split())
    return compact if len(compact) <= 240 else f"{compact[:237]}..."
