"""Generate deterministic minimal Query operations without executing them."""

from graphql import GraphQLError, parse
from pydantic import JsonValue

from gqlsleuth.domain.analysis import OperationAnalysis, OperationKind
from gqlsleuth.domain.exceptions import QueryGenerationError
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import (
    ParsedSchema,
    SchemaArgument,
    SchemaField,
    SchemaInputField,
    SchemaNamedType,
    SchemaTypeKind,
    TypeReference,
    TypeReferenceKind,
)

DEFAULT_MAX_SELECTION_DEPTH = 3
_BUILTIN_PLACEHOLDERS: dict[str, JsonValue] = {
    "String": "test",
    "ID": "1",
    "Int": 1,
    "Float": 1.0,
    "Boolean": False,
}


def generate_query(
    schema: ParsedSchema,
    operation: OperationAnalysis,
    *,
    max_selection_depth: int = DEFAULT_MAX_SELECTION_DEPTH,
) -> QueryGenerationResult:
    """Generate one anonymous Query document from project-owned schema models."""
    if operation.kind is not OperationKind.QUERY:
        raise QueryGenerationError("Only Query-root operations can be generated in Phase 8.")
    if max_selection_depth < 1:
        raise QueryGenerationError("Maximum selection depth must be at least 1.")

    try:
        field = _query_field(schema, operation.name)
        required_arguments = tuple(
            sorted(
                (argument for argument in field.arguments if _is_required(argument)),
                key=lambda argument: argument.name,
            )
        )
        variables: dict[str, JsonValue] = {}
        adjustments: list[str] = []
        for argument in required_arguments:
            value, argument_adjustments = _placeholder(
                schema,
                argument.type,
                active_input_types=frozenset(),
            )
            variables[argument.name] = value
            adjustments.extend(argument_adjustments)

        selection = _response_selection(
            schema,
            field.type,
            depth=1,
            max_depth=max_selection_depth,
            active_types=frozenset(),
        )
        query_text = _render_query(field, required_arguments, selection)
        parse(query_text)
    except QueryGenerationError:
        raise
    except (GraphQLError, ValueError) as error:
        raise QueryGenerationError(f"Could not generate a valid query: {error}") from error

    return QueryGenerationResult(
        operation=operation,
        query_text=query_text,
        variables=variables,
        manual_adjustments=tuple(dict.fromkeys(adjustments)),
        failure_reason=None,
    )


def _query_field(schema: ParsedSchema, operation_name: str) -> SchemaField:
    root = schema.type_named(schema.query_root)
    if root is None or root.kind is not SchemaTypeKind.OBJECT:
        raise QueryGenerationError(f"Query root '{schema.query_root}' is unavailable.")
    field = next((item for item in root.fields if item.name == operation_name), None)
    if field is None:
        raise QueryGenerationError(
            f"Query operation '{operation_name}' is missing from root '{schema.query_root}'."
        )
    return field


def _is_required(argument: SchemaArgument | SchemaInputField) -> bool:
    return argument.type.outer_non_null and argument.default_value is None


def _placeholder(
    schema: ParsedSchema,
    reference: TypeReference,
    *,
    active_input_types: frozenset[str],
) -> tuple[JsonValue, tuple[str, ...]]:
    if reference.kind is TypeReferenceKind.NON_NULL:
        if reference.of_type is None:
            raise QueryGenerationError("Non-null input type is missing its wrapped type.")
        return _placeholder(
            schema,
            reference.of_type,
            active_input_types=active_input_types,
        )
    if reference.kind is TypeReferenceKind.LIST:
        if reference.of_type is None:
            raise QueryGenerationError("List input type is missing its item type.")
        item, adjustments = _placeholder(
            schema,
            reference.of_type,
            active_input_types=active_input_types,
        )
        return [item], adjustments

    type_name = reference.named_type
    if type_name in _BUILTIN_PLACEHOLDERS:
        return _BUILTIN_PLACEHOLDERS[type_name], ()
    named_type = schema.type_named(type_name)
    if named_type is None:
        raise QueryGenerationError(f"Input type '{type_name}' is unavailable in the schema.")
    if named_type.kind is SchemaTypeKind.SCALAR:
        return "test", (f"Custom scalar '{type_name}' may require manual adjustment.",)
    if named_type.kind is SchemaTypeKind.ENUM:
        values = tuple(value for value in named_type.enum_values if not value.is_deprecated)
        if not values:
            values = named_type.enum_values
        if not values:
            raise QueryGenerationError(f"Enum '{type_name}' has no values.")
        return min(values, key=lambda value: value.name).name, ()
    if named_type.kind is SchemaTypeKind.INPUT_OBJECT:
        if type_name in active_input_types:
            raise QueryGenerationError(f"Required input object cycle detected at '{type_name}'.")
        fields: dict[str, JsonValue] = {}
        input_adjustments: list[str] = []
        next_active = active_input_types | {type_name}
        for input_field in sorted(named_type.input_fields, key=lambda item: item.name):
            if not _is_required(input_field):
                continue
            value, field_adjustments = _placeholder(
                schema,
                input_field.type,
                active_input_types=next_active,
            )
            fields[input_field.name] = value
            input_adjustments.extend(field_adjustments)
        return fields, tuple(input_adjustments)
    raise QueryGenerationError(f"Type '{type_name}' cannot be used as an input placeholder.")


def _response_selection(
    schema: ParsedSchema,
    reference: TypeReference,
    *,
    depth: int,
    max_depth: int,
    active_types: frozenset[str],
) -> str | None:
    type_name = reference.named_type
    named_type = schema.type_named(type_name)
    if named_type is None:
        raise QueryGenerationError(f"Return type '{type_name}' is unavailable in the schema.")
    if named_type.kind in {SchemaTypeKind.SCALAR, SchemaTypeKind.ENUM}:
        return None
    if named_type.kind in {SchemaTypeKind.INTERFACE, SchemaTypeKind.UNION}:
        return "__typename"
    if named_type.kind is not SchemaTypeKind.OBJECT:
        raise QueryGenerationError(f"Type '{type_name}' cannot be selected as output.")

    direct_leaf = _preferred_leaf(schema, named_type)
    if direct_leaf is not None:
        return direct_leaf.name
    if depth >= max_depth or type_name in active_types:
        return "__typename"

    next_active = active_types | {type_name}
    for field in _eligible_fields(named_type):
        child_type = schema.type_named(field.type.named_type)
        if child_type is None or child_type.kind not in {
            SchemaTypeKind.OBJECT,
            SchemaTypeKind.INTERFACE,
            SchemaTypeKind.UNION,
        }:
            continue
        child_selection = _response_selection(
            schema,
            field.type,
            depth=depth + 1,
            max_depth=max_depth,
            active_types=next_active,
        )
        if child_selection is not None:
            return f"{field.name} {{\n{_indent(child_selection, 2)}\n}}"
    return "__typename"


def _preferred_leaf(schema: ParsedSchema, named_type: SchemaNamedType) -> SchemaField | None:
    leaves = tuple(
        field
        for field in _eligible_fields(named_type)
        if _is_leaf_type(schema, field.type.named_type)
    )
    return min(leaves, key=lambda field: (field.name != "id", field.name)) if leaves else None


def _eligible_fields(named_type: SchemaNamedType) -> tuple[SchemaField, ...]:
    return tuple(
        sorted(
            (
                field
                for field in named_type.fields
                if not field.is_deprecated
                and not any(_is_required(argument) for argument in field.arguments)
            ),
            key=lambda field: field.name,
        )
    )


def _is_leaf_type(schema: ParsedSchema, type_name: str) -> bool:
    named_type = schema.type_named(type_name)
    return named_type is not None and named_type.kind in {
        SchemaTypeKind.SCALAR,
        SchemaTypeKind.ENUM,
    }


def _render_query(
    field: SchemaField,
    required_arguments: tuple[SchemaArgument, ...],
    selection: str | None,
) -> str:
    definitions = ", ".join(
        f"${argument.name}: {argument.type.render()}" for argument in required_arguments
    )
    uses = ", ".join(f"{argument.name}: ${argument.name}" for argument in required_arguments)
    operation_header = f"query ({definitions})" if definitions else "query"
    field_call = f"{field.name}({uses})" if uses else field.name
    if selection is not None:
        field_call = f"{field_call} {{\n{_indent(selection, 2)}\n}}"
    return f"{operation_header} {{\n{_indent(field_call, 2)}\n}}"


def _indent(value: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" for line in value.splitlines())
