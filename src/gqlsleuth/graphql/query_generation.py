"""Generate minimal Query and Mutation documents using shared finite input/output rules."""

from graphql import GraphQLError, parse
from pydantic import JsonValue

from gqlsleuth.domain.active import MutationGenerationResult
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
from gqlsleuth.graphql.collection_schema import collection_paths, iter_bounding_inputs
from gqlsleuth.rules.operation_analysis import normalize_terms

DEFAULT_MAX_SELECTION_DEPTH = 3
_BUILTIN_PLACEHOLDERS: dict[str, JsonValue] = {
    "String": "test",
    "ID": "1",
    "Int": 1,
    "Float": 1.0,
    "Boolean": False,
}
_STRING_PLACEHOLDERS = {
    ("email",): "test@example.com",
    ("email", "address"): "test@example.com",
    ("mail",): "test@example.com",
    ("mail", "address"): "test@example.com",
    ("password",): "TestPass123!",
    ("passwd",): "TestPass123!",
    ("passcode",): "TestPass123!",
    ("username",): "testuser",
    ("user", "name"): "testuser",
    ("login", "name"): "testuser",
    ("name",): "Test User",
    ("first", "name"): "Test",
    ("last", "name"): "User",
    ("full", "name"): "Test User",
    ("display", "name"): "Test User",
    ("url",): "https://example.com",
    ("uri",): "https://example.com",
    ("website",): "https://example.com",
    ("website", "url"): "https://example.com",
    ("callback", "url"): "https://example.com",
    ("redirect", "url"): "https://example.com",
    ("phone",): "+15555550100",
    ("phone", "number"): "+15555550100",
    ("telephone",): "+15555550100",
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
    return QueryGenerationResult(
        operation, *_generate_document(schema, operation, max_selection_depth)
    )


def generate_mutation(
    schema: ParsedSchema,
    operation: OperationAnalysis,
    *,
    max_selection_depth: int = DEFAULT_MAX_SELECTION_DEPTH,
) -> MutationGenerationResult:
    """Generate one anonymous Mutation locally; callers must gate execution separately."""
    if operation.kind is not OperationKind.MUTATION:
        raise QueryGenerationError("Only Mutation-root operations can generate Mutations.")
    return MutationGenerationResult(
        operation, *_generate_document(schema, operation, max_selection_depth)
    )


def _generate_document(
    schema: ParsedSchema,
    operation: OperationAnalysis,
    max_selection_depth: int,
) -> tuple[str, dict[str, JsonValue], tuple[str, ...], None]:
    if max_selection_depth < 1:
        raise QueryGenerationError("Maximum selection depth must be at least 1.")

    try:
        field = _operation_field(schema, operation)
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
                input_name=argument.name,
                active_input_types=frozenset(),
            )
            variables[argument.name] = value
            adjustments.extend(argument_adjustments)

        if operation.kind is OperationKind.QUERY:
            bound = generate_collection_bound(schema, field)
            if bound is not None:
                argument, value, bound_adjustments = bound
                variables[argument.name] = value
                adjustments.extend(bound_adjustments)
        arguments = tuple(
            sorted(
                (argument for argument in field.arguments if argument.name in variables),
                key=lambda argument: argument.name,
            )
        )
        selection = _response_selection(
            schema,
            field.type,
            depth=1,
            max_depth=max_selection_depth,
            active_types=frozenset(),
        )
        query_text = _render_query(field, arguments, selection, operation.kind)
        parse(query_text)
    except QueryGenerationError:
        raise
    except (GraphQLError, ValueError) as error:
        raise QueryGenerationError(f"Could not generate a valid query: {error}") from error

    return query_text, variables, tuple(dict.fromkeys(adjustments)), None


def _operation_field(schema: ParsedSchema, operation: OperationAnalysis) -> SchemaField:
    root_name = schema.query_root if operation.kind is OperationKind.QUERY else schema.mutation_root
    kind = operation.kind.value.title()
    root = schema.type_named(root_name) if root_name is not None else None
    if root is None or root.kind is not SchemaTypeKind.OBJECT:
        raise QueryGenerationError(f"{kind} root '{root_name}' is unavailable.")
    field = next((item for item in root.fields if item.name == operation.name), None)
    if field is None:
        raise QueryGenerationError(
            f"{kind} operation '{operation.name}' is missing from root '{root_name}'."
        )
    return field


def _is_required(argument: SchemaArgument | SchemaInputField) -> bool:
    return argument.type.outer_non_null and argument.default_value is None


def generate_collection_bound(
    schema: ParsedSchema, field: SchemaField
) -> tuple[SchemaArgument, JsonValue, tuple[str, ...]] | None:
    """Populate at most one Int quantity control; unsafe optional paths stay omitted."""
    types = {item.name: item for item in schema.types}
    if not collection_paths(field, types):
        return None
    arguments = {argument.name: argument for argument in field.arguments}
    for path in iter_bounding_inputs(field, types):
        argument_name, *children = path.split(".")
        argument = arguments[argument_name]
        try:
            value, adjustments = _placeholder(
                schema,
                argument.type,
                input_name=argument.name,
                active_input_types=frozenset(),
                bound_path=tuple(children),
            )
        except QueryGenerationError:
            # Optional bounds must not break an otherwise generatable Query.
            continue
        return argument, value, adjustments
    return None


def generate_input_path(
    schema: ParsedSchema,
    reference: TypeReference,
    path: tuple[str, ...],
    *,
    input_name: str,
) -> JsonValue:
    """Materialize one explicit input path using the existing required-input placeholders."""
    value, _ = _placeholder(
        schema, reference, input_name=input_name, active_input_types=frozenset()
    )
    if not path:
        return value
    named = schema.type_named(reference.named_type)
    if reference.is_list or named is None or not isinstance(value, dict):
        raise QueryGenerationError("Selected input path requires non-list input objects.")
    child = next((item for item in named.input_fields if item.name == path[0]), None)
    if child is None:
        raise QueryGenerationError("Selected input path is unavailable.")
    value[child.name] = generate_input_path(schema, child.type, path[1:], input_name=child.name)
    return value


def _placeholder(
    schema: ParsedSchema,
    reference: TypeReference,
    *,
    input_name: str,
    active_input_types: frozenset[str],
    bound_path: tuple[str, ...] | None = None,
) -> tuple[JsonValue, tuple[str, ...]]:
    if reference.kind is TypeReferenceKind.NON_NULL:
        if reference.of_type is None:
            raise QueryGenerationError("Non-null input type is missing its wrapped type.")
        return _placeholder(
            schema,
            reference.of_type,
            input_name=input_name,
            active_input_types=active_input_types,
            bound_path=bound_path,
        )
    if reference.kind is TypeReferenceKind.LIST:
        if bound_path is not None:
            raise QueryGenerationError("Quantity bounds cannot traverse list inputs.")
        if reference.of_type is None:
            raise QueryGenerationError("List input type is missing its item type.")
        item, adjustments = _placeholder(
            schema,
            reference.of_type,
            input_name=input_name,
            active_input_types=active_input_types,
        )
        return [item], adjustments

    type_name = reference.named_type
    if bound_path == ():
        if type_name != "Int":
            raise QueryGenerationError("Generated quantity bounds require an Int input.")
        return 1, ()
    if type_name == "String":
        return _STRING_PLACEHOLDERS.get(normalize_terms(input_name), "test"), ()
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
            on_bound_path = (
                bound_path is not None and len(bound_path) > 0 and input_field.name == bound_path[0]
            )
            if not _is_required(input_field) and not on_bound_path:
                continue
            value, field_adjustments = _placeholder(
                schema,
                input_field.type,
                input_name=input_field.name,
                active_input_types=next_active,
                bound_path=bound_path[1:] if on_bound_path and bound_path else None,
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
    kind: OperationKind,
) -> str:
    definitions = ", ".join(
        f"${argument.name}: {argument.type.render()}" for argument in required_arguments
    )
    uses = ", ".join(f"{argument.name}: ${argument.name}" for argument in required_arguments)
    operation_header = f"{kind.value} ({definitions})" if definitions else kind.value
    field_call = f"{field.name}({uses})" if uses else field.name
    if selection is not None:
        field_call = f"{field_call} {{\n{_indent(selection, 2)}\n}}"
    return f"{operation_header} {{\n{_indent(field_call, 2)}\n}}"


def _indent(value: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" for line in value.splitlines())
