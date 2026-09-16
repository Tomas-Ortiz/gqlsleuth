"""Bounded schema paths and structural authorization observations; never compare values."""

import json
from collections import deque

from graphql import (
    GraphQLInterfaceType,
    GraphQLObjectType,
    GraphQLSchema,
    get_named_type,
    parse,
    print_ast,
    validate,
)
from graphql.execution.values import get_argument_values, get_variable_values
from graphql.language.ast import FieldNode, OperationDefinitionNode, SelectionNode
from pydantic import JsonValue

from gqlsleuth.domain.analysis import RuleMatch, RuleSet
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.nested_authorization import (
    MAX_NESTED_AUTH_LIST_EDGES,
    MAX_NESTED_AUTH_SELECTION_DEPTH,
    NestedOutcome,
)
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import ParsedSchema, SchemaField, SchemaTypeKind
from gqlsleuth.graphql.authorization_response import explicit_authorization_error
from gqlsleuth.graphql.selection_paths import (
    composite_list_edges,
    extend_selection_path,
    schema_field,
    selection_depth,
)
from gqlsleuth.rules.operation_analysis import match_output_field
from gqlsleuth.rules.schema_graph import MAX_GRAPH_RELATIONSHIPS, TypeEdge


def discover_nested_paths(
    schema: ParsedSchema, root: str, rules: RuleSet
) -> tuple[tuple[tuple[tuple[TypeEdge, ...], tuple[RuleMatch, ...]], ...], tuple[str, ...]]:
    """Breadth-first, path-cycle-safe output inspection with the existing graph work budget."""
    field = schema_field(schema, schema.query_root, root)
    queue: deque[tuple[str, tuple[TypeEdge, ...], frozenset[str]]] = deque(
        [(field.type.named_type, (), frozenset({field.type.named_type}))]
    )
    found: list[tuple[tuple[TypeEdge, ...], tuple[RuleMatch, ...]]] = []
    examined = 0
    limitations = []
    while queue and examined < MAX_GRAPH_RELATIONSHIPS:
        name, path, seen = queue.popleft()
        named = schema.type_named(name)
        if named is None or named.kind is not SchemaTypeKind.OBJECT:
            limitations.append("Abstract or unavailable output types were not resolved.")
            continue
        for field in sorted(named.fields, key=lambda item: item.name):
            examined += 1
            if examined > MAX_GRAPH_RELATIONSHIPS:
                break
            target = schema.type_named(field.type.named_type)
            edge = TypeEdge(
                name, field.type.named_type, name + "." + field.name, field.type.is_list
            )
            next_path = (*path, edge)
            if target and target.kind in {SchemaTypeKind.SCALAR, SchemaTypeKind.ENUM}:
                matches = match_output_field(field, rules)
                if path and matches:
                    found.append((next_path, matches))
            elif (
                target
                and len(next_path) + 2 <= MAX_NESTED_AUTH_SELECTION_DEPTH
                and target.name not in seen
            ):
                queue.append((target.name, next_path, seen | {target.name}))
            elif target:
                limitations.append("Some output paths were omitted by the cycle/depth bound.")
    if queue or examined > MAX_GRAPH_RELATIONSHIPS:
        limitations.append("Output traversal reached the bounded schema-work limit.")
    return tuple(found), tuple(dict.fromkeys(limitations))


def path_fields(
    schema: ParsedSchema, root: str, names: tuple[str, ...]
) -> tuple[SchemaField, ...] | None:
    """Missing fields are distinct from unsupported abstract resolution."""
    field = schema_field(schema, schema.query_root, root)
    fields = [field]
    for name in names:
        named = schema.type_named(field.type.named_type)
        if named is None or named.kind is not SchemaTypeKind.OBJECT:
            raise SafeExecutionValidationError(
                "Nested path requires unsupported abstract type resolution."
            )
        child = next((item for item in named.fields if item.name == name), None)
        if child is None:
            return None
        field = child
        fields.append(field)
    return tuple(fields)


def field_signature(field: SchemaField) -> tuple[object, ...]:
    return (
        field.name,
        field.type.render(),
        tuple((arg.name, arg.type.render(), arg.default_value) for arg in field.arguments),
    )


def validate_common_document(
    native: GraphQLSchema, query: str, variables: dict[str, JsonValue]
) -> tuple[object, ...]:
    """Validate the one common AST and compare coerced inputs, including schema defaults."""
    document = parse(query)
    selection_depth(document, maximum_depth=MAX_NESTED_AUTH_SELECTION_DEPTH)
    if validate(native, document) or native.query_type is None:
        raise SafeExecutionValidationError(
            "Common nested document is unsupported by a retained schema."
        )
    operation = document.definitions[0]
    assert isinstance(operation, OperationDefinitionNode)
    coerced = get_variable_values(native, operation.variable_definitions or (), variables)
    if isinstance(coerced, list):
        raise SafeExecutionValidationError("Common variables are unsupported by a retained schema.")
    pending: list[tuple[GraphQLObjectType | GraphQLInterfaceType, SelectionNode]] = [
        (native.query_type, node) for node in operation.selection_set.selections
    ]
    arguments = []
    while pending:
        parent, node = pending.pop()
        assert isinstance(node, FieldNode)
        if node.name.value == "__typename":
            continue
        field = parent.fields[node.name.value]
        arguments.append(get_argument_values(field, node, coerced))
        child = get_named_type(field.type)
        if node.selection_set and isinstance(child, (GraphQLObjectType, GraphQLInterfaceType)):
            pending.extend((child, item) for item in node.selection_set.selections)
    return tuple(arguments)


def build_nested_query(
    schema: ParsedSchema,
    native: GraphQLSchema,
    base: QueryGenerationResult,
    path: tuple[TypeEdge, ...],
) -> tuple[str, int, int]:
    document = extend_selection_path(schema, native, base, path, terminal_typename=False)
    depth = selection_depth(document, maximum_depth=MAX_NESTED_AUTH_SELECTION_DEPTH)
    lists = composite_list_edges(schema, document)
    if lists > MAX_NESTED_AUTH_LIST_EDGES:
        raise SafeExecutionValidationError("Nested path exceeds one composite list expansion.")
    if validate(native, document):
        raise SafeExecutionValidationError(
            "Nested document does not validate against retained schema."
        )
    query = print_ast(document)
    if query == print_ast(parse(base.query_text or "")):
        raise SafeExecutionValidationError(
            "Nested path is already present in the baseline selection."
        )
    return query, depth, lists


def _terminal_present(data: object, path: tuple[str, ...]) -> bool:
    pending = [(data, 0)]
    while pending:
        node, offset = pending.pop()
        if offset == len(path):
            if node is not None:
                return True
        elif isinstance(node, list):
            pending.extend((item, offset) for item in node)
        elif isinstance(node, dict) and path[offset] in node:
            pending.append((node[path[offset]], offset + 1))
    return False


def classify_nested_response(
    status: int, body: bytes, path: tuple[str, ...]
) -> tuple[NestedOutcome, str]:
    """Use presence and explicit denial only. Returned business values never leave this function."""
    try:
        document = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        document = None
    returned = (
        isinstance(document, dict)
        and isinstance(document.get("data"), dict)
        and _terminal_present(document["data"], path)
    )
    if status in {401, 403} and not returned:
        return NestedOutcome.EXPLICIT_DENIAL, "HTTP authorization denial of this concrete request."
    if not isinstance(document, dict):
        return NestedOutcome.INDETERMINATE, "No interpretable GraphQL path observation."
    errors = document.get("errors")
    if errors:
        if (
            not returned
            and isinstance(errors, list)
            and all(explicit_authorization_error(error, path) for error in errors)
        ):
            return (
                NestedOutcome.EXPLICIT_DENIAL,
                "Explicit GraphQL authorization denial applicable to the tested path.",
            )
        return (
            NestedOutcome.INDETERMINATE,
            "Errors or partial data prevent an isolated path-access observation.",
        )
    if 200 <= status < 300 and returned:
        return NestedOutcome.RETURNED, "A non-null terminal occurrence was structurally observed."
    return (
        NestedOutcome.INDETERMINATE,
        "No conclusive terminal presence or explicit authorization denial.",
    )
