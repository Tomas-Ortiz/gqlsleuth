"""Shared conservative AST path extension for bounded read-only review requests."""

from graphql import (
    GraphQLInterfaceType,
    GraphQLObjectType,
    GraphQLSchema,
    ast_from_value,
    parse,
    validate,
)
from graphql.execution.values import get_argument_values, get_variable_values
from graphql.language.ast import (
    ArgumentNode,
    DocumentNode,
    FieldNode,
    NameNode,
    OperationDefinitionNode,
    SelectionSetNode,
)

from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import ParsedSchema, SchemaField, TypeReferenceKind
from gqlsleuth.graphql.query_generation import generate_collection_bound
from gqlsleuth.graphql.safe_execution import side_effect_tokens, validate_safe_artifact
from gqlsleuth.rules.schema_graph import COMPOSITE_KINDS, TypeEdge


def selection_depth(document: DocumentNode, *, maximum_depth: int) -> int:
    """Maximum root-to-leaf field-node count; unsupported fragments/aliases are rejected."""
    if len(document.definitions) != 1 or not isinstance(
        document.definitions[0], OperationDefinitionNode
    ):
        raise SafeExecutionValidationError("Depth probe requires exactly one operation definition.")
    operation = document.definitions[0]
    if operation.operation.value != "query" or operation.name or operation.directives:
        raise SafeExecutionValidationError("Depth probe requires an anonymous plain Query.")
    if len(operation.selection_set.selections) != 1:
        raise SafeExecutionValidationError("Depth probe must retain one root field.")
    pending = [(field, 1) for field in operation.selection_set.selections]
    maximum = 0
    while pending:
        node, depth = pending.pop()
        if not isinstance(node, FieldNode) or node.alias or node.directives:
            raise SafeExecutionValidationError(
                "Depth probes cannot contain aliases, fragments or directives."
            )
        if depth > maximum_depth:
            raise SafeExecutionValidationError(
                f"Constructed selection exceeds depth {maximum_depth}."
            )
        maximum = max(maximum, depth)
        if node.selection_set:
            pending.extend((child, depth + 1) for child in node.selection_set.selections)
    return maximum


def schema_field(schema: ParsedSchema, source: str, name: str) -> SchemaField:
    named = schema.type_named(source)
    found = next((field for field in named.fields if field.name == name), None) if named else None
    if found is None:
        raise SafeExecutionValidationError(
            "Recursive witness requires an unsupported field/abstract edge."
        )
    return found


def composite_list_edges(schema: ParsedSchema, document: DocumentNode) -> int:
    operation = document.definitions[0]
    assert isinstance(operation, OperationDefinitionNode)
    pending = [(schema.query_root, node) for node in operation.selection_set.selections]
    count = 0
    while pending:
        source, node = pending.pop()
        assert isinstance(node, FieldNode)
        if node.name.value == "__typename":
            continue
        field = schema_field(schema, source, node.name.value)
        target = schema.type_named(field.type.named_type)
        if target and target.kind in COMPOSITE_KINDS:
            reference = field.type
            while reference.of_type:
                count += int(reference.kind is TypeReferenceKind.LIST)
                reference = reference.of_type
            if node.selection_set:
                pending.extend((target.name, child) for child in node.selection_set.selections)
    return count


def extend_selection_path(
    schema: ParsedSchema,
    native: GraphQLSchema,
    base: QueryGenerationResult,
    path: tuple[TypeEdge, ...],
    *,
    terminal_typename: bool,
) -> DocumentNode:
    """Preserve baseline inputs/selections and add only one schema-owned path."""
    validate_safe_artifact(schema, base)
    if side_effect_tokens(base.operation_name):
        raise SafeExecutionValidationError("Representative Query fails Phase 9 name safety rules.")
    document = parse(base.query_text or "")
    selection_depth(document, maximum_depth=6)
    if validate(native, document):
        raise SafeExecutionValidationError(
            "Baseline Query cannot be validated against retained schema."
        )
    root_schema = schema_field(schema, schema.query_root, base.operation_name)
    operation = document.definitions[0]
    assert isinstance(operation, OperationDefinitionNode)
    coerced = get_variable_values(native, operation.variable_definitions or (), base.variables)
    if isinstance(coerced, list):
        raise SafeExecutionValidationError("Baseline variables cannot be safely validated.")
    current = operation.selection_set.selections[0]
    assert isinstance(current, FieldNode)
    root_bound = generate_collection_bound(schema, root_schema)
    root_values = (
        get_argument_values(native.query_type.fields[base.operation_name], current, coerced)
        if native.query_type
        else {}
    )
    bounded_parent = bool(root_bound and root_values.get(root_bound[0].name) == root_bound[1])
    for edge in path:
        # Labels come from the existing TypeEdge schema witness, never response text.
        prefix = edge.source + "."
        if not edge.label.startswith(prefix):
            raise SafeExecutionValidationError("Abstract-type witness edges are not supported.")
        name = edge.label[len(prefix) :]
        field = schema_field(schema, edge.source, name)
        if side_effect_tokens(name):
            raise SafeExecutionValidationError("Recursive field fails Query name safety rules.")
        if field.is_deprecated or any(
            arg.type.outer_non_null and arg.default_value is None for arg in field.arguments
        ):
            raise SafeExecutionValidationError(
                "Recursive path has deprecated fields or required nested business arguments."
            )
        selections = current.selection_set.selections if current.selection_set else ()
        existing = next(
            (
                item
                for item in selections
                if isinstance(item, FieldNode) and item.name.value == name
            ),
            None,
        )
        if existing is None:
            arguments: tuple[ArgumentNode, ...] = ()
            bound = generate_collection_bound(schema, field)
            if bound:
                argument, value, notes = bound
                # Do not introduce business placeholders hidden beside a nested quantity control.
                leaf = value
                while isinstance(leaf, dict) and len(leaf) == 1:
                    leaf = next(iter(leaf.values()))
                if notes or type(leaf) is not int or leaf != 1:
                    raise SafeExecutionValidationError(
                        "Nested collection bound requires unsupported inputs."
                    )
                # JSON object syntax differs from GraphQL: construct input AST through native type.
                native_type = native.get_type(edge.source)
                if not isinstance(native_type, (GraphQLObjectType, GraphQLInterfaceType)):
                    raise SafeExecutionValidationError("Unsupported recursive parent type.")
                value_node = ast_from_value(
                    value, native_type.fields[name].args[argument.name].type
                )
                if value_node is None:
                    raise SafeExecutionValidationError("Nested bound cannot be represented safely.")
                arguments = (ArgumentNode(name=NameNode(value=argument.name), value=value_node),)
            elif field.type.is_list and not bounded_parent:
                raise SafeExecutionValidationError(
                    "New list-valued recursive edge has no safely reusable quantity bound."
                )
            existing = FieldNode(name=NameNode(value=name), arguments=arguments, directives=())
            current.selection_set = SelectionSetNode(selections=(*selections, existing))
            bounded_parent = bound is not None
        else:
            bound = generate_collection_bound(schema, field)
            native_type = native.get_type(edge.source)
            values = (
                get_argument_values(native_type.fields[name], existing, coerced)
                if isinstance(native_type, (GraphQLObjectType, GraphQLInterfaceType))
                else {}
            )
            bounded_parent = bool(bound and values.get(bound[0].name) == bound[1])
        current = existing
    if terminal_typename and current.selection_set is None:
        current.selection_set = SelectionSetNode(
            selections=(FieldNode(name=NameNode(value="__typename"), arguments=(), directives=()),)
        )
    return document
