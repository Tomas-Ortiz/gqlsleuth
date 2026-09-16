"""Local AST substitution and exact identity classification; no identifier discovery."""

import json
from copy import deepcopy
from dataclasses import replace

from graphql import GraphQLSchema, get_named_type, parse, parse_type, print_ast, validate
from graphql.execution.values import get_argument_values, get_variable_values
from graphql.language.ast import (
    ArgumentNode,
    DocumentNode,
    FieldNode,
    NameNode,
    OperationDefinitionNode,
    SelectionSetNode,
    VariableDefinitionNode,
    VariableNode,
)
from graphql.language.visitor import Visitor, visit
from pydantic import JsonValue

from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.object_authorization import ObjectAuthorizationCase, ObjectOutcome
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import ParsedSchema, SchemaField, SchemaTypeKind
from gqlsleuth.graphql.authorization_response import explicit_authorization_error
from gqlsleuth.graphql.safe_execution import side_effect_tokens, validate_safe_artifact
from gqlsleuth.graphql.selection_paths import schema_field
from gqlsleuth.rules.operation_analysis import normalize_terms


def object_fields(
    schema: ParsedSchema, case: ObjectAuthorizationCase
) -> tuple[SchemaField, SchemaField]:
    root = schema_field(schema, schema.query_root, case.operation)
    argument = next((item for item in root.arguments if item.name == case.argument), None)
    output = schema.type_named(root.type.named_type)
    if (
        argument is None
        or argument.type.render() not in {"ID", "ID!"}
        or not normalize_terms(argument.name)
        or normalize_terms(argument.name)[-1] not in {"id", "ids"}
        or root.type.is_list
        or output is None
        or output.kind is not SchemaTypeKind.OBJECT
        or side_effect_tokens(root.name)
    ):
        raise SafeExecutionValidationError(
            "Requires a safe concrete object lookup with a direct ID argument."
        )
    identity = schema_field(schema, output.name, "id")
    if identity.type.render() not in {"ID", "ID!"} or identity.arguments:
        raise SafeExecutionValidationError("Requires an unambiguous direct output id: ID or ID!.")
    return root, identity


def _plain_query(document: DocumentNode) -> tuple[OperationDefinitionNode, FieldNode]:
    if len(document.definitions) != 1 or not isinstance(
        document.definitions[0], OperationDefinitionNode
    ):
        raise SafeExecutionValidationError("Requires exactly one Query definition.")
    operation = document.definitions[0]
    if (
        operation.operation.value != "query"
        or operation.name
        or len(operation.selection_set.selections) != 1
    ):
        raise SafeExecutionValidationError("Requires one anonymous Query root.")
    pending = list(operation.selection_set.selections)
    while pending:
        field = pending.pop()
        if not isinstance(field, FieldNode) or field.alias or side_effect_tokens(field.name.value):
            raise SafeExecutionValidationError(
                "Aliases, fragments and unsafe fields are unsupported."
            )
        if field.selection_set:
            pending.extend(field.selection_set.selections)
    root = operation.selection_set.selections[0]
    assert isinstance(root, FieldNode)
    return operation, root


class _VariableUses(Visitor):
    def __init__(self) -> None:
        super().__init__()
        self.names: list[str] = []

    def enter_variable(self, node: VariableNode, *_: object) -> None:
        self.names.append(node.name.value)


def validate_object_document(
    native: GraphQLSchema, query: str, variables: dict[str, JsonValue]
) -> tuple[object, ...]:
    """Validate all retained selections and compare effective schema-coerced inputs locally."""
    document = parse(query)
    operation, root = _plain_query(document)
    if validate(native, document):
        raise SafeExecutionValidationError("Query does not validate against retained schema.")
    coerced = get_variable_values(native, operation.variable_definitions or (), variables)
    if isinstance(coerced, list):
        raise SafeExecutionValidationError(
            "Query variables do not validate against retained schema."
        )
    pending = [(native.query_type, root)]
    values: list[object] = []
    while pending:
        parent, field = pending.pop()
        if field.name.value == "__typename":
            continue
        fields = getattr(parent, "fields", {})
        definition = fields.get(field.name.value)
        if definition is None:
            raise SafeExecutionValidationError("Selected output structure is unavailable.")
        values.append(
            (
                field.name.value,
                str(definition.type),
                get_argument_values(definition, field, coerced),
            )
        )
        if field.selection_set:
            pending.extend(
                (get_named_type(definition.type), child)
                for child in field.selection_set.selections
                if isinstance(child, FieldNode)
            )
    return tuple(values)


def build_object_query(
    schema: ParsedSchema,
    native: GraphQLSchema,
    base: QueryGenerationResult,
    case: ObjectAuthorizationCase,
) -> tuple[str, dict[str, JsonValue]]:
    """Change exactly the selected root ID input, adding only a direct identity selection."""
    root_schema, _ = object_fields(schema, case)
    validate_safe_artifact(schema, base)
    if base.operation_name != case.operation:
        raise SafeExecutionValidationError("Baseline operation does not match the supplied case.")
    document = deepcopy(parse(base.query_text or ""))
    operation, root = _plain_query(document)
    validate_object_document(native, base.query_text or "", base.variables)
    variables = deepcopy(base.variables)
    selected = next((arg for arg in root.arguments if arg.name.value == case.argument), None)
    if selected is not None and isinstance(selected.value, VariableNode):
        name = selected.value.name.value
        uses = _VariableUses()
        visit(operation.selection_set, uses)
        for directive in operation.directives:
            visit(directive, uses)
        if uses.names.count(name) != 1:
            raise SafeExecutionValidationError(
                "Selected ID variable also controls unrelated input."
            )
        variables[name] = case.identifier
    else:
        used = set(variables) | {
            item.variable.name.value for item in operation.variable_definitions or ()
        }
        name = case.argument
        suffix = 1
        while name in used:
            name = f"{case.argument}_{suffix}"
            suffix += 1
        argument_type = next(
            arg.type.render() for arg in root_schema.arguments if arg.name == case.argument
        )
        variable = VariableNode(name=NameNode(value=name))
        definition = VariableDefinitionNode(variable=variable, type=parse_type(argument_type))
        operation.variable_definitions = (*operation.variable_definitions, definition)
        new_argument = ArgumentNode(name=NameNode(value=case.argument), value=variable)
        root.arguments = (
            tuple(new_argument if arg is selected else arg for arg in root.arguments)
            if selected
            else (*root.arguments, new_argument)
        )
        variables[name] = case.identifier
    fields = root.selection_set.selections if root.selection_set else ()
    identity = next(
        (item for item in fields if isinstance(item, FieldNode) and item.name.value == "id"), None
    )
    if identity and identity.directives:
        raise SafeExecutionValidationError("Conditional identity selection is unsupported.")
    if identity is None:
        root.selection_set = SelectionSetNode(
            selections=(*fields, FieldNode(name=NameNode(value="id")))
        )
    query = print_ast(document)
    validate_safe_artifact(schema, replace(base, query_text=query, variables=variables))
    validate_object_document(native, query, variables)
    return query, variables


def classify_object_response(
    status: int, body: bytes, operation: str, identifier: str
) -> tuple[ObjectOutcome, bool | None, str]:
    """Only direct identity equality and authorization/transport shape influence outcomes."""
    try:
        document = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        document = None
    data = document.get("data") if isinstance(document, dict) else None
    root = data.get(operation) if isinstance(data, dict) else None
    value = root.get("id") if isinstance(root, dict) else None
    matches = str(value) == identifier if isinstance(value, str) or type(value) is int else None
    if status in {401, 403}:
        return (
            ObjectOutcome.EXPLICIT_DENIAL,
            matches,
            "HTTP authorization denial of this exact request.",
        )
    errors = document.get("errors") if isinstance(document, dict) else None
    if errors:
        if (
            isinstance(errors, list)
            and all(explicit_authorization_error(item, (operation, "id")) for item in errors)
            and not matches
        ):
            return (
                ObjectOutcome.EXPLICIT_DENIAL,
                matches,
                "Explicit GraphQL authorization denial applicable to the requested object.",
            )
        return (
            ObjectOutcome.INDETERMINATE,
            matches,
            "Errors or partial data prevent an isolated object-access observation.",
        )
    if 200 <= status < 300 and matches is True:
        return (
            ObjectOutcome.TARGET_RETURNED,
            True,
            "The direct returned id exactly matches the operator-supplied identifier.",
        )
    return (
        ObjectOutcome.INDETERMINATE,
        matches,
        "The requested object identity was not conclusively returned.",
    )
