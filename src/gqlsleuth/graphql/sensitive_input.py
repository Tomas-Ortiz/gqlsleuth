"""One-level schema eligibility, exact typed values, AST substitution and response confirmation."""

import json
import re
from copy import deepcopy
from dataclasses import dataclass, replace

from graphql import GraphQLSchema, parse, print_ast
from graphql.execution.values import get_argument_values, get_variable_values
from graphql.language.ast import FieldNode, OperationDefinitionNode, VariableNode
from pydantic import JsonValue

from gqlsleuth.domain.active import MutationGenerationResult
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.schema import ParsedSchema, SchemaField, SchemaInputField, SchemaTypeKind
from gqlsleuth.domain.sensitive_input import SensitiveInputCase, SensitiveInputOutcome
from gqlsleuth.graphql.active_execution import assess_mutation, destructive_tokens
from gqlsleuth.graphql.authorization_response import explicit_authorization_error
from gqlsleuth.graphql.object_authorization import (
    ensure_direct_selection,
    exact_id_matches,
    substitute_object_identifier,
    substitute_root_argument,
    validate_object_document,
)
from gqlsleuth.graphql.selection_paths import schema_field
from gqlsleuth.rules.sensitive_input import sensitive_category


@dataclass(frozen=True)
class SensitiveInputShape:
    root: SchemaField
    leaf: SchemaInputField
    target_argument: str | None


def sensitive_shape(
    schema: ParsedSchema, operation: str, argument: str, field: str
) -> SensitiveInputShape:
    """The same structural gate serves schema hints and ACTIVE request preparation."""
    if (
        schema.mutation_root is None
        or destructive_tokens(operation)
        or sensitive_category(field) is None
    ):
        raise SafeExecutionValidationError(
            "Requires a detected field on a non-destructive Mutation."
        )
    root = schema_field(schema, schema.mutation_root, operation)
    arg = next((item for item in root.arguments if item.name == argument), None)
    input_type = schema.type_named(arg.type.named_type) if arg else None
    if (
        arg is None
        or arg.type.is_list
        or input_type is None
        or input_type.kind is not SchemaTypeKind.INPUT_OBJECT
    ):
        raise SafeExecutionValidationError("Requires one direct input-object argument.")
    leaf = next((item for item in input_type.input_fields if item.name == field), None)
    named = schema.type_named(leaf.type.named_type) if leaf else None
    if (
        leaf is None
        or leaf.type.is_list
        or named is None
        or not (
            leaf.type.named_type in {"Boolean", "Int", "String", "ID"}
            or named.kind is SchemaTypeKind.ENUM
        )
    ):
        raise SafeExecutionValidationError("Unsupported sensitive input leaf type.")
    output = schema.type_named(root.type.named_type)
    if root.type.is_list or output is None or output.kind is not SchemaTypeKind.OBJECT:
        raise SafeExecutionValidationError("Requires a concrete non-list output object.")
    confirm = schema_field(schema, output.name, field)
    if confirm.arguments or confirm.type.is_list or confirm.type.named_type != leaf.type.named_type:
        raise SafeExecutionValidationError(
            "Requires a compatible direct output confirmation field."
        )
    targets = tuple(item for item in root.arguments if item.type.named_type == "ID")
    if len(targets) > 1 or any(item.type.is_list for item in targets):
        raise SafeExecutionValidationError("Target ID arguments are ambiguous or unsupported.")
    if targets:
        identity = schema_field(schema, output.name, "id")
        if identity.type.render() not in {"ID", "ID!"} or identity.arguments:
            raise SafeExecutionValidationError(
                "Requires a direct output id for target confirmation."
            )
    return SensitiveInputShape(root, leaf, targets[0].name if targets else None)


def typed_sensitive_value(schema: ParsedSchema, leaf: SchemaInputField, text: str) -> JsonValue:
    name = leaf.type.named_type
    if name == "Boolean":
        if text not in {"true", "false"}:
            raise SafeExecutionValidationError("Boolean value must be exactly true or false.")
        return text == "true"
    if name == "Int":
        if (
            re.fullmatch(r"(?:0|-?[1-9][0-9]*)", text) is None
            or len(text) > 11
            or not -(2**31) <= int(text) < 2**31
        ):
            raise SafeExecutionValidationError(
                "Int value must be canonical signed 32-bit decimal text."
            )
        return int(text)
    if name in {"String", "ID"}:
        return text
    named = schema.type_named(name)
    if (
        named
        and named.kind is SchemaTypeKind.ENUM
        and text in {item.name for item in named.enum_values}
    ):
        return text
    raise SafeExecutionValidationError("Value must exactly match a supported enum member.")


def build_sensitive_probe(
    schema: ParsedSchema,
    native: GraphQLSchema,
    base: MutationGenerationResult,
    case: SensitiveInputCase,
) -> tuple[str, dict[str, JsonValue], JsonValue, str]:
    shape = sensitive_shape(schema, case.operation, case.argument, case.field)
    if (case.target.argument if case.target else None) != shape.target_argument:
        raise SafeExecutionValidationError(
            "Supply exactly the required direct target ID with --sensitive-input-target; "
            "no target is accepted for a current-object Mutation."
        )
    if not assess_mutation(schema, base).selectable or base.operation_name != case.operation:
        raise SafeExecutionValidationError("Mutation artifact is invalid or blocked.")
    value = typed_sensitive_value(schema, shape.leaf, case.value)
    validate_object_document(
        native, base.query_text or "", base.variables, kind=OperationKind.MUTATION
    )
    document = deepcopy(parse(base.query_text or ""))
    operation = document.definitions[0]
    assert isinstance(operation, OperationDefinitionNode)
    root = operation.selection_set.selections[0]
    assert isinstance(root, FieldNode)
    if operation.directives:
        raise SafeExecutionValidationError("Conditional operations are unsupported.")
    # Effective values preserve inline arguments and schema defaults as well as variable names.
    coerced = get_variable_values(native, operation.variable_definitions or (), base.variables)
    assert isinstance(coerced, dict) and native.mutation_type is not None
    inputs = get_argument_values(native.mutation_type.fields[case.operation], root, coerced)
    current = inputs.get(case.argument, {})
    if not isinstance(current, dict):
        raise SafeExecutionValidationError("Input object must be present or safely constructible.")
    selected = next((arg for arg in root.arguments if arg.name.value == case.argument), None)
    # Keep exact generated variable values; do not materialize omitted optional/default siblings.
    if selected and isinstance(selected.value, VariableNode):
        current = base.variables.get(selected.value.name.value, current)
        if not isinstance(current, dict):
            raise SafeExecutionValidationError("Input variable must contain an object.")
    updated = deepcopy(current)
    updated[case.field] = value
    variables = substitute_root_argument(
        operation, root, shape.root, base.variables, case.argument, updated
    )
    if case.target:
        variables = substitute_object_identifier(
            operation, root, shape.root, variables, case.target.argument, case.target.identifier
        )
    ensure_direct_selection(root, case.field)
    query = print_ast(document)
    validate_object_document(native, query, variables, kind=OperationKind.MUTATION)
    if not assess_mutation(schema, replace(base, query_text=query, variables=variables)).selectable:
        raise SafeExecutionValidationError("Prepared Mutation is invalid or blocked.")
    return query, variables, value, shape.leaf.type.named_type


def classify_sensitive_response(
    status: int,
    body: bytes,
    case: SensitiveInputCase,
    value: JsonValue,
    value_type: str,
) -> tuple[SensitiveInputOutcome, bool | None, bool | None]:
    try:
        document = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        document = None
    data = document.get("data") if isinstance(document, dict) else None
    root = data.get(case.operation) if isinstance(data, dict) else None
    identity = (
        exact_id_matches(root.get("id"), case.target.identifier)
        if isinstance(root, dict) and case.target
        else None
    )
    returned = root.get(case.field) if isinstance(root, dict) else None
    matches = None
    if isinstance(root, dict) and case.field in root:
        matches = (
            exact_id_matches(returned, str(value))
            if value_type == "ID"
            else type(returned) is type(value) and returned == value
        )
    if status in {401, 403}:
        return SensitiveInputOutcome.EXPLICIT_DENIAL, identity, matches
    errors = document.get("errors") if isinstance(document, dict) else None
    confirmed = matches is True and (case.target is None or identity is True)
    if errors:
        if (
            isinstance(errors, list)
            and all(
                explicit_authorization_error(item, (case.operation, case.field)) for item in errors
            )
            and not confirmed
        ):
            return SensitiveInputOutcome.EXPLICIT_DENIAL, identity, matches
        return SensitiveInputOutcome.INDETERMINATE, identity, matches
    return (
        SensitiveInputOutcome.TARGET_VALUE_RETURNED
        if 200 <= status < 300 and confirmed
        else SensitiveInputOutcome.INDETERMINATE,
        identity,
        matches,
    )
