"""Local structural and AST checks for one exact Mutation/object request."""

from copy import deepcopy
from dataclasses import replace

from graphql import GraphQLSchema, parse, print_ast
from graphql.language.ast import FieldNode, OperationDefinitionNode
from pydantic import JsonValue

from gqlsleuth.domain.active import MutationGenerationResult
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.mutation_authorization import MutationAuthorizationCase
from gqlsleuth.domain.schema import ParsedSchema, SchemaTypeKind
from gqlsleuth.graphql.active_execution import assess_mutation
from gqlsleuth.graphql.object_authorization import (
    substitute_object_identifier,
    validate_object_document,
)
from gqlsleuth.graphql.selection_paths import schema_field


def build_mutation_probe(
    schema: ParsedSchema,
    native: GraphQLSchema,
    base: MutationGenerationResult,
    case: MutationAuthorizationCase,
) -> tuple[str, dict[str, JsonValue]]:
    """Preserve generated inputs and selections; substitute only the chosen direct ID."""
    if not assess_mutation(schema, base).selectable or base.operation_name != case.operation:
        raise SafeExecutionValidationError("Mutation artifact is invalid or blocked for safety.")
    if schema.mutation_root is None:
        raise SafeExecutionValidationError("Mutation root is unavailable.")
    root_schema = schema_field(schema, schema.mutation_root, case.operation)
    argument = next((item for item in root_schema.arguments if item.name == case.argument), None)
    output = schema.type_named(root_schema.type.named_type)
    if (
        argument is None
        or argument.type.render() not in {"ID", "ID!"}
        or root_schema.type.is_list
        or output is None
        or output.kind is not SchemaTypeKind.OBJECT
    ):
        raise SafeExecutionValidationError(
            "Requires a direct ID argument and concrete object return."
        )
    identity = schema_field(schema, output.name, "id")
    if identity.type.render() not in {"ID", "ID!"} or identity.arguments:
        raise SafeExecutionValidationError("Requires a direct output id: ID or ID!.")
    validate_object_document(
        native, base.query_text or "", base.variables, kind=OperationKind.MUTATION
    )
    document = deepcopy(parse(base.query_text or ""))
    operation = document.definitions[0]
    assert isinstance(operation, OperationDefinitionNode)
    if operation.directives:
        raise SafeExecutionValidationError("Conditional Mutation operations are unsupported.")
    root = operation.selection_set.selections[0]
    assert isinstance(root, FieldNode)
    variables = substitute_object_identifier(
        operation, root, root_schema, base.variables, case.argument, case.identifier
    )
    query = print_ast(document)
    if not assess_mutation(schema, replace(base, query_text=query, variables=variables)).selectable:
        raise SafeExecutionValidationError("Prepared Mutation is not eligible.")
    validate_object_document(native, query, variables, kind=OperationKind.MUTATION)
    return query, variables
