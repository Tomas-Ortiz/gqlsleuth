"""Upload schema/AST mapping and conservative response classification, without networking."""

import json
from copy import deepcopy
from dataclasses import replace

from graphql import GraphQLSchema, parse, print_ast
from graphql.language.ast import FieldNode, OperationDefinitionNode, VariableNode
from pydantic import JsonValue

from gqlsleuth.domain.active import MutationGenerationResult
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.file_upload import FileUploadCase, UploadOutcome
from gqlsleuth.domain.schema import ParsedSchema, SchemaTypeKind, TypeReference
from gqlsleuth.graphql.active_execution import assess_mutation
from gqlsleuth.graphql.object_authorization import (
    substitute_root_argument,
    validate_object_document,
)
from gqlsleuth.graphql.query_generation import generate_input_path
from gqlsleuth.graphql.selection_paths import schema_field
from gqlsleuth.rules.operation_analysis import normalize_terms


def build_upload_document(
    schema: ParsedSchema,
    native: GraphQLSchema,
    base: MutationGenerationResult,
    case: FileUploadCase,
) -> tuple[str, dict[str, JsonValue], str]:
    if not assess_mutation(schema, base).selectable or base.operation_name != case.operation:
        raise SafeExecutionValidationError("Upload Mutation is invalid or blocked for safety.")
    if schema.mutation_root is None:
        raise SafeExecutionValidationError("Mutation root is unavailable.")
    root_schema = schema_field(schema, schema.mutation_root, case.operation)
    argument = next((a for a in root_schema.arguments if a.name == case.path[0]), None)
    if argument is None:
        raise SafeExecutionValidationError("Upload argument is unavailable.")
    reference = argument.type
    for component in case.path[1:]:
        named = schema.type_named(reference.named_type)
        if reference.is_list or named is None or named.kind is not SchemaTypeKind.INPUT_OBJECT:
            raise SafeExecutionValidationError("Upload path must traverse non-list input objects.")
        child = next((f for f in named.input_fields if f.name == component), None)
        if child is None:
            raise SafeExecutionValidationError("Selected Upload path is unavailable.")
        reference = child.type
    scalar = schema.type_named(reference.named_type)
    if (
        reference.is_list
        or reference.named_type != "Upload"
        or scalar is None
        or scalar.kind is not SchemaTypeKind.SCALAR
    ):
        raise SafeExecutionValidationError("Requires exactly Upload or Upload!, without a list.")
    validate_object_document(
        native, base.query_text or "", base.variables, kind=OperationKind.MUTATION
    )
    document = parse(base.query_text or "")
    operation = document.definitions[0]
    assert isinstance(operation, OperationDefinitionNode)
    root = operation.selection_set.selections[0]
    assert isinstance(root, FieldNode)
    if operation.directives:
        raise SafeExecutionValidationError("Conditional upload operations are unsupported.")
    selected = next((a for a in root.arguments if a.name.value == argument.name), None)
    if selected and not isinstance(selected.value, VariableNode):
        raise SafeExecutionValidationError("Upload requires an unambiguous generated variable.")
    if selected:
        assert isinstance(selected.value, VariableNode)
        value = deepcopy(base.variables.get(selected.value.name.value))
    else:
        value = None
    # Populate only a missing selected path; required siblings use shared generation.
    generated = generate_input_path(schema, argument.type, case.path[1:], input_name=argument.name)
    if selected:

        def merge_path(current: JsonValue, fresh: JsonValue, path: tuple[str, ...]) -> JsonValue:
            if not path:
                return current
            if not isinstance(current, dict) or not isinstance(fresh, dict):
                raise SafeExecutionValidationError("Upload input variable must contain an object.")
            head, *tail = path
            current[head] = (
                merge_path(current[head], fresh[head], tuple(tail))
                if head in current
                else fresh[head]
            )
            return current

        value = merge_path(value, generated, case.path[1:])
    else:
        value = generated
    variables = substitute_root_argument(
        operation, root, root_schema, base.variables, argument.name, value
    )
    query = print_ast(document)
    validate_object_document(native, query, variables, kind=OperationKind.MUTATION)
    if not assess_mutation(schema, replace(base, query_text=query, variables=variables)).selectable:
        raise SafeExecutionValidationError("Prepared upload Mutation is not eligible.")
    paths: list[tuple[str, ...]] = []

    def populated_uploads(ref: TypeReference, value: JsonValue, path: tuple[str, ...]) -> None:
        if ref.named_type == "Upload":
            if value is not None:
                paths.append(path)
            return
        named = schema.type_named(ref.named_type)
        if isinstance(value, list):
            for index, item in enumerate(value):
                populated_uploads(TypeReference.named(ref.named_type), item, (*path, str(index)))
        elif named and named.kind is SchemaTypeKind.INPUT_OBJECT and isinstance(value, dict):
            for child in named.input_fields:
                if child.name in value:
                    populated_uploads(child.type, value[child.name], (*path, child.name))

    selected_variable = None
    for arg in root.arguments:
        if not isinstance(arg.value, VariableNode):
            raise SafeExecutionValidationError("Generated upload arguments must use variables.")
        definition = next(a for a in root_schema.arguments if a.name == arg.name.value)
        name = arg.value.name.value
        populated_uploads(definition.type, variables[name], (name,))
        if arg.name.value == argument.name:
            selected_variable = name
    assert selected_variable is not None
    upload_path = (selected_variable, *case.path[1:])
    if paths != [upload_path]:
        raise SafeExecutionValidationError(
            "Exactly one populated Upload leaf is supported; multiple files are unsupported."
        )
    parent = variables
    for name in upload_path[:-1]:
        child_value = parent[name]
        if not isinstance(child_value, dict):
            raise SafeExecutionValidationError("Upload variable path must contain objects.")
        parent = child_value
    parent[upload_path[-1]] = None
    return query, variables, "variables." + ".".join(upload_path)


_FILE_CODES = {
    normalize_terms(value)
    for value in (
        "INVALID_FILE_TYPE",
        "FILE_TYPE_NOT_ALLOWED",
        "UNSUPPORTED_FILE_TYPE",
        "UNSUPPORTED_MEDIA_TYPE",
        "INVALID_UPLOAD",
        "FILE_EXTENSION_NOT_ALLOWED",
    )
}
_FILE_MESSAGES = {
    normalize_terms(value)
    for value in (
        "unsupported file type",
        "file type not allowed",
        "invalid file type",
        "unsupported media type",
        "file extension not allowed",
        "invalid file extension",
    )
}


def classify_upload_response(status: int, body: bytes, case: FileUploadCase) -> UploadOutcome:
    if status in {413, 415}:
        return UploadOutcome.EXPLICIT_FILE_REJECTION
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return UploadOutcome.INDETERMINATE
    if not isinstance(data, dict):
        return UploadOutcome.INDETERMINATE
    errors = data.get("errors")
    if errors not in (None, []):
        if not isinstance(errors, list) or not errors:
            return UploadOutcome.INDETERMINATE
        for error in errors:
            if not isinstance(error, dict):
                return UploadOutcome.INDETERMINATE
            path = error.get("path")
            # A pathless exact file code on this one-file request is scoped; message-only
            # fallback must explicitly identify the selected root or Upload input path.
            scoped = path in ([case.operation], list(case.path), [case.operation, *case.path])
            extensions = error.get("extensions")
            code = extensions.get("code") if isinstance(extensions, dict) else None
            strong = isinstance(code, str) and normalize_terms(code) in _FILE_CODES
            message = error.get("message")
            fallback = (
                code is None
                and isinstance(message, str)
                and normalize_terms(message) in _FILE_MESSAGES
            )
            if not ((strong and (path is None or scoped)) or (fallback and scoped)):
                return UploadOutcome.INDETERMINATE
        # Partial non-null data plus errors is deliberately unresolved.
        result = data.get("data")
        if isinstance(result, dict) and result.get(case.operation) is not None:
            return UploadOutcome.INDETERMINATE
        return UploadOutcome.EXPLICIT_FILE_REJECTION
    result = data.get("data")
    if 200 <= status < 300 and isinstance(result, dict) and result.get(case.operation) is not None:
        return UploadOutcome.UPLOAD_ACCEPTED
    return UploadOutcome.INDETERMINATE
