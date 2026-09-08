"""Defensive validation and response classification for safe Query execution."""

import json
from dataclasses import dataclass

from graphql import GraphQLError, parse
from graphql.language.ast import FieldNode, OperationDefinitionNode, OperationType

from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import ParsedSchema, SchemaTypeKind
from gqlsleuth.rules.operation_analysis import normalize_terms

SIDE_EFFECT_ACTION_TOKENS = (
    "create",
    "update",
    "delete",
    "remove",
    "burn",
    "write",
    "set",
    "change",
    "reset",
    "revoke",
    "invalidate",
    "logout",
    "upload",
    "import",
    "send",
    "trigger",
    "execute",
    "consume",
)


@dataclass(frozen=True)
class ResponseClassification:
    """Status and concise reason derived from one HTTP response."""

    status: QueryExecutionStatus
    reason: str


def validate_safe_artifact(schema: ParsedSchema, artifact: QueryGenerationResult) -> None:
    """Reject generated artifacts that are not exactly the expected Query operation."""
    if artifact.operation_kind is not OperationKind.QUERY:
        raise SafeExecutionValidationError("Artifact metadata is not a Query operation.")
    if not artifact.success or artifact.query_text is None:
        raise SafeExecutionValidationError("Artifact does not contain a generated query.")

    root = schema.type_named(schema.query_root)
    if root is None or root.kind is not SchemaTypeKind.OBJECT:
        raise SafeExecutionValidationError(f"Query root '{schema.query_root}' is unavailable.")
    if not any(field.name == artifact.operation_name for field in root.fields):
        raise SafeExecutionValidationError(
            f"Operation '{artifact.operation_name}' is not present on "
            f"Query root '{schema.query_root}'."
        )

    try:
        document = parse(artifact.query_text)
    except GraphQLError as error:
        raise SafeExecutionValidationError(
            f"Generated document is invalid GraphQL: {error}"
        ) from error

    operations = tuple(
        definition
        for definition in document.definitions
        if isinstance(definition, OperationDefinitionNode)
    )
    if any(operation.operation is not OperationType.QUERY for operation in operations):
        raise SafeExecutionValidationError(
            "Generated document contains a Mutation or Subscription."
        )
    if len(operations) != 1:
        raise SafeExecutionValidationError(
            "Generated document must contain exactly one Query operation."
        )
    selections = operations[0].selection_set.selections
    if len(selections) != 1 or not isinstance(selections[0], FieldNode):
        raise SafeExecutionValidationError(
            "Generated Query must select exactly one top-level field."
        )
    if selections[0].name.value != artifact.operation_name:
        raise SafeExecutionValidationError(
            "Generated Query top-level field does not match the expected Query-root field."
        )


def side_effect_tokens(operation_name: str) -> tuple[str, ...]:
    """Return explicit action tokens found only in the primary Query field name."""
    terms = frozenset(normalize_terms(operation_name))
    return tuple(token for token in SIDE_EFFECT_ACTION_TOKENS if token in terms)


def classify_execution_response(status_code: int, body: bytes) -> ResponseClassification:
    """Classify an execution response without treating application errors as crashes."""
    document = _json_object(body)
    messages = _graphql_error_messages(document)
    if messages:
        return ResponseClassification(
            QueryExecutionStatus.GRAPHQL_ERROR,
            f'GraphQL errors: "{messages[0]}"',
        )
    if status_code >= 400:
        return ResponseClassification(
            QueryExecutionStatus.HTTP_ERROR,
            f"HTTP {status_code} without an interpretable GraphQL errors structure.",
        )
    if document is not None and "data" in document:
        return ResponseClassification(
            QueryExecutionStatus.SUCCESS,
            "GraphQL response contains data and no non-empty errors array.",
        )
    return ResponseClassification(
        QueryExecutionStatus.INVALID_RESPONSE,
        "Successful HTTP response is not interpretable GraphQL JSON.",
    )


def _json_object(body: bytes) -> dict[str, object] | None:
    try:
        value: object = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _graphql_error_messages(document: dict[str, object] | None) -> tuple[str, ...]:
    if document is None:
        return ()
    errors = document.get("errors")
    if not isinstance(errors, list) or not errors:
        return ()
    messages = []
    for error in errors:
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            messages.append(str(error["message"]))
    return tuple(messages)
