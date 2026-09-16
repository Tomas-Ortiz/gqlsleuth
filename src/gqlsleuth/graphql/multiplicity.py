"""Local AST transformation and conservative, probe-specific response interpretation."""

import json
import re
from copy import deepcopy

from graphql import parse, print_ast
from graphql.language.ast import FieldNode, NameNode, OperationDefinitionNode
from pydantic import JsonValue

from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.multiplicity import (
    ALIAS_COUNT,
    BATCH_SIZE,
    MultiplicityObservation,
    MultiplicityProbePreview,
    MultiplicityProbeType,
)
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import ParsedSchema
from gqlsleuth.graphql.safe_execution import (
    classify_execution_response,
    side_effect_tokens,
    validate_safe_artifact,
)

ALIAS_NAMES = tuple(f"gqlsleuthAlias{index}" for index in range(1, ALIAS_COUNT + 1))
_DENIAL = r"\s+(?:(?:are|is)\s+)?(?:not supported|not allowed|disabled|forbidden|rejected)\b"
_ALIAS_REJECTION = re.compile(
    r"\b(?:aliases|alias multiplicity)" + _DENIAL + r"|\btoo many aliases\b", re.IGNORECASE
)
_BATCH_REJECTION = re.compile(
    r"\b(?:batching|batch requests|batch queries|json[- ]array(?: requests)?)" + _DENIAL,
    re.IGNORECASE,
)


def prepare_probe(
    schema: ParsedSchema, base: QueryGenerationResult, probe_type: MultiplicityProbeType
) -> MultiplicityProbePreview:
    """Only aliases differ from the retained base; batching preserves even document whitespace."""
    validate_safe_artifact(schema, base)
    if side_effect_tokens(base.operation_name):
        raise SafeExecutionValidationError("Representative Query fails existing name safety rules.")
    document = parse(base.query_text or "")
    if len(document.definitions) != 1:
        raise SafeExecutionValidationError(
            "Representative Query must not contain extra definitions."
        )
    operation = document.definitions[0]
    if not isinstance(operation, OperationDefinitionNode) or operation.name is not None:
        raise SafeExecutionValidationError("Representative Query must be anonymous.")
    field = operation.selection_set.selections[0]
    if not isinstance(field, FieldNode) or field.alias is not None:
        raise SafeExecutionValidationError("Existing top-level aliases are ambiguous.")
    query = base.query_text or ""
    request: JsonValue
    if probe_type is MultiplicityProbeType.ALIAS_MULTIPLICITY:
        copies = []
        for name in ALIAS_NAMES:
            cloned = deepcopy(field)
            cloned.alias = NameNode(value=name)
            copies.append(cloned)
        operation.selection_set.selections = tuple(copies)
        query = print_ast(document)
        parse(query)
        request = {"query": query, "variables": deepcopy(base.variables)}
    elif probe_type is MultiplicityProbeType.HTTP_BATCHING:
        request = [
            {"query": query, "variables": deepcopy(base.variables)} for _ in range(BATCH_SIZE)
        ]
    else:
        raise SafeExecutionValidationError("Unknown multiplicity probe type.")
    return MultiplicityProbePreview(probe_type, deepcopy(base), query, request)


def classify_probe_response(
    probe_type: MultiplicityProbeType, status: int, body: bytes
) -> tuple[MultiplicityObservation, str, tuple[QueryExecutionStatus, ...]]:
    """No business-value comparison; generic errors do not establish request-shape policy."""
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return MultiplicityObservation.INDETERMINATE, "Response is not interpretable JSON.", ()
    if (
        probe_type is MultiplicityProbeType.HTTP_BATCHING
        and isinstance(document, list)
        and len(document) == BATCH_SIZE
    ):
        statuses = tuple(
            classify_execution_response(status, json.dumps(item).encode()).status
            for item in document
            if isinstance(item, dict)
        )
        if (
            200 <= status < 300
            and len(document) == BATCH_SIZE
            and len(statuses) == BATCH_SIZE
            and all(
                item in {QueryExecutionStatus.SUCCESS, QueryExecutionStatus.GRAPHQL_ERROR}
                for item in statuses
            )
        ):
            return (
                MultiplicityObservation.ACCEPTED,
                "The endpoint processed a JSON-array GraphQL request containing two entries.",
                statuses,
            )
    classification = classify_execution_response(status, body)
    if probe_type is MultiplicityProbeType.ALIAS_MULTIPLICITY and isinstance(document, dict):
        data = document.get("data")
        if (
            200 <= status < 300
            and classification.status is QueryExecutionStatus.SUCCESS
            and isinstance(data, dict)
            and all(name in data for name in ALIAS_NAMES)
        ):
            return (
                MultiplicityObservation.ACCEPTED,
                "Three aliased instances of the same Query field were accepted.",
                (),
            )
    # Only explicit format/policy messages tied to this shape establish rejection.
    errors = document.get("errors") if isinstance(document, dict) else None
    messages = (
        [item.get("message", "") for item in errors if isinstance(item, dict)]
        if isinstance(errors, list)
        else []
    )
    rejection = (
        _ALIAS_REJECTION
        if probe_type is MultiplicityProbeType.ALIAS_MULTIPLICITY
        else _BATCH_REJECTION
    )
    if not (isinstance(document, dict) and document.get("data")) and any(
        isinstance(message, str) and rejection.search(message) is not None for message in messages
    ):
        return (
            MultiplicityObservation.REJECTED,
            "The response explicitly rejected this request shape.",
            (),
        )
    return (
        MultiplicityObservation.INDETERMINATE,
        "The response does not establish acceptance or explicit request-shape rejection.",
        (),
    )
