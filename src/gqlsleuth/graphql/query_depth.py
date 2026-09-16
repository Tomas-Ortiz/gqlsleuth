"""One schema-witness-guided AST extension, without threshold searches or runtime learning."""

import json
import re

from graphql import (
    GraphQLSchema,
    parse,
    print_ast,
    validate,
)
from graphql.language.ast import (
    DocumentNode,
)

from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.query_depth import (
    MAX_CONSTRUCTED_SELECTION_DEPTH,
    MAX_LIST_EDGES,
    QueryDepthObservation,
)
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import ParsedSchema
from gqlsleuth.graphql.safe_execution import (
    classify_execution_response,
    side_effect_tokens,
    validate_safe_artifact,
)
from gqlsleuth.graphql.selection_paths import (
    composite_list_edges,
    extend_selection_path,
    schema_field,
)
from gqlsleuth.graphql.selection_paths import (
    selection_depth as bounded_selection_depth,
)
from gqlsleuth.rules.operation_analysis import normalize_terms
from gqlsleuth.rules.schema_graph import TypeEdge, TypeGraph, reachable_paths


def selection_depth(document: DocumentNode) -> int:
    """Phase 18's field-node metric with its fixed six-level bound."""
    return bounded_selection_depth(document, maximum_depth=MAX_CONSTRUCTED_SELECTION_DEPTH)


def build_depth_query(
    schema: ParsedSchema,
    native: GraphQLSchema,
    base: QueryGenerationResult,
    graph: TypeGraph,
    cycle: tuple[TypeEdge, ...],
) -> tuple[str, int, int, tuple[str, ...], int]:
    """Rotate one retained cycle to its closest reachable entry; traverse it exactly once."""
    validate_safe_artifact(schema, base)
    if side_effect_tokens(base.operation_name):
        raise SafeExecutionValidationError("Representative Query fails Phase 9 name safety rules.")
    document = parse(base.query_text or "")
    baseline = selection_depth(document)
    if validate(native, document):
        raise SafeExecutionValidationError(
            "Baseline Query cannot be validated against retained schema."
        )
    root_schema = schema_field(schema, schema.query_root, base.operation_name)
    paths = reachable_paths(graph, (root_schema.type.named_type,))
    entries = [
        (len(paths[edge.source]), index) for index, edge in enumerate(cycle) if edge.source in paths
    ]
    if not entries:
        raise SafeExecutionValidationError(
            "Representative Query cannot reach the retained recursive witness."
        )
    _, index = min(entries)
    path = paths[cycle[index].source] + cycle[index:] + cycle[:index]
    if len(path) + 2 > MAX_CONSTRUCTED_SELECTION_DEPTH:
        raise SafeExecutionValidationError("Recursive path cannot fit within constructed depth 6.")
    document = extend_selection_path(schema, native, base, path, terminal_typename=True)
    depth = selection_depth(document)
    lists = composite_list_edges(schema, document)
    if depth <= baseline or lists > MAX_LIST_EDGES:
        raise SafeExecutionValidationError(
            "Path is not deeper or exceeds one composite list expansion (including the root)."
        )
    if validate(native, document):
        raise SafeExecutionValidationError("Constructed depth Query failed schema validation.")
    query = print_ast(document)
    selection_depth(parse(query))
    return query, baseline, depth, tuple(edge.label for edge in path), lists


_DEPTH_REJECTION = re.compile(
    r"\bquery (?:is )?too deep\b|"
    r"\b(?:max(?:imum)? (?:query )?depth|query complexity|query cost)"
    r"(?: (?:of|is) \d+)? (?:exceeded|exceeds|limit exceeded)\b|"
    r"\bexceeds (?:the )?(?:max(?:imum)? (?:query )?depth|query complexity|query cost)\b"
)


def classify_depth_response(
    status: int, body: bytes, operation_name: str
) -> tuple[QueryDepthObservation, str]:
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, ValueError, RecursionError):
        document = None
    if not isinstance(document, dict):
        return (
            QueryDepthObservation.INDETERMINATE,
            "Response does not establish processing of this Query shape.",
        )
    classification = classify_execution_response(status, body)
    data = document.get("data")
    if (
        200 <= status < 300
        and classification.status is QueryExecutionStatus.SUCCESS
        and isinstance(data, dict)
        and operation_name in data
    ):
        return (
            QueryDepthObservation.ACCEPTED,
            "The bounded deeper Query was processed successfully; "
            "this applies only to the tested shape and depth.",
        )
    errors = document.get("errors")
    if (
        not data
        and isinstance(errors, list)
        and any(
            isinstance(error, dict)
            and isinstance(error.get("message"), str)
            and _DEPTH_REJECTION.search(" ".join(normalize_terms(error["message"])))
            for error in errors
        )
    ):
        return (
            QueryDepthObservation.REJECTED,
            "The response explicitly rejected this Query under "
            "a depth/complexity/cost validation rule.",
        )
    return (
        QueryDepthObservation.INDETERMINATE,
        "Response does not establish acceptance or an explicit depth-related rejection.",
    )
