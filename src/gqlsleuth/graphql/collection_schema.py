"""Shared, bounded schema inspection for collection generation and structural review."""

from collections import deque
from collections.abc import Iterator

from gqlsleuth.domain.schema import SchemaField, SchemaNamedType, SchemaTypeKind
from gqlsleuth.rules.operation_analysis import normalize_terms
from gqlsleuth.rules.schema_graph import COMPOSITE_KINDS, MAX_GRAPH_RELATIONSHIPS, MAX_GRAPH_TYPES

BOUND_ARGUMENTS = frozenset(
    {
        ("first",),
        ("last",),
        ("limit",),
        ("take",),
        ("size",),
        ("page", "size"),
        ("per", "page"),
        ("max", "results"),
    }
)
COLLECTION_FIELDS = frozenset({"data", "items", "nodes", "edges", "results", "records", "entries"})
COLLECTION_TYPE_SUFFIXES = (
    ("page",),
    ("connection",),
    ("collection",),
    ("results",),
    ("result", "set"),
)
MAX_BOUNDING_INPUT_DEPTH = 3


def collection_paths(
    field: SchemaField, types: dict[str, SchemaNamedType]
) -> tuple[tuple[str, str], ...]:
    """Return (schema path, element type) for direct lists or one high-signal wrapper."""
    output = types.get(field.type.named_type)
    if output is None or output.kind not in COMPOSITE_KINDS:
        return ()
    if field.type.is_list:
        return ((field.name, output.name),)
    terms = normalize_terms(output.name)
    hinted_type = any(terms[-len(suffix) :] == suffix for suffix in COLLECTION_TYPE_SUFFIXES)
    collections = []
    for child in sorted(output.fields, key=lambda child: child.name):
        element = types.get(child.type.named_type)
        if not child.type.is_list or element is None or element.kind not in COMPOSITE_KINDS:
            continue
        child_terms = normalize_terms(child.name)
        if hinted_type or (len(child_terms) == 1 and child_terms[0] in COLLECTION_FIELDS):
            collections.append((f"{output.name}.{child.name}", element.name))
    return tuple(collections)


def iter_bounding_inputs(field: SchemaField, types: dict[str, SchemaNamedType]) -> Iterator[str]:
    """Yield deterministic schema quantity-control paths, including optional inputs.

    Root argument -> input object counts as level one. Breadth-first traversal visits
    each type once at its shortest depth, capped at three levels and existing graph budgets.
    Names indicate schema controls only; no runtime enforcement is inferred.
    """
    arguments = sorted(field.arguments, key=lambda argument: argument.name)
    for argument in arguments:
        if normalize_terms(argument.name) in BOUND_ARGUMENTS:
            yield argument.name
    queue: deque[tuple[SchemaNamedType, str, int]] = deque()
    seen: set[str] = set()

    def enqueue(name: str, path: str, depth: int) -> None:
        named = types.get(name)
        if (
            named
            and named.kind is SchemaTypeKind.INPUT_OBJECT
            and name not in seen
            and len(seen) < MAX_GRAPH_TYPES
        ):
            seen.add(name)
            queue.append((named, path, depth))

    for argument in arguments:
        enqueue(argument.type.named_type, argument.name, 1)
    inspected = 0
    while queue:
        named, path, depth = queue.popleft()
        for item in sorted(named.input_fields, key=lambda item: item.name):
            if inspected >= MAX_GRAPH_RELATIONSHIPS:
                return
            inspected += 1
            child_path = f"{path}.{item.name}"
            if normalize_terms(item.name) in BOUND_ARGUMENTS:
                yield child_path
            if depth < MAX_BOUNDING_INPUT_DEPTH:
                enqueue(item.type.named_type, child_path, depth + 1)
    return


def find_bounding_input(field: SchemaField, types: dict[str, SchemaNamedType]) -> str | None:
    """Names are schema signals only, independent of generation or runtime enforcement."""
    return next(iter_bounding_inputs(field, types), None)
