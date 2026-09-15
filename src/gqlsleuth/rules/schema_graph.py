"""Bounded local type graphs and iterative cycle witnesses for structural review."""

from collections import deque
from dataclasses import dataclass

from gqlsleuth.domain.schema import SchemaField, SchemaInputField, SchemaNamedType, SchemaTypeKind

MAX_GRAPH_TYPES = 512
MAX_GRAPH_RELATIONSHIPS = 4096
COMPOSITE_KINDS = frozenset({SchemaTypeKind.OBJECT, SchemaTypeKind.INTERFACE, SchemaTypeKind.UNION})


@dataclass(frozen=True)
class TypeEdge:
    source: str
    target: str
    label: str
    is_list: bool = False
    required: bool = False


@dataclass(frozen=True)
class TypeGraph:
    edges: dict[str, tuple[TypeEdge, ...]]
    truncated: bool


def build_type_graph(types: tuple[SchemaNamedType, ...], *, inputs: bool) -> TypeGraph:
    """Bound both vertices and inspected relationships, including scalar fields."""
    kinds = {SchemaTypeKind.INPUT_OBJECT, SchemaTypeKind.SCALAR} if inputs else COMPOSITE_KINDS
    eligible = sorted((item for item in types if item.kind in kinds), key=lambda item: item.name)
    kept = eligible[:MAX_GRAPH_TYPES]
    names = {item.name for item in kept}
    edges: dict[str, tuple[TypeEdge, ...]] = {}
    count = 0
    truncated = len(eligible) > len(kept)
    for item in kept:
        outgoing = []
        fields: tuple[SchemaField | SchemaInputField, ...] = (
            item.input_fields if inputs else item.fields
        )
        for field in sorted(fields, key=lambda field: field.name):
            if count >= MAX_GRAPH_RELATIONSHIPS:
                truncated = True
                break
            count += 1
            if field.type.named_type in names:
                outgoing.append(
                    TypeEdge(
                        item.name,
                        field.type.named_type,
                        f"{item.name}.{field.name}",
                        field.type.is_list,
                        field.type.outer_non_null
                        and (
                            not isinstance(field, SchemaInputField) or field.default_value is None
                        ),
                    )
                )
        if not inputs:
            for possible in sorted(item.possible_types):
                if count >= MAX_GRAPH_RELATIONSHIPS:
                    truncated = True
                    break
                count += 1
                if possible in names:
                    outgoing.append(TypeEdge(item.name, possible, f"{item.name} on {possible}"))
        edges[item.name] = tuple(outgoing)
    return TypeGraph(edges, truncated)


def reachable_paths(graph: TypeGraph, starts: tuple[str, ...]) -> dict[str, tuple[TypeEdge, ...]]:
    """Visit each type once; retain one deterministic shortest witness per reached type."""
    paths: dict[str, tuple[TypeEdge, ...]] = {
        name: () for name in sorted(set(starts)) if name in graph.edges
    }
    queue = deque(paths)
    while queue:
        source = queue.popleft()
        for edge in graph.edges[source]:
            if edge.target not in paths:
                paths[edge.target] = (*paths[source], edge)
                queue.append(edge.target)
    return paths


def cycle_witnesses(graph: TypeGraph, *, require_list: bool) -> tuple[tuple[TypeEdge, ...], ...]:
    """One representative cycle per strongly connected component, without path enumeration.

    Iterative Kosaraju passes are O(V+E). A shortest return path within each disjoint
    component yields a witness containing a list edge when requested.
    """
    visited: set[str] = set()
    finished = []
    for start in sorted(graph.edges):
        if start in visited:
            continue
        stack = [(start, False)]
        while stack:
            name, exiting = stack.pop()
            if exiting:
                finished.append(name)
            elif name not in visited:
                visited.add(name)
                stack.append((name, True))
                stack.extend(
                    (edge.target, False)
                    for edge in reversed(graph.edges[name])
                    if edge.target not in visited
                )
    reverse: dict[str, list[str]] = {name: [] for name in graph.edges}
    for source in graph.edges:
        for edge in graph.edges[source]:
            reverse[edge.target].append(source)
    visited.clear()
    witnesses = []
    for start in reversed(finished):
        if start in visited:
            continue
        component: set[str] = set()
        pending = [start]
        while pending:
            name = pending.pop()
            if name in visited:
                continue
            visited.add(name)
            component.add(name)
            pending.extend(reverse[name])
        choices = sorted(
            (
                edge
                for name in component
                for edge in graph.edges[name]
                if edge.target in component
                and (len(component) > 1 or edge.target == name)
                and (not require_list or edge.is_list)
            ),
            key=lambda edge: (edge.source, edge.label, edge.target),
        )
        if not choices:
            continue
        first = choices[0]
        subgraph = TypeGraph(
            {
                name: tuple(edge for edge in graph.edges[name] if edge.target in component)
                for name in sorted(component)
            },
            False,
        )
        path = reachable_paths(subgraph, (first.target,))[first.source]
        witnesses.append((first, *path))
    return tuple(sorted(witnesses, key=lambda path: tuple(edge.label for edge in path)))


def format_path(path: tuple[TypeEdge, ...]) -> str:
    return " -> ".join((*[edge.label for edge in path], path[-1].target))
