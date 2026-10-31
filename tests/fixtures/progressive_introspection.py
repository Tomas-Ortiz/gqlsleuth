"""Local GraphQL execution simulates query-depth policy; never a network target."""

import json

import httpx
from graphql import (
    FragmentDefinitionNode,
    FragmentSpreadNode,
    OperationDefinitionNode,
    TypeInfo,
    TypeInfoVisitor,
    Visitor,
    build_schema,
    graphql_sync,
    parse,
    visit,
)

from gqlsleuth.graphql.introspection import (
    FULL_INTROSPECTION_QUERY,
    MINIMAL_INTROSPECTION_QUERY,
    REDUCED_INTROSPECTION_QUERY,
)

SDL = """
schema { query: Read mutation: Write subscription: Events }
interface Node { id: ID! }
type Person implements Node { id: ID! friends: [Person!]! role: Role! }
union Search = Person
enum Role { MEMBER STAFF }
input Filter { role: Role = MEMBER name: String }
type Read { people(filter: Filter): [Person!]! node: Node search: [Search] ping: String }
type Write { createPerson(name: String!): Person }
type Events { changed: Person }
directive @label(role: Role = MEMBER) repeatable on FIELD_DEFINITION
"""
QUERY_ONLY = """
enum Region { NORTH SOUTH }
enum Order { ASC DESC }
input Filter { region: Region order: Order }
type Place { code: ID! related: [Place!]! }
type Directory { places(filter: Filter): [Place!]! }
schema { query: Directory }
"""


def query_depth(query):
    document = parse(query)
    fragments = {
        n.name.value: n for n in document.definitions if isinstance(n, FragmentDefinitionNode)
    }

    def walk(selection):
        return max(
            (
                walk(fragments[n.name.value].selection_set)
                if isinstance(n, FragmentSpreadNode)
                else 1 + (walk(n.selection_set) if n.selection_set else 0)
                for n in selection.selections
            ),
            default=0,
        )

    return walk(
        next(
            n for n in document.definitions if isinstance(n, OperationDefinitionNode)
        ).selection_set
    )


def mock_recovery(sdl=SDL, *, depth=8, override=None):
    schema = build_schema(sdl)
    seen = []

    def handler(request):
        seen.append(request)
        if override:
            replacement = override(request, len(seen))
            if replacement is not None:
                return replacement
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": schema.query_type.name}})
        payload = json.loads(request.content)
        query = payload["query"]
        if query in {FULL_INTROSPECTION_QUERY, REDUCED_INTROSPECTION_QUERY} or (
            query != MINIMAL_INTROSPECTION_QUERY and query_depth(query) > depth
        ):
            return httpx.Response(
                413, json={"errors": [{"message": "Query depth limit exceeded."}]}
            )
        result = graphql_sync(schema, query, variable_values=payload.get("variables"))
        return httpx.Response(200, json=result.formatted)

    return handler, seen, schema


def legacy_recovery(sdl=SDL, *, unsupported=(), depth=8, override=None):
    """Simulate older introspection argument validation without modifying global schema types."""

    def reject(request, count):
        if override:
            response = override(request, count)
            if response is not None:
                return response
        if request.method != "POST":
            return None
        query = json.loads(request.content)["query"]
        if query in {FULL_INTROSPECTION_QUERY, REDUCED_INTROSPECTION_QUERY}:
            return None
        info = TypeInfo(schema)
        errors = []

        class LegacyArguments(Visitor):
            def enter_field(self, node, *_):
                parent = info.get_parent_type()
                if (
                    parent
                    and f"{parent.name}.{node.name.value}" in unsupported
                    and any(a.name.value == "includeDeprecated" for a in node.arguments)
                ):
                    errors.append(
                        {
                            "message": (
                                'Unknown argument "includeDeprecated" on field '
                                f'"{node.name.value}" of type "{parent.name}".'
                            )
                        }
                    )

        visit(parse(query), TypeInfoVisitor(info, LegacyArguments()))
        return httpx.Response(400, json={"errors": errors}) if errors else None

    handler, seen, schema = mock_recovery(sdl, depth=depth, override=reject)
    return handler, seen, schema
