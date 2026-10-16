"""Offline schema with the structural metadata retained by reduced introspection."""

from graphql import build_schema, graphql_sync

from gqlsleuth.graphql.introspection import REDUCED_INTROSPECTION_QUERY

SDL = """
interface Node { id: ID! }
type User implements Node { id: ID! name: String friends: [User!]! }
union SearchResult = User
enum Choice { FIRST SECOND @deprecated(reason: "Old value") }
input Options { choice: Choice = FIRST limit: Int nested: Options }
type Query {
  user(id: ID!): User
  users(options: Options): [User!]!
  search: [SearchResult]
  node: Node
  legacyToken: String @deprecated(reason: "Use other authentication")
  plain: String
  required: String!
  list: [String]
  listRequired: [String!]
  requiredList: [String!]!
}
type Mutation { createUser(name: String!): User deleteUser(id: ID!): Boolean }
type Subscription { changed: User }
"""


def introspection_body(query=REDUCED_INTROSPECTION_QUERY, sdl=SDL):
    result = graphql_sync(build_schema(sdl), query)
    assert result.errors is None
    return result.formatted
