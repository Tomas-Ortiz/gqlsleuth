"""Constructor-based AST replacement for mutable 3.2 and frozen 3.3 graphql-core nodes."""

from graphql.language.ast import Node


def replace_ast_node[T: Node](node: T, **changes: object) -> T:
    """Preserve every node attribute, including locations, without assigning to the input."""
    return type(node)(**({key: getattr(node, key) for key in node.keys} | changes))
