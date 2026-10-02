"""Exercise immutable AST preparation even when the locked graphql-core is mutable."""

import sys
from dataclasses import FrozenInstanceError, replace

import pytest
from graphql import build_schema, parse, print_ast, validate
from graphql.language.ast import NameNode, Node

from fixtures.phase17_target import SDL as MULTIPLICITY_SDL
from fixtures.phase18_target import SDL as DEPTH_SDL
from gqlsleuth.application.multiplicity import prepare_multiplicity
from gqlsleuth.graphql import selection_paths
from gqlsleuth.graphql.ast_nodes import replace_ast_node
from gqlsleuth.graphql.object_authorization import substitute_object_identifier
from gqlsleuth.rules.schema_graph import TypeEdge


@pytest.fixture(autouse=True)
def immutable_nodes(monkeypatch):
    original = Node.__setattr__

    def frozen(node, name, value):
        # The 3.2 printer itself edits copies in its visitor; permit that upstream
        # implementation while rejecting writes from application code and tests.
        upstream_visitor = sys._getframe(1).f_globals.get("__name__") == "graphql.language.visitor"
        if name in node.keys and hasattr(node, name) and not upstream_visitor:
            raise FrozenInstanceError(f"cannot assign to field {name!r}")
        original(node, name, value)

    # 3.2 constructors can initialize attributes, but no already-set AST field is writable.
    # 3.3 concrete dataclasses already enforce this themselves.
    monkeypatch.setattr(Node, "__setattr__", frozen)


def test_constructor_replacement_preserves_all_other_attributes():
    node = parse("query($id: ID!){item(id:$id) @include(if:true){id}}").definitions[0]
    field = node.selection_set.selections[0]
    before = print_ast(node)
    with pytest.raises(FrozenInstanceError):
        field.alias = NameNode(value="forbidden")
    changed = replace_ast_node(field, alias=NameNode(value="copy"))
    assert changed is not field and changed.alias.value == "copy"
    for key in field.keys:
        if key != "alias":
            assert getattr(changed, key) is getattr(field, key)
    assert print_ast(node) == before


def test_frozen_multiplicity_keeps_three_aliases_and_exact_batch(phase_ten_scan):
    safe, requests = phase_ten_scan(MULTIPLICITY_SDL)
    before, count = safe.query_generation.queries, len(requests)
    alias, batch = prepare_multiplicity(safe).candidates
    original = parse(alias.base.query_text).definitions[0]
    aliased = parse(alias.query).definitions[0]
    assert aliased.variable_definitions == original.variable_definitions
    assert [f.alias.value for f in aliased.selection_set.selections] == [
        "gqlsleuthAlias1",
        "gqlsleuthAlias2",
        "gqlsleuthAlias3",
    ]
    for field in aliased.selection_set.selections:
        assert print_ast(replace_ast_node(field, alias=None)) == print_ast(
            original.selection_set.selections[0]
        )
    assert (
        batch.request_json
        == [{"query": batch.base.query_text, "variables": batch.base.variables}] * 2
    )
    assert len(requests) == count and safe.query_generation.queries == before


@pytest.mark.parametrize("argument", ['id:"old",', "", "id:$key,"])
def test_frozen_id_substitution_rebuilds_parents_without_changing_inputs(phase_ten_scan, argument):
    sdl = "type Query { order(id:ID,label:String!): Order } type Order { id:ID total:Float }"
    safe = phase_ten_scan(sdl)[0]
    schema = safe.query_generation.operation_analysis.schema_scan.schemas[0].schema
    root_schema = selection_paths.schema_field(schema, schema.query_root, "order")
    variables = {"label": "keep", "id": "unrelated"}
    definition = "$label:String!"
    if "$key" in argument:
        definition += ",$key:ID"
        variables["key"] = "old"
    document = parse(f"query({definition}){{order({argument}label:$label){{total}}}}")
    before = print_ast(document)
    operation = document.definitions[0]
    original_root = operation.selection_set.selections[0]
    updated, root, values = substitute_object_identifier(
        operation, original_root, root_schema, variables, "id", "chosen"
    )
    result = replace_ast_node(document, definitions=(updated,))
    assert not validate(build_schema(sdl), parse(print_ast(result)))
    assert updated.selection_set.selections[0] is root
    assert [f.name.value for f in root.selection_set.selections] == ["total", "id"]
    variable = next(a.value.name.value for a in root.arguments if a.name.value == "id")
    assert values[variable] == "chosen"
    assert values["label"] == "keep" and values["id"] == "unrelated"
    assert print_ast(document) == before and variables.get("key", "old") == "old"


@pytest.mark.parametrize("has_path", [False, True])
def test_frozen_path_extension_retains_siblings_and_original_ast(
    phase_ten_scan, monkeypatch, has_path
):
    safe = phase_ten_scan(DEPTH_SDL)[0]
    schema = safe.query_generation.operation_analysis.schema_scan.schemas[0].schema
    base = safe.query_generation.queries[0]
    if has_path:
        base = replace(base, query_text="query($id:ID!){album(id:$id){id user{id}}}")
    document = parse(base.query_text)
    before = print_ast(document)
    monkeypatch.setattr(selection_paths, "parse", lambda _: document)
    updated = selection_paths.extend_selection_path(
        schema,
        build_schema(DEPTH_SDL),
        base,
        (TypeEdge("Album", "User", "Album.user"), TypeEdge("User", "Album", "User.albums", True)),
        terminal_typename=True,
    )
    assert print_ast(document) == before
    assert not validate(build_schema(DEPTH_SDL), updated)
    operation = updated.definitions[0]
    assert operation.variable_definitions == document.definitions[0].variable_definitions
    root = operation.selection_set.selections[0]
    assert [f.name.value for f in root.selection_set.selections] == ["id", "user"]
    user = root.selection_set.selections[1]
    assert [f.name.value for f in user.selection_set.selections] == (
        ["id", "albums"] if has_path else ["albums"]
    )
    assert "albums(limit: 1)" in print_ast(updated) and "__typename" in print_ast(updated)
