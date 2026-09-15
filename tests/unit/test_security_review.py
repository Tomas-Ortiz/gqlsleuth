"""Offline positive/negative boundaries for structural candidates and bounded traversal."""

import json
from dataclasses import replace
from uuid import uuid4

import pytest
from graphql import build_schema, introspection_from_schema

from fixtures.phase16_smoke import SDL
from gqlsleuth.domain.security_review import SecurityCandidateType as Kind
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.presentation.security_review import candidate_summary
from gqlsleuth.rules import schema_graph
from gqlsleuth.rules.loader import load_bundled_rules
from gqlsleuth.rules.operation_analysis import analyze_schema_operations
from gqlsleuth.rules.security_review import find_bounding_input, review_schema

ENDPOINT = "https://example.com/graphql"


def parsed(sdl):
    return parse_introspection_response(
        json.dumps({"data": introspection_from_schema(build_schema(sdl))}).encode()
    )


def review(sdl):
    schema = parsed(sdl)
    operations = analyze_schema_operations(ENDPOINT, schema, load_bundled_rules())
    return review_schema(ENDPOINT, schema, operations)


def candidates(sdl, kind):
    return tuple(item for item in review(sdl).candidates if item.candidate_type is kind)


@pytest.mark.parametrize(
    "argument,extra,path",
    [
        ("file: Upload!", "", "file: Upload!"),
        ("input: Attachment!", "input Attachment { file: Upload! }", "Attachment.file -> Upload"),
        (
            "input: [Attachment!]!",
            "input Attachment { file: [Upload!]! }",
            "Attachment.file -> Upload",
        ),
    ],
)
def test_upload_inputs(argument, extra, path):
    result = candidates(
        f"scalar Upload type Query {{ ok: String }} {extra} "
        f"type Mutation {{ attach({argument}): String }}",
        Kind.FILE_UPLOAD_SURFACE,
    )
    assert len(result) == 1 and result[0].subject == "mutation attach"
    assert path in " ".join(result[0].supporting_facts)


def test_upload_name_without_upload_scalar_does_not_trigger():
    assert not candidates(
        "type Query { ok: String } type Mutation { upload(fileName: String): String }",
        Kind.FILE_UPLOAD_SURFACE,
    )


@pytest.mark.parametrize(
    "sdl",
    [
        "type Query { _service: _Service! } type _Service { sdl: String }",
        "scalar _Any type Item { id: ID } union _Entity = Item "
        "type Query { _entities(representations: [_Any!]!): [_Entity]! }",
    ],
)
def test_coherent_federation_shapes(sdl):
    result = candidates(sdl, Kind.FEDERATION_SURFACE)
    assert len(result) == 1 and len(result[0].supporting_facts) >= 2
    assert "apollo" not in repr(result).lower()


@pytest.mark.parametrize(
    "sdl",
    [
        "type Query { _internal: String }",
        "scalar _Any type Query { _service: String _entities: String }",
        "type Query { _service: _Service } type _Service { name: String }",
    ],
)
def test_federation_requires_coherent_structure(sdl):
    assert not candidates(sdl, Kind.FEDERATION_SURFACE)


def test_subscription_surface_only_when_exposed():
    assert not candidates("type Query { ok: String }", Kind.SUBSCRIPTION_SURFACE)
    result = candidates(
        "type Query { ok: String } type Subscription { event: String }", Kind.SUBSCRIPTION_SURFACE
    )
    assert len(result) == 1 and "1 operation" in result[0].deterministic_reason


@pytest.mark.parametrize(
    "field",
    [
        "node(id: ID!): Item",
        "nodes(ids: [ID!]!): [Item]",
        "user(id: ID!): Item",
        "account(accountId: ID): Item",
        "account(account_id: ID): Item",
    ],
)
def test_identifier_lookup(field):
    result = candidates(
        f"type Query {{ {field} }} type Item {{ value: String }}", Kind.OBJECT_LOOKUP_REVIEW
    )
    assert len(result) == 1
    assert "IDOR" not in repr(result) and "BOLA" not in repr(result)


@pytest.mark.parametrize(
    "field",
    [
        "item(valid: ID): Item",
        "item(id: Int): Item",
        "item(name: String): Item",
        "item(id: ID): String",
        "item(identity: ID): Item",
    ],
)
def test_lookup_false_positive_controls(field):
    assert not candidates(
        f"type Query {{ {field} }} type Item {{ value: String }}", Kind.OBJECT_LOOKUP_REVIEW
    )


@pytest.mark.parametrize(
    "argument",
    [
        "first",
        "last",
        "limit",
        "take",
        "size",
        "pageSize",
        "page_size",
        "perPage",
        "per_page",
        "maxResults",
        "max_results",
    ],
)
def test_exact_bounding_arguments(argument):
    assert not candidates(
        f"type Query {{ items({argument}: Int): [Item!]! }} type Item {{ id: ID }}",
        Kind.LIST_BOUNDING_REVIEW,
    )


@pytest.mark.parametrize(
    "field,expected",
    [
        ("items: [Item]", True),
        ("items(unlimited: Int): [Item]", True),
        ("items: [String]", False),
        ("items: Item", False),
    ],
)
def test_list_structure_and_substring_collisions(field, expected):
    assert (
        bool(
            candidates(
                f"type Query {{ {field} }} type Item {{ id: ID }}", Kind.LIST_BOUNDING_REVIEW
            )
        )
        is expected
    )


@pytest.mark.parametrize("scalar", ["JSON", "JSONObject", "Any", "Map"])
def test_flexible_root_and_nested_scalars_deduplicated(scalar):
    result = candidates(
        f"scalar {scalar} input Settings {{ value: {scalar} }} "
        f"type Query {{ search(a: {scalar}, b: Settings): String }}",
        Kind.FLEXIBLE_SCALAR_INPUT_REVIEW,
    )
    assert len(result) == 1 and len(result[0].supporting_facts) == 1
    nested = candidates(
        f"scalar {scalar} input Settings {{ value: {scalar} }} "
        "type Query { search(input: Settings): String }",
        Kind.FLEXIBLE_SCALAR_INPUT_REVIEW,
    )
    assert "Settings.value" in nested[0].supporting_facts[0]


@pytest.mark.parametrize("scalar", ["DateTime", "UUID", "Email", "URL", "JSONText"])
def test_other_custom_scalars_are_not_flexible(scalar):
    assert not candidates(
        f"scalar {scalar} type Query {{ item(value: {scalar}): String }}",
        Kind.FLEXIBLE_SCALAR_INPUT_REVIEW,
    )


@pytest.mark.parametrize(
    "sdl,path",
    [
        (
            "type Query { users: [User] other: User } type User { friends: [User] }",
            "User.friends -> User",
        ),
        (
            "type Query { org: Org } type Org { users: [User] } type User { org: Org }",
            "Org.users -> User.org -> Org",
        ),
        (
            "type Query { node: Node } interface Node { id: ID } "
            "type User implements Node { id: ID friends: [User] }",
            "User.friends -> User",
        ),
    ],
)
def test_reachable_list_cycles_one_witness(sdl, path):
    result = candidates(sdl, Kind.RECURSIVE_GRAPH_REVIEW)
    assert len(result) == 1 and result[0].supporting_facts == ("Cycle: " + path,)


@pytest.mark.parametrize(
    "sdl",
    [
        "type Query { user: User } type User { address: Address } type Address { city: String }",
        "type Query { user: User } type User { friend: User }",
        "type Query { ok: String } type User { friends: [User] }",
    ],
)
def test_finite_singular_or_unreachable_cycles_do_not_trigger(sdl):
    assert not candidates(sdl, Kind.RECURSIVE_GRAPH_REVIEW)


def test_complex_recursive_input_is_bounded_and_deduplicated():
    result = candidates(
        "input Filter { next: Filter alternatives: [Filter] } "
        "type Query { search(a: Filter, b: Filter): String }",
        Kind.COMPLEX_INPUT_REVIEW,
    )
    assert len(result) == 1 and len(result[0].supporting_facts) == 1
    assert "Recursive input:" in result[0].supporting_facts[0]


@pytest.mark.parametrize("count,expected", [(2, False), (4, False), (5, True)])
def test_required_input_threshold(count, expected):
    inputs = " ".join(f"input Input{i} {{ next: Input{i + 1}! }}" for i in range(count - 1))
    inputs += f" input Input{count - 1} {{ value: String }}"
    assert (
        bool(
            candidates(
                "type Query { search(input: Input0!): String } " + inputs, Kind.COMPLEX_INPUT_REVIEW
            )
        )
        is expected
    )


def test_optional_and_defaulted_inputs_do_not_extend_required_chain():
    for middle in ("Input1", "Input1! = {}"):
        sdl = f"input Input0 {{ next: {middle} }} input Input1 {{ next: Input2! = {{}} }} "
        sdl += "input Input2 { next: Input3! = {} } input Input3 { value: String } "
        sdl += "type Query { search(input: Input0!): String }"
        assert not candidates(sdl, Kind.COMPLEX_INPUT_REVIEW)


def test_deprecated_interest_preserves_phase_seven_score_and_reason():
    sdl = 'type Query { login: String @deprecated(reason: "Use signIn") plain: String @deprecated }'
    result = candidates(sdl, Kind.DEPRECATED_SECURITY_RELEVANT_OPERATION)
    assert len(result) == 1 and result[0].subject == "query login"
    assert result[0].supporting_facts == ("Deprecation reason: Use signIn",)
    assert result[0].related_operation.interest_score > 0


def test_order_deduplication_and_evidence_references_do_not_depend_on_schema_order():
    schema = parsed(SDL)
    operations = analyze_schema_operations(ENDPOINT, schema, load_bundled_rules())
    evidence_id = uuid4()
    result = review_schema(ENDPOINT, schema, operations, source_evidence_ids=(evidence_id,))
    reordered = replace(
        schema,
        types=tuple(
            replace(
                item,
                fields=tuple(reversed(item.fields)),
                input_fields=tuple(reversed(item.input_fields)),
            )
            for item in reversed(schema.types)
        ),
    )
    assert result == review_schema(
        ENDPOINT, reordered, operations[::-1], source_evidence_ids=(evidence_id,)
    )
    assert {item.candidate_type for item in result.candidates} == set(Kind)
    assert len({(item.candidate_type, item.subject) for item in result.candidates}) == len(
        result.candidates
    )
    rank = {kind: index for index, kind in enumerate(Kind)}
    keys = [(rank[item.candidate_type], item.endpoint, item.subject) for item in result.candidates]
    assert keys == sorted(keys)
    assert all(item.source_evidence_ids == (evidence_id,) for item in result.candidates)
    assert operations == analyze_schema_operations(ENDPOINT, schema, load_bundled_rules())


@pytest.mark.parametrize("limit", ["MAX_GRAPH_TYPES", "MAX_GRAPH_RELATIONSHIPS"])
def test_traversal_limit_is_explicit_and_results_remain_deterministic(monkeypatch, limit):
    monkeypatch.setattr(schema_graph, limit, 2)
    result = review(SDL)
    assert result.limitations and all("partial" in item.reason for item in result.limitations)
    assert review(SDL) == result


def test_long_cycle_terminates_without_python_recursion_or_cycle_enumeration():
    types = " ".join(f"type T{i} {{ next: [T{(i + 1) % 180}] }}" for i in range(180))
    result = candidates("type Query { start: T0 } " + types, Kind.RECURSIVE_GRAPH_REVIEW)
    assert len(result) == 1


@pytest.mark.parametrize(
    "wrapper,child",
    [
        ("AlbumsPage", "data"),
        ("UserConnection", "edges"),
        ("ItemCollection", "values"),
        ("ItemResults", "values"),
        ("ItemResultSet", "values"),
        ("Item_Result_Set", "values"),
        *(
            ("Payload", name)
            for name in ("data", "items", "nodes", "edges", "results", "records", "entries")
        ),
    ],
)
def test_high_signal_one_level_collection_wrappers(wrapper, child):
    result = candidates(
        f"type Query {{ collection: {wrapper} }} "
        f"type {wrapper} {{ {child}: [Item!]! }} type Item {{ id: ID }}",
        Kind.LIST_BOUNDING_REVIEW,
    )
    assert len(result) == 1 and result[0].subject == "query collection"
    assert f"Collection path: {wrapper}.{child}" in result[0].supporting_facts
    assert "Element type: Item" in result[0].supporting_facts


@pytest.mark.parametrize(
    "arguments,inputs,bound",
    [
        ("limit: Int", "", "limit"),
        ("after: String, first: Int", "", "first"),
        ("options: Options", "input Options { limit: Int }", "options.limit"),
        (
            "options: Options",
            "input Options { paginate: Pagination } input Pagination { page: Int limit: Int }",
            "options.paginate.limit",
        ),
        (
            "options: Options",
            "input Options { paginate: Pagination } "
            "input Pagination { count: Count } input Count { size: Int }",
            "options.paginate.count.size",
        ),
        ("options: Options = {limit: 10}", "input Options { limit: Int }", "options.limit"),
        ("options: Options", "input Options { page_size: Int }", "options.page_size"),
    ],
)
def test_wrapper_schema_bounds_include_optional_nested_inputs(arguments, inputs, bound):
    schema = parsed(
        f"type Query {{ albums({arguments}): AlbumsPage }} "
        f"type AlbumsPage {{ data: [Album] }} type Album {{ id: ID }} {inputs}"
    )
    field = schema.type_named("Query").fields[0]
    assert find_bounding_input(field, {item.name: item for item in schema.types}) == bound
    assert not any(
        item.candidate_type is Kind.LIST_BOUNDING_REVIEW
        for item in review_schema(ENDPOINT, schema).candidates
    )


@pytest.mark.parametrize(
    "arguments,inputs",
    [
        ("page: Int", ""),
        ("after: String", ""),
        ("before: String", ""),
        ("cursor: String", ""),
        ("offset: Int", ""),
        ("filter: String, sort: String, search: String", ""),
        ("options: Options", "input Options { page: Int offset: Int search: String }"),
        ("options: Options", "input Options { unlimited: Int resized: Int }"),
        (
            "options: A",
            "input A { next: B } input B { next: C } input C { next: D } input D { limit: Int }",
        ),
    ],
)
def test_position_only_or_out_of_depth_bounds_do_not_suppress(arguments, inputs):
    result = candidates(
        f"type Query {{ albums({arguments}): AlbumsPage }} "
        f"type AlbumsPage {{ data: [Album] }} type Album {{ id: ID }} {inputs}",
        Kind.LIST_BOUNDING_REVIEW,
    )
    assert len(result) == 1
    assert "Obvious bounding input: none observed" in result[0].supporting_facts[-1]


@pytest.mark.parametrize(
    "wrapper,fields,extra",
    [
        ("User", "roles: [Role]", "type Role { id: ID }"),
        ("User", "metadata: [Role]", "type Role { id: ID }"),
        ("Homepage", "values: [Role]", "type Role { id: ID }"),
        ("PageStatistics", "values: [Role]", "type Role { id: ID }"),
        ("AlbumsPage", "data: [String]", ""),
        ("AlbumsPage", "data: NestedPage", "type NestedPage { data: [Role] } type Role { id: ID }"),
    ],
)
def test_incidental_lists_scalars_and_deeper_wrappers_do_not_qualify(wrapper, fields, extra):
    assert not candidates(
        f"type Query {{ current: {wrapper} }} type {wrapper} {{ {fields} }} {extra}",
        Kind.LIST_BOUNDING_REVIEW,
    )


def test_multiple_wrapper_fields_one_candidate_bounded_stable_facts():
    sdl = (
        "type Query { rows: RowPage } "
        "type RowPage { z: [Row] c: [Row] b: [Row] a: [Row] } type Row { id: ID }"
    )
    result = candidates(sdl, Kind.LIST_BOUNDING_REVIEW)
    assert len(result) == 1
    assert [fact for fact in result[0].supporting_facts if fact.startswith("Collection path")] == [
        "Collection path: RowPage.a",
        "Collection path: RowPage.b",
        "Collection path: RowPage.c",
    ]
    assert "Additional qualifying collection fields: 1." in result[0].supporting_facts
    assert result == candidates(
        sdl.replace("z: [Row] c: [Row] b: [Row] a: [Row]", "a: [Row] b: [Row] c: [Row] z: [Row]"),
        Kind.LIST_BOUNDING_REVIEW,
    )


@pytest.mark.parametrize("quantity,expected", [("", True), ("limit: Int", False)])
def test_bounding_input_cycle_terminates(quantity, expected):
    sdl = f"input A {{ next: B }} input B {{ back: A {quantity} }} "
    sdl += "type Query { rows(options: A): [Row] } type Row { id: ID }"
    assert bool(candidates(sdl, Kind.LIST_BOUNDING_REVIEW)) is expected


def test_lookup_contextual_guidance_does_not_change_structural_detection():
    result = candidates(
        "type Query { country(id: ID): Country } type Country { name: String }",
        Kind.OBJECT_LOOKUP_REVIEW,
    )
    assert len(result) == 1
    assert candidate_summary(result[0]) == "Direct object lookup by identifier"
    assert result[0].review_guidance.startswith("Where these objects are access-controlled,")


def test_collection_page_cycle_still_has_one_stable_recursive_witness():
    result = candidates(
        "type Query { albums: AlbumsPage } type AlbumsPage { data: [Album] } "
        "type Album { user: User } type User { albums: AlbumsPage }",
        Kind.RECURSIVE_GRAPH_REVIEW,
    )
    assert len(result) == 1
    assert result[0].supporting_facts == (
        "Cycle: AlbumsPage.data -> Album.user -> User.albums -> AlbumsPage",
    )
