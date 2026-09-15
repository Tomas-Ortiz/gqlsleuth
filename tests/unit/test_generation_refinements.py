"""Offline boundaries for conservative collection bounds and semantic String inputs."""

import json
from dataclasses import replace

import pytest
from graphql import build_schema, introspection_from_schema, parse, validate
from graphql.execution.values import get_variable_values

from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.schema import TypeReference
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.graphql.query_generation import _placeholder, generate_mutation, generate_query
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.rules.loader import load_bundled_rules
from gqlsleuth.rules.operation_analysis import analyze_schema_operations
from gqlsleuth.rules.security_review import review_schema


def generate(sdl, name="inspect", kind=OperationKind.QUERY):
    native = build_schema(sdl)
    schema = parse_introspection_response(
        json.dumps({"data": introspection_from_schema(native)}).encode()
    )
    operations = analyze_schema_operations(
        "https://example.com/graphql", schema, load_bundled_rules()
    )
    operation = next(item for item in operations if item.name == name and item.kind is kind)
    generator = generate_query if kind is OperationKind.QUERY else generate_mutation
    artifact = generator(schema, operation)
    assert not validate(native, parse(artifact.query_text))
    assert isinstance(
        get_variable_values(
            native,
            parse(artifact.query_text).definitions[0].variable_definitions,
            artifact.variables,
        ),
        dict,
    )
    assert artifact == generator(schema, operation)
    assert artifact == generator(replace(schema, types=tuple(reversed(schema.types))), operation)
    return artifact, schema


@pytest.mark.parametrize(
    "name",
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
def test_direct_quantity_bounds(name):
    artifact, _ = generate(
        f"type Query {{ inspect({name}: Int): [User!]! }} type User {{ id: ID }}"
    )
    assert artifact.variables == {name: 1}


@pytest.mark.parametrize(
    "arguments,output,extra,expected",
    [
        (
            "options: Options",
            "UsersPage",
            "input Options { paginate: Page sort: String search: String } "
            "input Page { page: Int limit: Int }",
            {"options": {"paginate": {"limit": 1}}},
        ),
        (
            "options: Options!",
            "UsersPage",
            "input Options { accountId: ID! paginate: Page } input Page { limit: Int }",
            {"options": {"accountId": "1", "paginate": {"limit": 1}}},
        ),
        (
            "options: Options",
            "UsersPage",
            "input Options { accountId: ID! paginate: Page } input Page { limit: Int }",
            {"options": {"accountId": "1", "paginate": {"limit": 1}}},
        ),
        ("limit: Int = 50", "UsersPage", "", {"limit": 1}),
        ("limit: Int! = 50", "UsersPage", "", {"limit": 1}),
        ("limit: Int", "User", "", {}),
        ("after: String", "UserConnection", "", {}),
        ("first: Int, after: String", "UserConnection", "", {"first": 1}),
        ("accountId: ID!, limit: Int", "[User]", "", {"accountId": "1", "limit": 1}),
        (
            "options: Options",
            "UsersPage",
            "input Options { next: Options paginate: Page } input Page { limit: Int }",
            {"options": {"paginate": {"limit": 1}}},
        ),
        ("options: Options", "UsersPage", "input Options { next: Options page: Int }", {}),
        (
            "options: Options",
            "UsersPage",
            "input Options { next: Next } input Next { page: Page } input Page { limit: Int }",
            {"options": {"next": {"page": {"limit": 1}}}},
        ),
        (
            "options: Options",
            "UsersPage",
            "input Options { next: Next } input Next { page: Page } "
            "input Page { deeper: Deep } input Deep { limit: Int }",
            {},
        ),
        ("limit: String, take: Int", "[User]", "", {"take": 1}),
        ("options: [Options]", "UsersPage", "input Options { limit: Int }", {}),
        ("options: Options", "UsersPage", "input Options { limit: [Int] }", {}),
    ],
)
def test_minimal_paths_and_conservative_fallbacks(arguments, output, extra, expected):
    artifact, _ = generate(f"""
        type Query {{ inspect({arguments}): {output} }}
        type User {{ id: ID roles: [Role] }} type Role {{ id: ID }}
        type UsersPage {{ data: [User] }}
        type UserConnection {{ edges: [User] }}
        {extra}
    """)
    assert artifact.variables == expected


@pytest.mark.parametrize(
    "type_name", ["String", "ID", "Boolean", "Float", "DateTime", "JSON", "Choice"]
)
def test_optional_bound_requires_int_and_phase_sixteen_stays_name_based(type_name):
    artifact, schema = generate(f"""
        scalar DateTime scalar JSON enum Choice {{ ONE }}
        type Query {{ inspect(limit: {type_name}): [User] }} type User {{ id: ID }}
    """)
    assert artifact.variables == {}
    assert not any(
        item.candidate_type is SecurityCandidateType.LIST_BOUNDING_REVIEW
        for item in review_schema("https://example.com/graphql", schema).candidates
    )


def test_optional_bound_failure_keeps_original_required_arguments():
    artifact, _ = generate("""
        input Options { next: Recursive! limit: Int }
        input Recursive { next: [Recursive!]! }
        type Query { inspect(id: ID!, options: Options): [User] } type User { id: ID }
    """)
    assert artifact.variables == {"id": "1"}


@pytest.mark.parametrize(
    "name,expected",
    [
        ("email", "test@example.com"),
        ("emailAddress", "test@example.com"),
        ("EmailAddress", "test@example.com"),
        ("email_address", "test@example.com"),
        ("mail", "test@example.com"),
        ("mailAddress", "test@example.com"),
        ("password", "TestPass123!"),
        ("passwd", "TestPass123!"),
        ("passcode", "TestPass123!"),
        ("username", "testuser"),
        ("userName", "testuser"),
        ("user_name", "testuser"),
        ("loginName", "testuser"),
        ("login_name", "testuser"),
        ("name", "Test User"),
        ("firstName", "Test"),
        ("first_name", "Test"),
        ("lastName", "User"),
        ("fullName", "Test User"),
        ("displayName", "Test User"),
        ("phoneNumber", "+15555550100"),
        ("phone_number", "+15555550100"),
        ("phone", "+15555550100"),
        ("telephone", "+15555550100"),
        ("url", "https://example.com"),
        ("uri", "https://example.com"),
        ("website", "https://example.com"),
        ("websiteUrl", "https://example.com"),
        ("callbackUrl", "https://example.com"),
        ("redirectUrl", "https://example.com"),
        ("title", "test"),
        ("description", "test"),
        ("unrelated", "test"),
        ("passwordHint", "test"),
        ("emailAddressHint", "test"),
        ("renamed", "test"),
        ("urlEncoded", "test"),
        ("telephoneBook", "test"),
    ],
)
def test_semantic_direct_string_arguments(name, expected):
    artifact, _ = generate(f"type Query {{ inspect({name}: String!): String }}")
    assert artifact.variables == {name: expected}


def test_kebab_case_normalization_without_generating_invalid_graphql_names():
    _, schema = generate("type Query { inspect: String }")
    assert _placeholder(
        schema,
        TypeReference.named("String"),
        input_name="email-address",
        active_input_types=frozenset(),
    ) == ("test@example.com", ())


@pytest.mark.parametrize("kind", [OperationKind.QUERY, OperationKind.MUTATION])
def test_nested_semantics_scalar_precedence_and_query_only_bounds(kind, monkeypatch):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Generation sent HTTP"))
    artifact, _ = generate(
        """
        scalar DateTime scalar JSON enum State { Z A }
        input Input { profile: Profile! }
        input Profile {
            email: String! firstName: String! password: String!
            title: String! emails: [String!]! optional: String
        }
        type User { id: ID }
        type Query { inspect(input: Input!, email: ID!, password: Boolean!, ratio: Float!,
            state: State!, when: DateTime!, payload: JSON!, limit: Int): [User] }
        type Mutation { inspect(input: Input!, email: ID!, password: Boolean!, ratio: Float!,
            state: State!, when: DateTime!, payload: JSON!, limit: Int): [User] }
    """,
        kind=kind,
    )
    expected = {
        "input": {
            "profile": {
                "email": "test@example.com",
                "firstName": "Test",
                "password": "TestPass123!",
                "title": "test",
                "emails": ["test"],
            }
        },
        "email": "1",
        "password": False,
        "ratio": 1.0,
        "state": "A",
        "when": "test",
        "payload": "test",
    }
    if kind is OperationKind.QUERY:
        expected["limit"] = 1
    assert artifact.variables == expected
    assert len(artifact.manual_adjustments) == 2
    assert "operationName" not in artifact.query_text


def test_semantic_string_lists_use_leaf_name():
    artifact, _ = generate("type Query { inspect(email: [String!]!): String }")
    assert artifact.variables == {"email": ["test@example.com"]}
