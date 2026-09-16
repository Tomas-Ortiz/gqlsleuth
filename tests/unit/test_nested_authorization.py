"""Local-only nested paths, exact request eligibility and conservative structural outcomes."""

import json
from copy import deepcopy
from dataclasses import replace

import pytest
from graphql import build_schema, parse, validate

from fixtures.phase19_target import SDL
from gqlsleuth.application.differential_review import ContextScanResult, compare_context_scans
from gqlsleuth.application.nested_authorization import (
    execute_nested_authorization,
    prepare_nested_authorization,
)
from gqlsleuth.domain.differential import NamedAuthContext
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.domain.nested_authorization import NestedDifference
from gqlsleuth.domain.nested_authorization import NestedOutcome as Outcome
from gqlsleuth.graphql.nested_authorization import classify_nested_response
from gqlsleuth.infrastructure.http import HttpClient


@pytest.fixture
def scan_contexts(phase_ten_scan):
    def build(*schemas):
        return compare_context_scans(
            Target.parse("https://example.com/graphql"),
            tuple(
                ContextScanResult(label, phase_ten_scan(sdl, mode=ScanMode.SAFE)[0])
                for label, sdl in zip(
                    ("cliente", "soporte", "tercero"), schemas or (SDL, SDL), strict=False
                )
            ),
        )

    return build


def test_local_rules_paths_and_ast(scan_contexts, monkeypatch):
    result = scan_contexts()
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Preparation HTTP"))
    preview = prepare_nested_authorization(result)
    assert len(preview.candidates) == 3
    assert [item.path for item in preview.candidates] == [
        ("settings", "secret"),
        ("members", "email"),
        ("owner", "email"),
    ]
    for item in preview.candidates:
        assert item.query and not validate(build_schema(SDL), parse(item.query))
        base, query = parse(item.base.query_text).definitions[0], parse(item.query).definitions[0]
        assert base.variable_definitions == query.variable_definitions
        assert (
            base.selection_set.selections[0].arguments
            == query.selection_set.selections[0].arguments
        )
        assert item.base.variables == {"id": "1"}
        assert query.selection_set.selections[0].selection_set.selections[0].name.value == "id"
        assert item.selection_depth == 3 and item.list_edges <= 1
        assert len(item.path) == 2 and item.matched_rules and item.source_evidence_ids
    assert "members(limit: 1)" in preview.candidates[1].query
    assert prepare_nested_authorization(result) == preview


@pytest.mark.parametrize(
    "change", ["not_attempted", "graphql_error", "variables", "document", "missing"]
)
def test_common_success_equivalent_baselines_required(scan_contexts, change):
    result = scan_contexts()
    context = result.contexts[1]
    execution = context.scan.executions[0]
    if change == "not_attempted":
        execution = replace(execution, attempted=False)
    elif change == "graphql_error":
        execution = replace(execution, status=QueryExecutionStatus.GRAPHQL_ERROR)
    elif change == "variables":
        execution = replace(
            execution, generated_query=replace(execution.generated_query, variables={"id": "2"})
        )
    elif change == "document":
        execution = replace(
            execution,
            generated_query=replace(
                execution.generated_query, query_text="query($id:ID!){project(id:$id){__typename}}"
            ),
        )
    context = replace(
        context, scan=replace(context.scan, executions=() if change == "missing" else (execution,))
    )
    preview = prepare_nested_authorization(replace(result, contexts=(result.contexts[0], context)))
    assert not preview.candidates and preview.limitations


def test_visibility_is_local_and_missing_schema_is_not_absence(scan_contexts):
    result = scan_contexts(SDL, SDL.replace("email: String", "label: String"))
    preview = prepare_nested_authorization(result)
    assert len(preview.pairs) == 2
    assert all(
        pair.kind is NestedDifference.NESTED_FIELD_VISIBILITY_DIFFERENCE for pair in preview.pairs
    )
    assert all(pair.source_evidence_ids for pair in preview.pairs)
    assert sum(item.query is not None for item in preview.candidates) == 1
    context = result.contexts[1]
    generation = context.scan.query_generation
    analysis = generation.operation_analysis
    scan = replace(
        context.scan,
        query_generation=replace(
            generation,
            operation_analysis=replace(
                analysis, schema_scan=replace(analysis.schema_scan, schemas=())
            ),
        ),
    )
    missing = prepare_nested_authorization(
        replace(result, contexts=(result.contexts[0], replace(context, scan=scan)))
    )
    assert not missing.pairs and not missing.candidates and missing.limitations


@pytest.mark.parametrize(
    "sdl",
    [
        "type Query { user: User } type User { id: ID email: String }",
        "type Query { project: Project } type Project { id: ID owner(id: ID!): User } "
        "type User { id: ID email: String }",
        "type Query { project: Project } type Project { id: ID members: [User] } "
        "type User { id: ID email: String }",
        "type Query { project: Project } type Project { id: ID owner: User } "
        "type User { id: ID password: String login: String upload: String }",
        "type Query { project: Project } union Project = User type User { id: ID email: String }",
        "type Query { project: Project } type Project { id: ID child: Project email: String }",
        "type Query { project: Project } type Project { id: ID a: A } "
        "type A { b: B } type B { c: C } type C { d: D } type D { email: String }",
        "type Query { project: Project } type Project { id: ID members(limit: Int): [User] } "
        "type User { id: ID members(limit: Int): [Member] } type Member { id: ID email: String }",
    ],
)
def test_unsuitable_paths_are_not_probed(scan_contexts, sdl):
    preview = prepare_nested_authorization(scan_contexts(sdl, sdl))
    assert not preview.candidates and preview.limitations


def test_nested_bounds_optional_siblings_and_global_cap(scan_contexts):
    sdl = (
        SDL.replace("members(limit: Int)", "members(options: Options)")
        + "input Options { page: Page sort: String } input Page { limit: Int offset: Int }"
    )
    preview = prepare_nested_authorization(scan_contexts(sdl, sdl))
    assert "members(options: {page: {limit: 1}})" in preview.candidates[1].query
    assert "sort:" not in preview.candidates[1].query
    many = SDL.replace("email: String", "email: String phone: String debug: String secret: String")
    preview = prepare_nested_authorization(scan_contexts(many, many, many))
    assert len(preview.candidates) == 3 and any(
        "three-candidate" in item for item in preview.limitations
    )


def test_schema_input_defaults_must_be_compatible(scan_contexts):
    sdl = (
        SDL.replace("project(id: ID!)", "project(options: Options!)")
        + "input Options { option: Int = 1 }"
    )
    preview = prepare_nested_authorization(scan_contexts(sdl, sdl.replace("Int = 1", "Int = 2")))
    assert not preview.candidates
    assert any("defaults/coerced inputs differ" in reason for reason in preview.limitations)


def test_visibility_requires_compatible_parent_types(scan_contexts):
    changed = SDL.replace("owner: User", "owner: Other") + "type Other { id: ID label: String }"
    preview = prepare_nested_authorization(scan_contexts(SDL, changed))
    assert not preview.pairs
    assert all(item.path != ("owner", "email") for item in preview.candidates)
    assert any("parent types differ" in reason for reason in preview.limitations)


def test_semantic_enum_terminal_and_bounded_root_preserved(scan_contexts):
    sdl = """
    type Query { projects(limit: Int, accountId: ID!): [Project] }
    type Project { id: ID owner: User }
    type User { email: Email }
    enum Email { UNDISCLOSED }
    """
    candidate = prepare_nested_authorization(scan_contexts(sdl, sdl)).candidates[0]
    assert candidate.terminal_type == "Email" and candidate.list_edges == 1
    assert candidate.base.variables == {"accountId": "1", "limit": 1}
    assert "projects(accountId: $accountId, limit: $limit)" in candidate.query


@pytest.mark.parametrize("value", [False, 0, "", [], "first", "different", 93])
def test_non_null_presence_does_not_compare_values(value):
    body = json.dumps({"data": {"project": {"owner": {"email": value}}}}).encode()
    assert classify_nested_response(200, body, ("project", "owner", "email"))[0] is Outcome.RETURNED


@pytest.mark.parametrize(
    "data",
    [
        {"project": None},
        {"project": {"owner": None}},
        {"project": {"owner": {"email": None}}},
        {"project": {"owner": []}},
        {},
        [],
    ],
)
def test_null_missing_empty_parent_is_not_denial(data):
    assert (
        classify_nested_response(
            200, json.dumps({"data": data}).encode(), ("project", "owner", "email")
        )[0]
        is Outcome.INDETERMINATE
    )


@pytest.mark.parametrize(
    "code", ["FORBIDDEN", "UNAUTHENTICATED", "UNAUTHORIZED", "ACCESS_DENIED", "AccessDenied"]
)
def test_structured_denial_codes_and_list_indices(code):
    body = json.dumps(
        {
            "errors": [
                {
                    "message": "untrusted",
                    "extensions": {"code": code},
                    "path": ["project", "members", 0, "email"],
                }
            ]
        }
    ).encode()
    assert (
        classify_nested_response(200, body, ("project", "members", "email"))[0]
        is Outcome.EXPLICIT_DENIAL
    )


@pytest.mark.parametrize(
    "error",
    [
        {"message": "Object is missing"},
        {"message": "Resolver failed"},
        {"message": "FORBIDDEN", "path": ["project", "other"]},
        {"message": "Forbidden", "path": ["other"]},
        {"message": "Forbidden", "path": ["project", "owner", True, "email"]},
        {"message": "Field forbiddenStatus is invalid"},
        {"extensions": {"code": "NOT_FORBIDDEN"}},
    ],
)
def test_generic_or_unrelated_errors_indeterminate(error):
    assert (
        classify_nested_response(
            200, json.dumps({"errors": [error]}).encode(), ("project", "owner", "email")
        )[0]
        is Outcome.INDETERMINATE
    )


def test_partial_data_with_denial_is_ambiguous():
    document = {
        "data": {"project": {"members": [{"email": "value"}, {"email": None}]}},
        "errors": [{"message": "Forbidden", "path": ["project", "members", 1, "email"]}],
    }
    assert (
        classify_nested_response(
            200, json.dumps(document).encode(), ("project", "members", "email")
        )[0]
        is Outcome.INDETERMINATE
    )


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, Outcome.EXPLICIT_DENIAL),
        (403, Outcome.EXPLICIT_DENIAL),
        (400, Outcome.INDETERMINATE),
        (500, Outcome.INDETERMINATE),
        (200, Outcome.INDETERMINATE),
    ],
)
def test_http_and_malformed_responses(status, expected):
    assert (
        classify_nested_response(status, b"not json", ("project", "owner", "email"))[0] is expected
    )


def test_programmatic_enable_mode_context_and_forgery_gates(scan_contexts, monkeypatch):
    result = scan_contexts()
    contexts = tuple(NamedAuthContext(item.name) for item in result.contexts)
    preview = prepare_nested_authorization(result)
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid request"))
    for enabled in (False, 1, "yes"):
        assert not execute_nested_authorization(result, contexts=contexts, enabled=enabled).evidence
    for changes in (
        {"query": "mutation { deleteUser }"},
        {"query": "{ a: project { id } }"},
        {"selection_depth": 9},
        {"list_edges": 2},
        {"path": ("owner", "different")},
    ):
        forged = replace(preview, candidates=(replace(preview.candidates[0], **changes),))
        executed = execute_nested_authorization(
            result, contexts=contexts, enabled=True, preview=forged
        )
        assert not executed.evidence and all(
            "INVALID_ARTIFACT" in item.reason for item in executed.executions
        )
    forged = deepcopy(preview.candidates[0])
    forged.base.variables["id"] = "other"
    assert not execute_nested_authorization(
        result, contexts=contexts, enabled=True, preview=replace(preview, candidates=(forged,))
    ).evidence
    with pytest.raises(HttpConfigurationError):
        execute_nested_authorization(result, contexts=contexts[::-1], enabled=True)
