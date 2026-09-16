"""Offline witness construction, conservative classification and execution boundaries."""

import json
from copy import deepcopy
from dataclasses import replace

import httpx
import pytest
from graphql import build_schema, parse, validate

from fixtures.phase18_target import SDL, response_for
from gqlsleuth.application.query_depth import execute_query_depth, prepare_query_depth
from gqlsleuth.domain.exceptions import GQLSleuthError, SafeExecutionValidationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.query_depth import QueryDepthDecision as Decision
from gqlsleuth.domain.query_depth import QueryDepthObservation as Observation
from gqlsleuth.graphql.query_depth import classify_depth_response, selection_depth
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings


@pytest.fixture
def preview(phase_ten_scan):
    return prepare_query_depth(phase_ten_scan(SDL)[0])


def test_witness_ast_and_exact_baseline_preserved(preview):
    assert len(preview.candidates) == 1
    item = preview.candidates[0]
    assert item.baseline_depth == 2 and item.probe_depth == 4 and item.list_edges == 1
    assert item.recursive_path == ("Album.user", "User.albums")
    assert item.base.variables == {"id": "1"}
    assert "albums(limit: 1)" in item.query
    assert item.source_evidence_ids
    base, probe = parse(item.base.query_text).definitions[0], parse(item.query).definitions[0]
    assert probe.variable_definitions == base.variable_definitions
    assert probe.selection_set.selections[0].arguments == base.selection_set.selections[0].arguments
    assert not validate(build_schema(SDL), parse(item.query))
    assert prepare_query_depth(preview.safe_execution) == preview


def test_nested_optional_bound_reuses_generation(phase_ten_scan):
    sdl = (
        SDL.replace("albums(limit: Int): [Album]", "albums(options: Options): AlbumsPage")
        + """
    type AlbumsPage { data: [Album] }
    input Options { paginate: Paginate search: String }
    input Paginate { limit: Int page: Int }
    """
    )
    candidate = prepare_query_depth(phase_ten_scan(sdl)[0]).candidates[0]
    assert candidate.probe_depth == 5
    assert "albums(options: {paginate: {limit: 1}})" in candidate.query
    assert "search:" not in candidate.query and "page:" not in candidate.query
    assert not validate(build_schema(sdl), parse(candidate.query))


def test_non_null_wrappers_do_not_double_count_lists(phase_ten_scan):
    candidate = prepare_query_depth(
        phase_ten_scan(SDL.replace("[Album]", "[Album!]!"))[0]
    ).candidates[0]
    assert candidate.list_edges == 1
    result = prepare_query_depth(phase_ten_scan(SDL.replace("[Album]", "[[Album]]"))[0])
    assert not result.candidates and "one composite list" in result.limitations[0]


def test_existing_wrapper_root_bound_preserved(phase_ten_scan):
    sdl = """
    type Query { albums(limit: Int, email: String!): Page }
    type Page { item: Album data: [Album] }
    type Album { id: ID! page: Page }
    """
    # The cycle's only list edge is Page.data; the representative already has limit=1.
    result = prepare_query_depth(phase_ten_scan(sdl)[0])
    assert result.candidates
    candidate = result.candidates[0]
    assert candidate.base.variables == {"email": "test@example.com", "limit": 1}
    assert (
        parse(candidate.query).definitions[0].variable_definitions
        == parse(candidate.base.query_text).definitions[0].variable_definitions
    )


@pytest.mark.parametrize(
    "sdl,reason",
    [
        ("type Query { hello: String }", "no retained"),
        (SDL.replace("albums(limit: Int)", "albums(id: ID!)"), "required nested"),
        (SDL.replace("albums(limit: Int)", "albums"), "no safely reusable"),
        (SDL.replace("user: User", "user: [User]"), "no safely reusable"),
        (SDL.replace("user: User", "deleteUser: User"), "name safety"),
        (SDL.replace("user: User", "user: User @deprecated"), "deprecated"),
        (
            SDL.replace("album(id: ID!): Album", "album(id: ID!, limit: Int): [Album]"),
            "one composite list",
        ),
        (
            "type Query { start: A } type A { id: ID b: B } type B { c: C } "
            "type C { d: D } type D { e: E } type E { a(limit: Int): [A] }",
            "depth 6",
        ),
    ],
)
def test_unsuitable_paths_are_structured_limitations(phase_ten_scan, sdl, reason):
    result = prepare_query_depth(phase_ten_scan(sdl)[0])
    assert not result.candidates
    assert any(reason in item for item in result.limitations)


def test_preparation_is_local_and_requires_retained_review(preview, monkeypatch):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Preparation HTTP"))
    assert prepare_query_depth(preview.safe_execution) == preview
    no_review = replace(
        preview.safe_execution,
        query_generation=replace(preview.safe_execution.query_generation, security_review=None),
    )
    assert not prepare_query_depth(no_review).candidates
    no_attempt = replace(
        preview.safe_execution,
        executions=tuple(
            replace(item, attempted=False) for item in preview.safe_execution.executions
        ),
    )
    assert not prepare_query_depth(no_attempt).candidates


def test_success_preference_and_meaningful_error_fallback(phase_ten_scan):
    safe = phase_ten_scan(SDL.replace("album(id: ID!): Album", "a(id: ID!): Album b: Album"))[0]
    safe = replace(
        safe,
        executions=tuple(
            replace(item, status=QueryExecutionStatus.GRAPHQL_ERROR)
            if item.operation_name == "a"
            else item
            for item in safe.executions
        ),
    )
    assert prepare_query_depth(safe).candidates[0].base.operation_name == "b"
    safe = replace(
        safe,
        executions=tuple(
            replace(item, status=QueryExecutionStatus.GRAPHQL_ERROR) for item in safe.executions
        ),
    )
    assert prepare_query_depth(safe).candidates[0].base.operation_name == "a"


@pytest.mark.parametrize(
    "query",
    [
        "mutation { album { id } }",
        "subscription { album { id } }",
        "query Named { album { id } }",
        "{ x: album { id } }",
        "{ album { id } album { id } }",
        "{ album { id } } query { album { id } }",
        "{ album { ...X } } fragment X on Album { id }",
        "{ album @skip(if: true) { id } }",
        "{ a { b { c { d { e { f { g } } } } } } }",
    ],
)
def test_metric_rejects_unsupported_shapes(query):
    with pytest.raises(SafeExecutionValidationError):
        selection_depth(parse(query))


def test_metric_counts_terminal_fields():
    assert selection_depth(parse("{ album { user { albums { data { id } } } } }")) == 5
    assert selection_depth(parse("{ album { id user { __typename } } }")) == 3


@pytest.mark.parametrize(
    "selected,confirmed", [((), True), ((1,), False), ((1,), 1), ((1,), "yes"), ((1,), None)]
)
def test_explicit_selection_and_exact_confirmation(preview, selected, confirmed):
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("Unexpected HTTP"))
    ) as client:
        result = execute_query_depth(
            preview, selected_indices=selected, confirmed=confirmed, client=client
        )
    assert not result.evidence
    assert result.executions[0].decision is (
        Decision.DECLINED if selected else Decision.NOT_SELECTED
    )


def test_safe_mode_independently_enforced(preview, phase_ten_scan):
    safe = phase_ten_scan(SDL, mode=ScanMode.SAFE)[0]
    assert not prepare_query_depth(safe).candidates
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("SAFE probe"))
    ) as client:
        result = execute_query_depth(
            replace(preview, safe_execution=safe),
            selected_indices=(1,),
            confirmed=True,
            client=client,
        )
    assert result.executions[0].decision is Decision.MODE_DISABLED
    assert not result.evidence


@pytest.mark.parametrize(
    "change",
    [
        {"query": "mutation { createAlbum { id } }"},
        {"query": "{ wrong { id } }"},
        {"query": "{ a: album { id } }"},
        {"probe_depth": 7},
        {"list_edges": 2},
        {"recursive_path": ("other",)},
        {"source_evidence_ids": ()},
    ],
)
def test_altered_candidates_do_not_execute(preview, change):
    forged = replace(preview, candidates=(replace(preview.candidates[0], **change),))
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("Forged HTTP"))
    ) as client:
        result = execute_query_depth(forged, selected_indices=(1,), confirmed=True, client=client)
    assert result.executions[0].decision is Decision.INVALID_ARTIFACT
    assert not result.evidence


def test_altered_variables_rejected(preview):
    candidate = deepcopy(preview.candidates[0])
    candidate.base.variables["id"] = "different"
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("Forged variables"))
    ) as client:
        result = execute_query_depth(
            replace(preview, candidates=(candidate,)),
            selected_indices=(1,),
            confirmed=True,
            client=client,
        )
    assert result.executions[0].decision is Decision.INVALID_ARTIFACT


@pytest.mark.parametrize("index", [0, 2, True, "1", -1])
def test_unknown_indices(preview, index):
    with pytest.raises(GQLSleuthError):
        execute_query_depth(preview, selected_indices=(index,), confirmed=True)


@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("accepted", Observation.ACCEPTED),
        ("rejected", Observation.REJECTED),
        ("indeterminate", Observation.INDETERMINATE),
        ("network", Observation.NETWORK_FAILURE),
    ],
)
def test_exact_single_post_evidence_no_retry(preview, scenario, expected):
    requests = []
    bodies = []

    def handler(request):
        requests.append(json.loads(request.content))
        assert request.headers["X-Test"] == "PHASE18_FAKE_HEADER"
        assert request.extensions["timeout"]["read"] == 3
        if scenario == "network":
            raise httpx.ConnectError("offline", request=request)
        status, body = response_for("POST", "/" + scenario, requests[-1])
        bodies.append(json.dumps(body).encode())
        return httpx.Response(status, content=bodies[-1], headers={"X-Fact": "retained"})

    with HttpClient(
        HttpClientSettings(custom_headers=(("X-Test", "PHASE18_FAKE_HEADER"),), timeout_seconds=3),
        transport=httpx.MockTransport(handler),
    ) as client:
        result = execute_query_depth(
            preview, selected_indices=(1, 1), confirmed=True, client=client
        )
    assert requests == [{"query": preview.candidates[0].query, "variables": {"id": "1"}}]
    evidence = result.evidence[0]
    assert evidence.observation is expected
    assert evidence.query == requests[0]["query"] and evidence.variables == requests[0]["variables"]
    assert evidence.source_evidence_ids == preview.candidates[0].source_evidence_ids
    assert evidence.baseline_depth == 2 and evidence.probe_depth == 4
    assert evidence.execution_mode is ScanMode.ACTIVE and evidence.request_method == "POST"
    assert evidence.timestamp and evidence.duration_seconds >= 0
    if bodies:
        assert (
            evidence.response_body == bodies[0]
            and evidence.response_headers["x-fact"] == "retained"
        )
    else:
        assert evidence.error_type and evidence.response_body is None


@pytest.mark.parametrize(
    "message,expected",
    [
        ("Maximum query depth exceeded", Observation.REJECTED),
        ("Query is too deep", Observation.REJECTED),
        ("max depth exceeded", Observation.REJECTED),
        ("Query complexity exceeded", Observation.REJECTED),
        ("Query cost exceeded", Observation.REJECTED),
        ("Object not found", Observation.INDETERMINATE),
        ("Invalid identifier", Observation.INDETERMINATE),
        ("queryDepth metadata field is unavailable", Observation.INDETERMINATE),
        ("Internal server error", Observation.INDETERMINATE),
    ],
)
def test_rejection_requires_explicit_rule(message, expected):
    body = json.dumps({"errors": [{"message": message}]}).encode()
    assert classify_depth_response(400, body, "album")[0] is expected


@pytest.mark.parametrize(
    "status,body",
    [
        (200, b"not json"),
        (500, b"error"),
        (200, b'{"data":null}'),
        (200, b'{"data":{"other":null}}'),
        (200, b'{"data":{"album":null},"errors":[{"message":"query is too deep"}]}'),
        (200, b"[" * 2000 + b"]" * 2000),
    ],
)
def test_ambiguous_response_is_indeterminate(status, body):
    assert classify_depth_response(status, body, "album")[0] is Observation.INDETERMINATE
