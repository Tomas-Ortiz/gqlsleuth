"""Offline AST, decision, classification and budget boundaries for Phase 17."""

import json
from copy import deepcopy
from dataclasses import replace

import httpx
import pytest
from graphql import parse, print_ast

from fixtures.phase17_target import SDL, response_for
from gqlsleuth.application.multiplicity import execute_multiplicity, prepare_multiplicity
from gqlsleuth.domain.exceptions import GQLSleuthError, SafeExecutionValidationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.multiplicity import MultiplicityDecision as Decision
from gqlsleuth.domain.multiplicity import MultiplicityObservation as Observation
from gqlsleuth.domain.multiplicity import MultiplicityProbeType as Kind
from gqlsleuth.graphql.multiplicity import ALIAS_NAMES, classify_probe_response, prepare_probe
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings


@pytest.fixture
def preview(phase_ten_scan):
    return prepare_multiplicity(phase_ten_scan(SDL)[0])


def test_ast_only_changes_top_level_aliases_and_preserves_bounds(preview):
    alias, batch = preview.candidates
    base = parse(alias.base.query_text).definitions[0]
    transformed = parse(alias.query).definitions[0]
    assert transformed.variable_definitions == base.variable_definitions
    assert len(transformed.selection_set.selections) == 3
    for name, field in zip(ALIAS_NAMES, transformed.selection_set.selections, strict=True):
        assert field.alias.value == name
        field.alias = None
        assert print_ast(field) == print_ast(base.selection_set.selections[0])
    assert alias.base.variables == {"email": "test@example.com", "limit": 1}
    assert alias.request_json == {"query": alias.query, "variables": alias.base.variables}
    assert (
        batch.request_json
        == [{"query": batch.base.query_text, "variables": batch.base.variables}] * 2
    )
    assert "operationName" not in json.dumps(batch.request_json)
    assert prepare_multiplicity(preview.safe_execution) == preview


@pytest.mark.parametrize(
    "document",
    [
        'query { existing: items(email: "test@example.com") { id } }',
        'mutation { createItem(name: "test") { id } }',
        "subscription { items { id } }",
        "query { items { id } items { id } }",
        "query { items { id } } query { items { id } }",
        "query { wrong { id } }",
        "query { items { id } } fragment Extra on Item { id }",
        "not graphql",
    ],
)
def test_invalid_base_documents(preview, document):
    schema = preview.safe_execution.query_generation.operation_analysis.schema_scan.schemas[
        0
    ].schema
    with pytest.raises(SafeExecutionValidationError):
        prepare_probe(
            schema,
            replace(preview.candidates[0].base, query_text=document),
            Kind.ALIAS_MULTIPLICITY,
        )


@pytest.mark.parametrize(
    "selected,confirmed", [((), True), ((1, 2), False), ((1,), 1), ((1,), "yes"), ((2,), None)]
)
def test_selection_and_strict_confirmation(preview, selected, confirmed):
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("Unexpected HTTP"))
    ) as client:
        result = execute_multiplicity(
            preview, selected_indices=selected, confirmed=confirmed, client=client
        )
    assert not result.evidence


def test_safe_and_preview_make_no_probe_requests(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL, mode=ScanMode.SAFE)[0]
    active = phase_ten_scan(SDL)[0]
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Preparation sent HTTP"))
    assert not prepare_multiplicity(safe).candidates
    active_preview = prepare_multiplicity(active)
    forged = replace(active_preview, safe_execution=safe)
    assert all(
        item.decision is Decision.MODE_DISABLED
        for item in execute_multiplicity(forged, selected_indices=(1, 2), confirmed=True).executions
    )
    assert len(active_preview.candidates) == 2


@pytest.mark.parametrize("selection", [(0,), (3,), (True,), ("1",), (-1,)])
def test_forged_indices_rejected(preview, selection):
    with pytest.raises(GQLSleuthError):
        execute_multiplicity(preview, selected_indices=selection, confirmed=True)


@pytest.mark.parametrize("tamper", ["query", "variables", "bool", "count", "base", "kind"])
def test_forged_candidates_cannot_send_http(preview, tamper):
    candidate = deepcopy(preview.candidates[0])
    if tamper == "query":
        candidate = replace(candidate, query="mutation { createItem { id } }")
    elif tamper in {"variables", "bool"}:
        candidate.request_json["variables"]["limit"] = True if tamper == "bool" else 99
    elif tamper == "count":
        candidate.request_json["query"] = candidate.query.replace("gqlsleuthAlias3", "other")
    elif tamper == "base":
        candidate = replace(candidate, base=replace(candidate.base, variables={"limit": 7}))
    else:
        candidate = replace(candidate, probe_type=candidate.probe_type.value)
    with HttpClient(
        transport=httpx.MockTransport(lambda request: pytest.fail("Forged HTTP"))
    ) as client:
        result = execute_multiplicity(
            replace(preview, candidates=(candidate,)),
            selected_indices=(1,),
            confirmed=True,
            client=client,
        )
    assert result.executions[0].decision is Decision.INVALID_ARTIFACT
    assert not result.evidence


@pytest.mark.parametrize(
    "kind,status,body,expected",
    [
        (Kind.ALIAS_MULTIPLICITY, 200, {"data": dict.fromkeys(ALIAS_NAMES)}, Observation.ACCEPTED),
        (Kind.ALIAS_MULTIPLICITY, 200, {"data": None}, Observation.INDETERMINATE),
        (Kind.ALIAS_MULTIPLICITY, 200, {"data": {"gqlsleuthAlias1": 1}}, Observation.INDETERMINATE),
        (
            Kind.ALIAS_MULTIPLICITY,
            200,
            {"data": dict.fromkeys(ALIAS_NAMES), "errors": [{"message": "Business input"}]},
            Observation.INDETERMINATE,
        ),
        (
            Kind.ALIAS_MULTIPLICITY,
            400,
            {"errors": [{"message": "Aliases not allowed"}]},
            Observation.REJECTED,
        ),
        (
            Kind.HTTP_BATCHING,
            200,
            [{"data": None}, {"errors": [{"message": "Placeholder rejected"}]}],
            Observation.ACCEPTED,
        ),
        (
            Kind.HTTP_BATCHING,
            200,
            [{"errors": [{"message": "Business error"}]}] * 2,
            Observation.ACCEPTED,
        ),
        (Kind.HTTP_BATCHING, 200, [{"data": None}], Observation.INDETERMINATE),
        (Kind.HTTP_BATCHING, 200, [{"data": None}] * 3, Observation.INDETERMINATE),
        (Kind.HTTP_BATCHING, 200, [{"data": None}, {}], Observation.INDETERMINATE),
        (Kind.HTTP_BATCHING, 200, {"data": None}, Observation.INDETERMINATE),
        (
            Kind.HTTP_BATCHING,
            400,
            {"errors": [{"message": "Batching is disabled"}]},
            Observation.REJECTED,
        ),
        (
            Kind.HTTP_BATCHING,
            500,
            {"errors": [{"message": "Internal server error"}]},
            Observation.INDETERMINATE,
        ),
        (
            Kind.HTTP_BATCHING,
            403,
            {"errors": [{"message": "Permission denied"}]},
            Observation.INDETERMINATE,
        ),
        (Kind.HTTP_BATCHING, 200, "HTML", Observation.INDETERMINATE),
    ],
)
def test_observations_are_conservative(kind, status, body, expected):
    assert classify_probe_response(kind, status, json.dumps(body).encode())[0] is expected


@pytest.mark.parametrize("body", [b"not json", b"\xff", b"[" * 2000 + b"]" * 2000])
def test_malformed_and_excessively_nested_responses_are_indeterminate(body):
    for kind in Kind:
        assert classify_probe_response(kind, 200, body)[0] is Observation.INDETERMINATE


@pytest.mark.parametrize(
    "kind,message",
    [
        (Kind.ALIAS_MULTIPLICITY, "User alias value is forbidden"),
        (Kind.HTTP_BATCHING, "Field batchStatus is not supported"),
    ],
)
def test_business_errors_do_not_establish_shape_rejection(kind, message):
    body = json.dumps({"errors": [{"message": message}]}).encode()
    assert classify_probe_response(kind, 400, body)[0] is Observation.INDETERMINATE


@pytest.mark.parametrize("selected", [(1,), (2,), (2, 1, 2, 1)])
def test_exact_requests_sequential_evidence_and_headers(preview, selected):
    requests = []

    def handler(request):
        assert request.headers["X-Test"] == "PHASE17_FAKE_HEADER"
        assert request.headers["Content-Type"] == "application/json"
        assert request.extensions["timeout"]["read"] == 3
        payload = json.loads(request.content)
        requests.append(payload)
        status, body = response_for("POST", "/accepted", payload)
        return httpx.Response(status, json=body, headers={"X-Response": "preserved"})

    settings = HttpClientSettings(
        custom_headers=(("X-Test", "PHASE17_FAKE_HEADER"),), timeout_seconds=3
    )
    with HttpClient(settings, transport=httpx.MockTransport(handler)) as client:
        result = execute_multiplicity(
            preview, selected_indices=selected, confirmed=True, client=client
        )
    assert len(requests) == len(set(selected)) == len(result.evidence)
    assert requests == [
        preview.candidates[index - 1].request_json for index in sorted(set(selected))
    ]
    for evidence, request in zip(result.evidence, requests, strict=True):
        assert evidence.request_json == request
        assert evidence.observation is Observation.ACCEPTED
        assert evidence.response_body and evidence.response_headers["x-response"] == "preserved"
        assert evidence.request_method == "POST" and evidence.duration_seconds >= 0
        assert evidence.execution_mode is ScanMode.ACTIVE


def test_failure_isolated_and_budget_includes_attempts(preview):
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(200, json=[{"data": None}] * 2)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = execute_multiplicity(
            preview, selected_indices=(1, 2), confirmed=True, client=client
        )
    assert len(requests) == 2
    assert [item.observation for item in result.evidence] == [
        Observation.NETWORK_FAILURE,
        Observation.ACCEPTED,
    ]
    assert result.evidence[0].error_type and result.evidence[0].response_body is None


def test_prefer_success_and_never_unattempted_or_unsafe(phase_ten_scan):
    safe = phase_ten_scan("type Query { a: String b: String readAndBurn: String }")[0]
    executions = tuple(
        replace(item, status=QueryExecutionStatus.GRAPHQL_ERROR)
        if item.operation_name == "a"
        else item
        for item in safe.executions
    )
    result = prepare_multiplicity(replace(safe, executions=executions))
    assert all(item.base.operation_name == "b" for item in result.candidates)
    no_attempts = replace(
        safe, executions=tuple(replace(item, attempted=False) for item in safe.executions)
    )
    result = prepare_multiplicity(no_attempts)
    assert not result.candidates and result.limitations
    only_errors = replace(
        safe,
        executions=tuple(
            replace(item, status=QueryExecutionStatus.GRAPHQL_ERROR) for item in safe.executions
        ),
    )
    assert prepare_multiplicity(only_errors).candidates[0].base.operation_name == "a"
