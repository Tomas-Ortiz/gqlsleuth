"""Offline active-mode gates, sequential transport, hard limits, and exact evidence."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from threading import get_ident

import httpx
import pytest

from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.active import MutationDecision
from gqlsleuth.domain.exceptions import GQLSleuthError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.infrastructure.http import HttpClient


def _unexpected(request):
    raise AssertionError(f"Unexpected request: {request.method}")


@pytest.mark.parametrize(
    ("select", "confirmed"), [(False, False), (False, True), (True, False), (True, "yes")]
)
def test_explicit_selection_and_boolean_confirmation_are_both_required(
    phase_ten_scan, select, confirmed
):
    safe, _ = phase_ten_scan()
    preview = prepare_active_mutations(safe)
    selected = (
        tuple(i for i, item in enumerate(preview.candidates, 1) if item.selectable)
        if select
        else ()
    )
    with HttpClient(transport=httpx.MockTransport(_unexpected)) as client:
        result = execute_selected_mutations(
            preview, selected_indices=selected, confirmed=confirmed, client=client
        )
    assert not result.execution_evidence
    assert not any(item.attempted for item in result.executions)
    for item in result.executions:
        if item.preview.selectable:
            assert item.decision is (
                MutationDecision.DECLINED if select else MutationDecision.NOT_SELECTED
            )
    assert result.evidence == safe.evidence


def test_safe_mode_cannot_execute_even_with_forged_preview_and_confirmation(phase_ten_scan):
    active, _ = phase_ten_scan()
    safe, _ = phase_ten_scan(mode=ScanMode.SAFE)
    preview = replace(prepare_active_mutations(active), safe_execution=safe)
    with HttpClient(transport=httpx.MockTransport(_unexpected)) as client:
        result = execute_selected_mutations(
            preview,
            selected_indices=tuple(range(1, len(preview.candidates) + 1)),
            confirmed=True,
            client=client,
        )
    assert all(item.decision is MutationDecision.MODE_DISABLED for item in result.executions)
    assert not result.execution_evidence


def test_blocked_selection_and_forged_selectable_decision_cannot_send(phase_ten_scan):
    safe, _ = phase_ten_scan()
    preview = prepare_active_mutations(safe)
    blocked = tuple(
        replace(item, decision=MutationDecision.EXECUTABLE)
        for item in preview.candidates
        if item.decision is MutationDecision.BLOCKED_SAFETY
    )
    preview = replace(preview, candidates=blocked)
    with HttpClient(transport=httpx.MockTransport(_unexpected)) as client:
        result = execute_selected_mutations(
            preview,
            selected_indices=tuple(range(1, len(blocked) + 1)),
            confirmed=True,
            client=client,
        )
    assert all(item.decision is MutationDecision.BLOCKED_SAFETY for item in result.executions)
    assert not result.execution_evidence


@pytest.mark.parametrize(
    "tamper", ["query", "metadata", "endpoint", "root_field", "generation_failure"]
)
def test_execution_revalidates_forged_artifacts_before_http(phase_ten_scan, tamper):
    safe, _ = phase_ten_scan()
    original = prepare_active_mutations(safe)
    item = next(item for item in original.candidates if item.selectable)
    artifact = item.generated_mutation
    if tamper == "query":
        artifact = replace(artifact, query_text="query { health }")
    elif tamper == "metadata":
        artifact = replace(artifact, operation=replace(artifact.operation, interest_score=999))
    elif tamper == "endpoint":
        artifact = replace(
            artifact, operation=replace(artifact.operation, endpoint="https://example.com/other")
        )
    elif tamper == "root_field":
        artifact = replace(artifact, query_text="mutation { missing }")
    else:
        artifact = replace(artifact, query_text=None, failure_reason="failed")
    preview = replace(original, candidates=(replace(item, generated_mutation=artifact),))
    with HttpClient(transport=httpx.MockTransport(_unexpected)) as client:
        result = execute_selected_mutations(
            preview, selected_indices=(1,), confirmed=True, client=client
        )
    assert not result.execution_evidence
    assert not result.executions[0].attempted


def test_selected_request_and_evidence_preserve_exact_facts(phase_ten_scan):
    safe, _ = phase_ten_scan()
    preview = prepare_active_mutations(safe)
    index = next(
        i
        for i, item in enumerate(preview.candidates, 1)
        if item.generated_mutation.operation_name == "createUser"
    )
    artifact = preview.candidates[index - 1].generated_mutation
    requests = []
    body = b'{"data":{"createUser":"created"}}'
    started = datetime.now(UTC)

    def handler(request):
        requests.append(request)
        return httpx.Response(200, content=body, headers={"x-request-id": "test-request"})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = execute_selected_mutations(
            preview, selected_indices=(index,), confirmed=True, client=client
        )
    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert str(requests[0].url) == artifact.endpoint
    assert json.loads(requests[0].content) == {
        "query": artifact.query_text,
        "variables": artifact.variables,
    }
    evidence = result.execution_evidence[0]
    assert evidence.evidence_type is EvidenceType.MUTATION_EXECUTION
    assert evidence.execution_mode is ScanMode.ACTIVE
    assert evidence.execution_status is QueryExecutionStatus.SUCCESS
    assert evidence.operation == artifact.operation
    assert evidence.query == artifact.query_text
    assert evidence.variables == {"id": "1"}
    assert evidence.endpoint == artifact.endpoint
    assert evidence.request_method == "POST"
    assert evidence.response_status_code == 200
    assert evidence.response_headers["x-request-id"] == "test-request"
    assert evidence.response_body == body
    assert evidence.duration_seconds >= 0
    assert started <= evidence.timestamp <= datetime.now(UTC)
    assert evidence.error_type is None
    assert result.safe_execution is safe
    assert result.evidence == safe.evidence + result.execution_evidence
    assert {item.evidence_type for item in safe.evidence} >= {
        EvidenceType.ENDPOINT_CANDIDATE,
        EvidenceType.GRAPHQL_CONFIRMATION,
        EvidenceType.INTROSPECTION_RESULT,
        EvidenceType.SCHEMA_ARTIFACT,
        EvidenceType.INTERESTING_OPERATION,
        EvidenceType.GENERATED_QUERY,
        EvidenceType.QUERY_EXECUTION,
    }
    artifact.variables["id"] = "changed-after-execution"
    assert evidence.variables == {"id": "1"}


def test_five_request_limit_order_sequential_errors_and_duplicate_indices(phase_ten_scan):
    safe, _ = phase_ten_scan(
        "type Query { health: String } type Mutation { "
        + " ".join(f"action{i}: String" for i in range(8))
        + " }"
    )
    original = prepare_active_mutations(safe)
    preview = replace(original, candidates=tuple(reversed(original.candidates)))
    requested = []
    thread_ids = []

    def handler(request):
        requested.append(json.loads(request.content)["query"])
        thread_ids.append(get_ident())
        if len(requested) == 1:
            return httpx.Response(
                200, json={"data": None, "errors": [{"message": "Placeholder rejected"}]}
            )
        if len(requested) == 2:
            raise httpx.ReadTimeout("offline", request=request)
        if len(requested) == 3:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(200, json={"data": None})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = execute_selected_mutations(
            preview, selected_indices=(8, 7, 6, 5, 4, 3, 2, 1, 8), confirmed=True, client=client
        )
    assert requested == [item.generated_mutation.query_text for item in original.candidates[:5]]
    assert thread_ids == [get_ident()] * 5
    assert [item.status for item in result.executions[:5]] == [
        QueryExecutionStatus.GRAPHQL_ERROR,
        QueryExecutionStatus.NETWORK_FAILURE,
        QueryExecutionStatus.NETWORK_FAILURE,
        QueryExecutionStatus.SUCCESS,
        QueryExecutionStatus.SUCCESS,
    ]
    assert all(item.decision is MutationDecision.SKIPPED_LIMIT for item in result.executions[5:])
    assert len(result.execution_evidence) == 5
    assert result.execution_evidence[1].error_type == "HttpTimeoutError"
    assert result.execution_evidence[2].error_type == "HttpTransportError"
    assert all(item.duration_seconds >= 0 for item in result.execution_evidence)
    assert result.execution_evidence[1].response_body is None


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (200, b'{"data":null}', QueryExecutionStatus.SUCCESS),
        (200, b'{"data":null,"errors":[]}', QueryExecutionStatus.SUCCESS),
        (
            200,
            b'{"data":{"x":1},"errors":[{"message":"partial"}]}',
            QueryExecutionStatus.GRAPHQL_ERROR,
        ),
        (400, b'{"errors":[{"message":"invalid input"}]}', QueryExecutionStatus.GRAPHQL_ERROR),
        (500, b"server failed", QueryExecutionStatus.HTTP_ERROR),
        (200, b"<html>not graphql</html>", QueryExecutionStatus.INVALID_RESPONSE),
    ],
)
def test_phase_nine_classifier_semantics_apply_to_mutations(phase_ten_scan, status, body, expected):
    safe, _ = phase_ten_scan("type Query { health: String } type Mutation { create: String }")
    with HttpClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(status, content=body))
    ) as client:
        result = execute_selected_mutations(
            prepare_active_mutations(safe), selected_indices=(1,), confirmed=True, client=client
        )
    assert result.executions[0].status is expected
    assert result.execution_evidence[0].execution_status is expected


def test_safe_and_active_phase_nine_query_workflows_are_identical(phase_ten_scan):
    safe, safe_requests = phase_ten_scan(mode=ScanMode.SAFE)
    active, active_requests = phase_ten_scan(mode=ScanMode.ACTIVE)
    assert safe_requests == active_requests
    assert safe.query_generation.queries == active.query_generation.queries
    assert [(item.status, item.attempted) for item in safe.executions] == [
        (item.status, item.attempted) for item in active.executions
    ]
    assert all(
        item.evidence_type is not EvidenceType.MUTATION_EXECUTION
        for item in safe.evidence + active.evidence
    )
    assert not prepare_active_mutations(safe).candidates
    assert prepare_active_mutations(active).candidates


def test_unknown_selection_is_controlled_and_sends_nothing(phase_ten_scan):
    safe, _ = phase_ten_scan()
    with (
        HttpClient(transport=httpx.MockTransport(_unexpected)) as client,
        pytest.raises(GQLSleuthError, match="unknown candidate"),
    ):
        execute_selected_mutations(
            prepare_active_mutations(safe),
            selected_indices=(999,),
            confirmed=True,
            client=client,
        )
