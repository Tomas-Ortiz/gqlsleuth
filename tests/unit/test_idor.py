"""Bounded plans, exact identity/policy, consent and request provenance; entirely offline."""

import json
from dataclasses import replace

import httpx
import pytest
from graphql import build_schema, parse, validate

from fixtures.phase22_target import SDL
from fixtures.phase25_target import response_for
from gqlsleuth.application import idor as application
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.idor import IdorContextType, IdorPolicyResult
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.sequential_discovery import MAX_PHASE22_IDENTIFIER, parse_discovery_seeds
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings

SECRET = "PHASE25_CONTEXT_SECRET"


@pytest.fixture
def active(phase_ten_scan):
    return phase_ten_scan(SDL)[0]


@pytest.fixture
def wire(monkeypatch):
    requests = []
    controls = {"scenario": "open", "override": {}, "network": set()}

    def handler(request):
        payload = json.loads(request.content)
        requests.append(request)
        identifier = payload["variables"]["id"]
        assert "learned" not in request.headers.get("cookie", "")
        if identifier in controls["network"]:
            raise httpx.ConnectError(SECRET, request=request)
        body = controls["override"].get(
            identifier,
            response_for(
                request.method,
                payload,
                scenario=controls["scenario"],
                authenticated=bool(request.headers.get("authorization")),
            ),
        )
        return httpx.Response(200, json=body, headers={"set-cookie": "learned=private"})

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(
            settings,
            transport=httpx.MockTransport(handler),
        ),
    )
    return requests, controls


def session(active, authenticated=False, seeds=("123",), **kwargs):
    settings = HttpClientSettings(
        custom_headers=(("Authorization", SECRET),) if authenticated else ()
    )
    return application.IdorSession(
        active,
        seeds=parse_discovery_seeds(["order:id=" + value for value in seeds]),
        enabled=True,
        http_settings=settings,
        context_label="opaque-label" if authenticated else None,
        **kwargs,
    )


@pytest.mark.parametrize("authenticated", [False, True])
@pytest.mark.parametrize(
    "scenario,ids,anonymous,authenticated_results",
    [
        (
            "open",
            ["123", "122", "124"],
            ["violated", "satisfied", "violated"],
            ["baseline_confirmed", "satisfied", "violated"],
        ),
        ("denied", ["123"], ["satisfied"], ["baseline_unusable"]),
        (
            "protected",
            ["123", "122", "124"],
            ["violated", "satisfied", "satisfied"],
            ["baseline_confirmed", "satisfied", "satisfied"],
        ),
        ("unusable", ["123"], ["unresolved"], ["baseline_unusable"]),
        (
            "mismatch",
            ["123", "122", "124"],
            ["violated", "satisfied", "unresolved"],
            ["baseline_confirmed", "satisfied", "unresolved"],
        ),
    ],
)
def test_policy_matrix_and_findings(
    active, wire, authenticated, scenario, ids, anonymous, authenticated_results
):
    requests, controls = wire
    controls["scenario"] = scenario
    workflow = session(active, authenticated)
    assert not requests
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert [json.loads(req.content)["variables"]["id"] for req in requests] == ids
    expected = authenticated_results if authenticated else anonymous
    assert [item.policy_result.value for item in result.executions if item.attempted] == expected
    assert result.attempted_request_count == len(result.evidence) == len(ids)
    assert len(result.findings) == expected.count("violated")
    for evidence in result.evidence:
        assert evidence.evidence_type is EvidenceType.IDOR_BOLA_PROBE
        assert evidence.execution_mode is ScanMode.ACTIVE
        assert evidence.variables == {"id": evidence.requested_identifier}
        assert evidence.response_status_code == 200 and evidence.response_body
        assert evidence.request_method == "POST" and evidence.duration_seconds >= 0
        assert evidence.source_evidence_ids
        assert "operationName" not in json.loads(requests[0].content)
    for finding in result.findings:
        assert finding.finding_type == "object_level_authorization_failure"
        assert finding.expected == "deny" and finding.provenance.value == "operator_supplied"
        evidence = next(item for item in result.evidence if item.evidence_id == finding.evidence_id)
        assert finding.identifier == evidence.requested_identifier
        assert evidence.policy_result is IdorPolicyResult.VIOLATED
        if authenticated:
            assert finding.baseline_evidence_id == result.evidence[0].evidence_id
            assert finding.baseline_evidence_id in finding.source_evidence_ids
        else:
            assert finding.baseline_evidence_id is None
        assert not any(hasattr(finding, name) for name in ("severity", "cvss", "cwe", "owner"))
    assert all((req.headers.get("authorization") == SECRET) is authenticated for req in requests)
    assert SECRET not in repr(result)
    assert workflow.execute(preview=workflow.preview, confirmed=True) == result
    assert len(requests) == len(ids)


@pytest.mark.parametrize("failed,ids", [("123", ["123"]), ("122", ["123", "122", "124"])])
@pytest.mark.parametrize("authenticated", [False, True])
def test_network_failures_consume_budget_continue_only_eligible(
    active, wire, failed, ids, authenticated
):
    requests, controls = wire
    controls["network"].add(failed)
    workflow = session(active, authenticated)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert [json.loads(item.content)["variables"]["id"] for item in requests] == ids
    failure = next(item for item in result.evidence if item.requested_identifier == failed)
    assert failure.outcome.value == "network_failure"
    assert failure.error_message == "Target transport failed."
    assert SECRET not in repr(result)
    assert not any(item.identifier == failed for item in result.findings)


@pytest.mark.parametrize(
    "seed,ids",
    [
        ("0", ["0", "1"]),
        (
            str(MAX_PHASE22_IDENTIFIER),
            [str(MAX_PHASE22_IDENTIFIER), str(MAX_PHASE22_IDENTIFIER - 1)],
        ),
    ],
)
def test_shared_bounds_no_requests_during_planning(active, wire, seed, ids):
    workflow = session(active, seeds=(seed,))
    assert [probe.requested_identifier for probe in workflow.preview.probes] == ids
    assert not wire[0]
    for probe in workflow.preview.probes:
        assert not validate(build_schema(SDL), parse(probe.query))
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert result.attempted_request_count == len(ids)


def test_shared_six_request_limit_no_expansion(active, wire):
    workflow = session(active, seeds=("10", "20"))
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert result.attempted_request_count == 6
    assert [json.loads(item.content)["variables"]["id"] for item in wire[0]] == [
        "10",
        "9",
        "11",
        "20",
        "19",
        "21",
    ]
    workflow.execute(preview=workflow.preview, confirmed=True)
    assert len(wire[0]) == 6


@pytest.mark.parametrize("confirmed", [False, 1, "yes"])
def test_strict_consent_zero_attempts(active, wire, confirmed):
    workflow = session(active)
    result = workflow.execute(preview=workflow.preview, confirmed=confirmed)
    assert not wire[0] and not result.evidence and not result.findings


@pytest.mark.parametrize(
    "mode,enabled", [(ScanMode.SAFE, True), (ScanMode.ACTIVE, False), (ScanMode.ACTIVE, 1)]
)
def test_independent_gate(phase_ten_scan, mode, enabled):
    safe = phase_ten_scan(SDL, mode=mode)[0]
    result = application.prepare_idor_detection(
        safe, seeds=parse_discovery_seeds(["order:id=123"]), enabled=enabled
    )
    assert not result.probes and result.limitations


@pytest.mark.parametrize(
    "mutation", ["id", "offset", "context", "ordering", "query", "variable_type"]
)
def test_forged_preview_never_sent(active, wire, mutation):
    workflow = session(active)
    preview = workflow.preview
    probe = preview.probes[0]
    if mutation == "id":
        preview = replace(
            preview, probes=(replace(probe, requested_identifier="999"), *preview.probes[1:])
        )
    elif mutation == "offset":
        preview = replace(preview, probes=(replace(probe, offset=False), *preview.probes[1:]))
    elif mutation == "context":
        preview = replace(preview, context_type=IdorContextType.AUTHENTICATED)
    elif mutation == "ordering":
        preview = replace(preview, probes=tuple(reversed(preview.probes)))
    elif mutation == "query":
        preview = replace(
            preview, probes=(replace(probe, query="mutation { burn }"), *preview.probes[1:])
        )
    else:
        probe.variables["id"] = 123
    result = workflow.execute(preview=preview, confirmed=True)
    assert not wire[0] and not result.evidence and not result.findings


def test_revalidates_between_sends(active, monkeypatch):
    calls = []
    workflow = session(active)
    preview = workflow.preview

    def handler(request):
        calls.append(request)
        active.query_generation.queries[0].variables["id"] = False
        return httpx.Response(200, json={"data": {"order": {"id": "123"}}})

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    result = workflow.execute(preview=preview, confirmed=True)
    assert len(calls) == result.attempted_request_count == 1


@pytest.mark.parametrize("value", [125, True, 124.0, None, "0124"])
def test_exact_alternate_id_no_business_field_inference(active, wire, value):
    wire[1]["override"]["124"] = {"data": {"order": {"id": value, "ownerId": "124", "total": 124}}}
    workflow = session(active, authenticated=True)
    result = workflow.execute(preview=workflow.preview, confirmed=True)
    assert not result.findings
    assert result.executions[-1].policy_result is IdorPolicyResult.UNRESOLVED


def test_integer_json_id_uses_existing_semantics(active, wire):
    wire[1]["override"]["124"] = {"data": {"order": {"id": 124}}}
    workflow = session(active, authenticated=True)
    assert len(workflow.execute(preview=workflow.preview, confirmed=True).findings) == 1


@pytest.mark.parametrize(
    "entries",
    [
        [],
        ["order:id=1"] * 3,
        ["order:id=01"],
        ["order:id=-1"],
        ["order:id=UUID"],
        [f"order:id={MAX_PHASE22_IDENTIFIER + 1}"],
    ],
)
def test_same_seed_parser_rejects_invalid_entries(entries):
    with pytest.raises(HttpConfigurationError):
        parse_discovery_seeds(entries)


@pytest.mark.parametrize(
    "root,output",
    [
        ("order(id: [ID]): Order", "type Order { id: ID }"),
        ("order(filter: Input): Order", "input Input { id: ID } type Order { id: ID }"),
        ("order(id: ID): [Order]", "type Order { id: ID }"),
        ("order(id: ID): Order", "type Order { other: ID }"),
        ("order(id: ID): Order", "interface Order { id: ID } type A implements Order { id: ID }"),
        ("other: String", "type Mutation { order(id: ID): Order } type Order { id: ID }"),
        ("other: String", "type Subscription { order(id: ID): Order } type Order { id: ID }"),
    ],
)
def test_shared_structural_gate(phase_ten_scan, root, output):
    scan = phase_ten_scan(f"type Query {{ {root} }} {output}")[0]
    assert not session(scan).preview.probes


def test_actual_ast_variable_mapping_preserved(phase_ten_scan):
    safe = phase_ten_scan(
        "type Query { order(id: ID, email: String!): Order } type Order { id: ID! total: Float }"
    )[0]
    original = {"identifier": "1", "email": "test@example.com", "show": True}
    query = (
        "query($identifier:ID,$email:String!,$show:Boolean!)"
        "{order(id:$identifier,email:$email){total @include(if:$show)}}"
    )
    artifact = replace(safe.query_generation.queries[0], query_text=query, variables=original)
    safe = replace(safe, query_generation=replace(safe.query_generation, queries=(artifact,)))
    for probe in session(safe).preview.probes:
        assert probe.variables == {**original, "identifier": probe.requested_identifier}
        assert "@include" in probe.query and "total" in probe.query
    assert original["identifier"] == "1"
