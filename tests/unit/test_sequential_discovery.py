"""Local numeric bounds, shared object eligibility/AST behavior and defensive request gates."""

import json
from dataclasses import replace

import httpx
import pytest
from graphql import build_schema, parse, validate

from fixtures.phase22_target import SDL, response_for
from gqlsleuth.application import sequential_discovery as application
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.object_authorization import ObjectOutcome
from gqlsleuth.domain.sequential_discovery import MAX_PHASE22_IDENTIFIER, parse_discovery_seeds
from gqlsleuth.infrastructure.http import HttpClient


@pytest.fixture
def active(phase_ten_scan):
    return phase_ten_scan(SDL)[0]


@pytest.fixture
def transport(monkeypatch):
    requests = []
    overrides = {}

    def handler(request):
        payload = json.loads(request.content)
        requests.append((payload, dict(request.headers)))
        identifier = payload["variables"]["id"]
        assert "learned" not in request.headers.get("cookie", "")
        if overrides.get(identifier) == "network":
            raise httpx.ConnectError("PHASE22_TRANSPORT_SECRET", request=request)
        response = overrides.get(identifier)
        if response is None:
            response = response_for(request.method, payload)
        return httpx.Response(200, json=response, headers={"set-cookie": "learned=one-request"})

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    return requests, overrides


@pytest.mark.parametrize(
    "entry",
    [
        "order:id=",
        "order=123",
        "extra:order:id=123",
        "9order:id=123",
        "order:bad-name=123",
        "order:id=00123",
        "order:id=-1",
        "order:id=+1",
        "order:id=12.3",
        "order:id=0x7b",
        "order:id=1e3",
        "order:id= 123",
        "order:id=123 ",
        "order:id=123=4",
        "order:id=１２３",
        "order:id=550e8400-e29b-41d4-a716-446655440000",
        "order:id=" + str(2**63),
        "order:id=" + "9" * 65,
        "order:id=PHASE22_SECRET\r",
        "order:id=PHASE22_SECRET\n",
        "order:id=PHASE22_SECRET\x00",
        "order:id=PHASE22_SECRET\t",
    ],
)
def test_invalid_seeds_hide_values(entry):
    with pytest.raises(HttpConfigurationError) as error:
        parse_discovery_seeds([entry])
    assert "idor-seed #1" in str(error.value)
    assert "PHASE22_SECRET" not in str(error.value)


def test_seed_count_and_input_order():
    assert [item.identifier for item in parse_discovery_seeds(["order:id=42", "order:id=1"])] == [
        "42",
        "1",
    ]
    for entries in ([], ["order:id=1"] * 3):
        with pytest.raises(HttpConfigurationError):
            parse_discovery_seeds(entries)


@pytest.mark.parametrize(
    "seed,ids",
    [
        ("123", ["123", "122", "124"]),
        ("0", ["0", "1"]),
        (
            str(MAX_PHASE22_IDENTIFIER),
            [str(MAX_PHASE22_IDENTIFIER), str(MAX_PHASE22_IDENTIFIER - 1)],
        ),
    ],
)
def test_local_derivation_and_syntax(active, monkeypatch, seed, ids):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Preparation sent HTTP"))
    seeds = parse_discovery_seeds(["order:id=" + seed])
    first = application.prepare_sequential_discovery(active, seeds=seeds, enabled=True)
    assert first == application.prepare_sequential_discovery(active, seeds=seeds, enabled=True)
    assert [probe.requested_identifier for probe in first.probes] == ids
    assert not first.evidence and not first.executions
    for probe in first.probes:
        assert probe.variables == {"id": probe.requested_identifier}
        assert not validate(build_schema(SDL), parse(probe.query))
        assert probe.response_id_path == ("order", "id")
        assert probe.source_evidence_ids


@pytest.mark.parametrize(
    "query_type,output",
    [
        ("order(id: [ID]): Order", "type Order { id: ID }"),
        ("order(id: String!): Order", "type Order { id: ID }"),
        ("order(filter: Filter): Order", "input Filter { id: ID } type Order { id: ID }"),
        ("order(id: ID!): [Order]", "type Order { id: ID }"),
        ("order(id: ID!): Order", "type Order { key: ID }"),
        ("order(id: ID!): Order", "type Order { id: String }"),
        ("order(id: ID!): Order", "interface Order { id: ID } type A implements Order { id: ID }"),
        ("order(id: ID!): Order", "union Order = A type A { id: ID }"),
        ("other: String", "type Mutation { order(id:ID!): Order } type Order { id:ID }"),
        ("other: String", "type Subscription { order(id:ID!): Order } type Order { id:ID }"),
    ],
)
def test_unsupported_structure(phase_ten_scan, query_type, output):
    safe = phase_ten_scan(f"type Query {{ {query_type} }} {output}")[0]
    preview = application.prepare_sequential_discovery(
        safe, seeds=parse_discovery_seeds(["order:id=123"]), enabled=True
    )
    assert not preview.probes and preview.limitations


def test_missing_schema_and_safe_mode_never_derive_ids(active, phase_ten_scan):
    seeds = parse_discovery_seeds(["order:id=123"])
    schema_scan = active.query_generation.operation_analysis.schema_scan
    missing = replace(
        active,
        query_generation=replace(
            active.query_generation,
            operation_analysis=replace(
                active.query_generation.operation_analysis,
                schema_scan=replace(schema_scan, schemas=()),
            ),
        ),
    )
    assert application.prepare_sequential_discovery(missing, seeds=seeds, enabled=True).limitations
    safe = phase_ten_scan(SDL, mode=ScanMode.SAFE)[0]
    for scan, enabled in ((safe, True), (active, False), (active, 1)):
        result = application.prepare_sequential_discovery(scan, seeds=seeds, enabled=enabled)
        assert not result.probes


@pytest.mark.parametrize("id_type", ["ID", "ID!"])
def test_ast_mapping_only_selected_variable_changes(phase_ten_scan, id_type):
    sdl = (
        f"type Query {{ order(id: {id_type}, email: String!): Order }} "
        "type Order { id: ID! total: Float }"
    )
    safe = phase_ten_scan(sdl)[0]
    variables = {"objectIdentifier": "1", "email": "test@example.com", "show": True}
    document = (
        f"query($objectIdentifier:{id_type},$email:String!,$show:Boolean!)"
        "{order(id:$objectIdentifier,email:$email){total @include(if:$show)}}"
    )
    artifact = replace(safe.query_generation.queries[0], query_text=document, variables=variables)
    safe = replace(safe, query_generation=replace(safe.query_generation, queries=(artifact,)))
    result = application.prepare_sequential_discovery(
        safe, seeds=parse_discovery_seeds(["order:id=123"]), enabled=True
    )
    assert len(result.probes) == 3
    assert len({probe.query for probe in result.probes}) == 1
    for probe in result.probes:
        assert probe.variables == {**variables, "objectIdentifier": probe.requested_identifier}
        root = parse(probe.query).definitions[0].selection_set.selections[0]
        assert root.selection_set.selections[0].directives[0].name.value == "include"
        assert root.selection_set.selections[-1].name.value == "id"
    assert artifact.variables == variables


@pytest.mark.parametrize(
    "document",
    [
        "mutation { updateOrder(id:1){id} }",
        "subscription { order(id:1){id} }",
        "query { order(id:1){id} } query { order(id:1){id} }",
        "query { a:order(id:1){id} }",
        "query { order(id:1){a:id} }",
        "query { order(id:1){...F} } fragment F on Order { id }",
    ],
)
def test_invalid_source_documents(active, document):
    artifact = replace(active.query_generation.queries[0], query_text=document, variables={})
    active = replace(active, query_generation=replace(active.query_generation, queries=(artifact,)))
    assert not application.prepare_sequential_discovery(
        active, seeds=parse_discovery_seeds(["order:id=123"]), enabled=True
    ).probes


@pytest.mark.parametrize(
    "seed,ids,outcomes,candidates",
    [
        ("123", ["123", "122", "124"], ["target_returned", "indeterminate", "target_returned"], 1),
        ("200", ["200"], ["indeterminate"], 0),
        (
            "500",
            ["500", "499", "501"],
            ["target_returned", "explicit_denial", "explicit_denial"],
            0,
        ),
        ("499", ["499"], ["explicit_denial"], 0),
        ("0", ["0", "1"], ["target_returned", "target_returned"], 1),
        ("1234", ["1234", "1233", "1235"], ["target_returned"] * 3, 2),
    ],
)
def test_baseline_first_exact_sets_and_evidence(active, transport, seed, ids, outcomes, candidates):
    result = application.execute_sequential_discovery(
        active, seeds=parse_discovery_seeds(["order:id=" + seed]), enabled=True, confirmed=True
    )
    requests, _ = transport
    assert [payload["variables"]["id"] for payload, _ in requests] == ids
    assert result.attempted_request_count == len(result.evidence) == len(ids)
    assert [item.outcome.value for item in result.executions if item.attempted] == outcomes
    assert len(result.candidates) == candidates
    for execution in result.executions:
        if not execution.attempted:
            assert execution.evidence is None
            continue
        evidence = execution.evidence
        assert evidence.execution_mode is ScanMode.ACTIVE
        assert evidence.offset == execution.probe.offset
        assert evidence.operator_seed == seed
        assert evidence.query == execution.probe.query
        assert evidence.variables == execution.probe.variables
        assert evidence.request_method == "POST" and evidence.response_status_code == 200
        assert evidence.response_body and evidence.response_headers
        assert evidence.timestamp and evidence.duration_seconds >= 0
    for candidate in result.candidates:
        assert result.evidence[0].evidence_id in candidate.source_evidence_ids


@pytest.mark.parametrize("failure,ids", [("123", ["123"]), ("122", ["123", "122", "124"])])
def test_transport_failures_are_counted_and_isolated(active, transport, failure, ids):
    requests, overrides = transport
    overrides[failure] = "network"
    result = application.execute_sequential_discovery(
        active, seeds=parse_discovery_seeds(["order:id=123"]), enabled=True, confirmed=True
    )
    assert [payload["variables"]["id"] for payload, _ in requests] == ids
    assert result.attempted_request_count == len(ids)
    assert any(item.outcome is ObjectOutcome.NETWORK_FAILURE for item in result.executions)
    assert "PHASE22_TRANSPORT_SECRET" not in repr(result)


def test_two_seed_budget_order_and_no_response_harvesting(active, transport):
    requests, overrides = transport
    for identifier in ("123", "122", "124", "800", "799", "801"):
        overrides[identifier] = {
            "data": {
                "order": {
                    "id": identifier,
                    "customerId": "991",
                    "ownerId": "992",
                    "relatedOrderId": "993",
                    "nested": {"id": "994"},
                    "ids": ["995"],
                }
            }
        }
    seeds = parse_discovery_seeds(["order:id=123", "order:id=800"])
    result = application.execute_sequential_discovery(
        active, seeds=seeds, enabled=True, confirmed=True
    )
    assert [payload["variables"]["id"] for payload, _ in requests] == [
        "123",
        "122",
        "124",
        "800",
        "799",
        "801",
    ]
    assert len(requests) == len(result.evidence) == 6
    assert len(result.candidates) == 4
    assert all(set(payload) == {"query", "variables"} for payload, _ in requests)
    with pytest.raises(HttpConfigurationError):
        application.execute_sequential_discovery(
            active, seeds=seeds + (replace(seeds[0], index=3),), enabled=True, confirmed=True
        )
    assert len(requests) == 6


@pytest.mark.parametrize(
    "change",
    [
        "identifier",
        "offset",
        "variable",
        "query",
        "endpoint",
        "root",
        "seed",
        "duplicate",
        "reorder",
        "boolean",
    ],
)
def test_forged_previews_send_zero_requests(active, transport, change):
    seeds = parse_discovery_seeds(["order:id=123"])
    preview = application.prepare_sequential_discovery(active, seeds=seeds, enabled=True)
    probe = preview.probes[0]
    changes = {
        "identifier": {"requested_identifier": "999"},
        "offset": {"offset": 2},
        "variable": {"variables": {"id": "999"}},
        "query": {"query": "query { order(id:999){id} }"},
        "endpoint": {"endpoint": "https://other.example/graphql"},
        "root": {"response_id_path": ("other", "id")},
        "seed": {"seed": replace(seeds[0], identifier="999")},
        "boolean": {"offset": False},
    }
    if change in changes:
        preview = replace(preview, probes=(replace(probe, **changes[change]), *preview.probes[1:]))
    elif change == "duplicate":
        preview = replace(preview, probes=preview.probes + (probe,))
    else:
        preview = replace(preview, probes=tuple(reversed(preview.probes)))
    result = application.execute_sequential_discovery(
        active, seeds=seeds, enabled=True, confirmed=True, preview=preview
    )
    assert not result.evidence and not transport[0]


@pytest.mark.parametrize("enabled,confirmed", [(False, True), (True, False), (True, 1), (1, True)])
def test_strict_opt_in_and_confirmation(active, transport, enabled, confirmed):
    result = application.execute_sequential_discovery(
        active, seeds=parse_discovery_seeds(["order:id=123"]), enabled=enabled, confirmed=confirmed
    )
    assert not result.evidence and not transport[0]


@pytest.mark.parametrize(
    "returned,expected",
    [
        ("124", "target_returned"),
        (124, "target_returned"),
        ("125", "indeterminate"),
        (None, "indeterminate"),
        (True, "indeterminate"),
        ({}, "indeterminate"),
    ],
)
def test_shared_identity_semantics_and_business_independence(active, transport, returned, expected):
    _, overrides = transport
    outcomes = []
    for business in (
        {"total": 1, "role": "a"},
        {"total": 999, "role": "b", "email": "test@example.com", "account": "other"},
    ):
        root = {**business, **({"id": returned} if returned != {} else {})}
        overrides["124"] = {"data": {"order": root}}
        result = application.execute_sequential_discovery(
            active, seeds=parse_discovery_seeds(["order:id=123"]), enabled=True, confirmed=True
        )
        outcomes.append((tuple(item.outcome for item in result.executions), len(result.candidates)))
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0][-1].value == expected
