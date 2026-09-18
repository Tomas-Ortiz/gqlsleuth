"""One exact Mutation/ID, generator/AST reuse, strict consent and conservative DENY semantics."""

import json
from copy import deepcopy
from dataclasses import replace

import httpx
import pytest
from graphql import parse, print_ast
from graphql.language.ast import NameNode, VariableNode
from graphql.language.visitor import Visitor, visit

from fixtures.phase23_target import SDL
from gqlsleuth.application import mutation_authorization as application
from gqlsleuth.domain.exceptions import HttpConfigurationError, SafeExecutionValidationError
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.mutation_authorization import parse_mutation_cases
from gqlsleuth.graphql.mutation_authorization import build_mutation_probe
from gqlsleuth.graphql.query_generation import generate_mutation
from gqlsleuth.graphql.schema_parser import load_introspection_schema
from gqlsleuth.infrastructure.http import HttpClient


def session_for(safe, entry="updateOrder:id=123", **kwargs):
    return application.MutationAuthorizationSession(
        safe, cases=parse_mutation_cases([entry]), enabled=True, **kwargs
    )


@pytest.mark.parametrize(
    "value", ["123", "001", "abc123", "550e8400-e29b-41d4-a716-446655440000", "a:b=c", " café "]
)
def test_exact_text_ids(value):
    case = parse_mutation_cases(["updateOrder:id=" + value])[0]
    assert case.identifier == value and case.expected.value == "deny" and case.index == 1


@pytest.mark.parametrize(
    "entries",
    [
        [],
        ["x:id=1", "x:id=1"],
        ["x:id=1", "y:id=2"],
        ["x:id="],
        ["x:id"],
        ["ctx:x:id=1"],
        ["bad-name:id=1"],
        ["x:0id=1"],
        ["x:id=a\r"],
        ["x:id=a\n"],
        ["x:id=a\x00"],
        ["x:id=a\x1f"],
        ["x:id=a\u200b"],
        ["x:id=" + "é" * 129],
    ],
)
def test_invalid_cases_never_echo_values(entries):
    with pytest.raises(HttpConfigurationError) as error:
        parse_mutation_cases(entries)
    assert not any(entry in str(error.value) for entry in entries)


@pytest.mark.parametrize(
    "signature,extra,eligible",
    [
        ("updateOrder(id: ID!): Order", "", True),
        ("updateOrder(key: ID): Order", "", True),
        ("updateOrder(id: [ID!]): Order", "", False),
        ("updateOrder(id: String!): Order", "", False),
        ("updateOrder(id: Input!): Order", "input Input { id: ID! }", False),
        ("updateOrder(id: ID!): [Order]", "", False),
        ("updateOrder(id: ID!): String", "", False),
        ("updateOrder(id: ID!): Node", "interface Node { id: ID }", False),
        ("updateOrder(id: ID!): Result", "union Result = Order", False),
        ("deleteOrder(id: ID!): Order", "", False),
        ("removeOrder(id: ID!): Order", "", False),
    ],
)
def test_structural_gate_is_local(phase_ten_scan, monkeypatch, signature, extra, eligible):
    safe = phase_ten_scan(
        f"type Query {{ health: String }} type Mutation {{ {signature} }} "
        f"type Order {{ id: ID! }} {extra}"
    )[0]
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Unexpected HTTP"))
    name = signature.split("(")[0]
    argument = "key" if "key:" in signature else "id"
    session = session_for(safe, f"{name}:{argument}=abc123")
    assert bool(session.preview.probe) == eligible
    result = session.execute(preview=session.preview, confirmed=False)
    assert result.attempted_request_count == 0 and not result.evidence


@pytest.mark.parametrize("output", ["name: String", "id: String", "id: [ID]", "id(arg: Int): ID"])
def test_output_id_required(phase_ten_scan, output):
    safe = phase_ten_scan(
        "type Query { health: String } type Mutation { updateOrder(id: ID): Order } "
        f"type Order {{ {output} }}"
    )[0]
    assert session_for(safe).preview.probe is None


def test_required_inputs_mapping_and_selection_preserved(phase_ten_scan, monkeypatch):
    safe, requests = phase_ten_scan(SDL)
    original = deepcopy(safe)
    count = len(requests)
    scan = safe.query_generation.operation_analysis.schema_scan
    schema = scan.schemas[0].schema
    native = load_introspection_schema(scan.introspection.introspections[0].full_response.body)
    analysis = next(
        op
        for ep in safe.query_generation.operation_analysis.endpoints
        for op in ep.operations
        if op.name == "updateOrder"
    )
    base = generate_mutation(schema, analysis)

    class Rename(Visitor):
        def enter_variable(self, node, *_):
            if node.name.value == "id":
                return VariableNode(name=NameNode(value="objectIdentifier"))

    document = visit(parse(base.query_text), Rename())
    variables = deepcopy(base.variables)
    variables["objectIdentifier"] = variables.pop("id")
    mapped = replace(base, query_text=print_ast(document), variables=variables)
    case = parse_mutation_cases(["updateOrder:id=abc=123"])[0]
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Generation sent HTTP"))
    query, actual = build_mutation_probe(schema, native, mapped, case)
    assert actual == {**variables, "objectIdentifier": "abc=123"}
    assert actual["input"] == {"name": "Test User", "profile": {"email": "test@example.com"}}
    assert print_ast(parse(query).definitions[0].selection_set) == print_ast(
        document.definitions[0].selection_set
    )
    assert build_mutation_probe(schema, native, mapped, case) == (query, actual)
    assert len(requests) == count and safe == original


@pytest.mark.parametrize(
    "document",
    [
        "query ($id: ID!) { order(id: $id) { id } }",
        "subscription { x }",
        'mutation { updateOrder(id: "1") { id } } mutation { updateOrder(id: "1") { id } }',
        "mutation ($id: ID!) { other: updateOrder(id: $id) { id } }",
        "mutation ($id: ID!) { updateOrder(id: $id) { other: id } }",
        "mutation ($id: ID!) { updateOrder(id: $id) { id } deleteOrder(id: $id) { id } }",
        "mutation ($id: ID!) { deleteOrder(id: $id) { id } }",
    ],
)
def test_forged_ast_rejected(phase_ten_scan, document):
    safe = phase_ten_scan(SDL)[0]
    scan = safe.query_generation.operation_analysis.schema_scan
    schema = scan.schemas[0].schema
    native = load_introspection_schema(scan.introspection.introspections[0].full_response.body)
    analysis = next(
        op
        for ep in safe.query_generation.operation_analysis.endpoints
        for op in ep.operations
        if op.name == "updateOrder"
    )
    base = generate_mutation(schema, analysis)
    with pytest.raises(SafeExecutionValidationError):
        build_mutation_probe(
            schema,
            native,
            replace(base, query_text=document),
            parse_mutation_cases(["updateOrder:id=123"])[0],
        )


@pytest.mark.parametrize(
    "status,body,outcome,policy,match",
    [
        (
            200,
            {"data": {"updateOrder": {"id": "123"}}},
            "target_mutation_returned",
            "violated",
            True,
        ),
        (200, {"data": {"updateOrder": {"id": 123}}}, "target_mutation_returned", "violated", True),
        (200, {"data": {"updateOrder": {"id": "124"}}}, "indeterminate", "unresolved", False),
        (200, {"data": {"updateOrder": {"id": True}}}, "indeterminate", "unresolved", None),
        (200, {"data": {"updateOrder": {"id": 123.0}}}, "indeterminate", "unresolved", None),
        (
            200,
            {"data": {"updateOrder": {"name": "irrelevant"}}},
            "indeterminate",
            "unresolved",
            None,
        ),
        (200, {"data": {"updateOrder": None}}, "indeterminate", "unresolved", None),
        (
            200,
            {"errors": [{"message": "business input rejected"}]},
            "indeterminate",
            "unresolved",
            None,
        ),
        (
            200,
            {
                "errors": [
                    {
                        "message": "denied",
                        "extensions": {"code": "FORBIDDEN"},
                        "path": ["updateOrder"],
                    }
                ]
            },
            "explicit_denial",
            "satisfied",
            None,
        ),
        (
            200,
            {
                "errors": [
                    {"message": "denied", "extensions": {"code": "FORBIDDEN"}, "path": ["other"]}
                ]
            },
            "indeterminate",
            "unresolved",
            None,
        ),
        (
            200,
            {"data": {"updateOrder": {"id": "123"}}, "errors": [{"message": "partial"}]},
            "indeterminate",
            "unresolved",
            True,
        ),
        (401, {}, "explicit_denial", "satisfied", None),
        (403, {}, "explicit_denial", "satisfied", None),
        (400, {}, "indeterminate", "unresolved", None),
        (404, {}, "indeterminate", "unresolved", None),
        (500, {}, "indeterminate", "unresolved", None),
        (200, "not graphql", "indeterminate", "unresolved", None),
    ],
)
def test_outcome_policy_and_exact_evidence(
    phase_ten_scan, monkeypatch, status, body, outcome, policy, match
):
    safe = phase_ten_scan(SDL)[0]
    requests = []
    raw = json.dumps(body).encode()

    def handler(request):
        requests.append(request)
        return httpx.Response(status, content=raw, headers={"X-Test": "response"})

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    session = session_for(safe)
    preview = session.preview
    result = session.execute(preview=preview, confirmed=True)
    assert len(requests) == result.attempted_request_count == 1
    assert requests[0].method == "POST"
    assert json.loads(requests[0].content) == {
        "query": preview.probe.query,
        "variables": preview.probe.variables,
    }
    assert result.execution.outcome.value == outcome
    assert result.execution.returned_id_matches is match
    assert result.evaluation.status.value == policy
    assert bool(result.violation) == (policy == "violated")
    evidence = result.evidence[0]
    assert evidence.evidence_type is EvidenceType.MUTATION_AUTHORIZATION_PROBE
    assert evidence.execution_mode is ScanMode.ACTIVE
    assert evidence.response_body == raw and evidence.response_status_code == status
    assert evidence.response_headers["x-test"] == "response"
    assert evidence.query == preview.probe.query and evidence.variables == preview.probe.variables
    assert evidence.identifier == "123" and evidence.expected.value == "deny"
    assert evidence.timestamp and evidence.duration_seconds >= 0
    assert result.evaluation.source_evidence_ids == (evidence.evidence_id,)
    assert session.execute(preview=preview, confirmed=True) == result
    assert len(requests) == 1


def test_network_failure_consumes_attempt_and_hides_transport_text(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL)[0]
    attempts = []

    def handler(request):
        attempts.append(request)
        raise httpx.ConnectError("PHASE23_SECRET", request=request)

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    session = session_for(safe)
    result = session.execute(preview=session.preview, confirmed=True)
    assert session.execute(preview=session.preview, confirmed=True) == result
    assert len(attempts) == result.attempted_request_count == 1
    assert result.execution.outcome.value == "network_failure"
    assert result.evaluation.status.value == "unresolved"
    assert not result.violation and "PHASE23_SECRET" not in repr(result)


@pytest.mark.parametrize(
    "mode,enabled,confirmed",
    [
        (ScanMode.SAFE, True, True),
        (ScanMode.ACTIVE, False, True),
        (ScanMode.ACTIVE, True, False),
        (ScanMode.ACTIVE, True, 1),
    ],
)
def test_strict_independent_gates(phase_ten_scan, monkeypatch, mode, enabled, confirmed):
    safe = phase_ten_scan(SDL, mode=mode)[0]
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Unconsented HTTP"))
    session = application.MutationAuthorizationSession(
        safe, cases=parse_mutation_cases(["updateOrder:id=123"]), enabled=enabled
    )
    result = session.execute(preview=session.preview, confirmed=confirmed)
    assert result.attempted_request_count == 0 and not result.evidence


@pytest.mark.parametrize("tamper", ["id", "input", "query", "endpoint", "path", "policy", "replay"])
def test_forged_preview_cannot_send(phase_ten_scan, monkeypatch, tamper):
    safe = phase_ten_scan(SDL)[0]
    session = session_for(safe)
    preview = session.preview
    probe = preview.probe
    if tamper in {"id", "input"}:
        probe.variables[tamper] = "FORGED"
    elif tamper == "query":
        preview = replace(
            preview, probe=replace(probe, query=probe.query.replace("mutation", "query"))
        )
    elif tamper == "endpoint":
        preview = replace(preview, probe=replace(probe, endpoint="https://other.example/graphql"))
    elif tamper == "path":
        preview = replace(preview, probe=replace(probe, response_id_path=("other", "id")))
    elif tamper == "policy":
        preview = replace(preview, cases=(replace(preview.cases[0], expected="allow"),))
    else:
        preview = replace(preview, attempted_request_count=1)
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Forged HTTP"))
    result = session.execute(preview=preview, confirmed=True)
    assert result.attempted_request_count == 0 and not result.evidence


def test_query_root_and_forged_cases_rejected(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL)[0]
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid HTTP"))
    assert session_for(safe, "order:id=123").preview.probe is None
    case = parse_mutation_cases(["updateOrder:id=123"])[0]
    for cases in ((case, case), (replace(case, expected="allow"),), (replace(case, index=True),)):
        with pytest.raises(HttpConfigurationError):
            application.MutationAuthorizationSession(safe, cases=cases, enabled=True)


def test_optional_id_and_missing_selection_added_without_other_inputs(phase_ten_scan):
    safe = phase_ten_scan(
        "type Query { health: String } "
        "type Mutation { updateOrder(id: ID, other: String): Order } "
        "type Order { id: ID! name: String }"
    )[0]
    scan = safe.query_generation.operation_analysis.schema_scan
    schema = scan.schemas[0].schema
    native = load_introspection_schema(scan.introspection.introspections[0].full_response.body)
    analysis = next(
        op
        for ep in safe.query_generation.operation_analysis.endpoints
        for op in ep.operations
        if op.name == "updateOrder"
    )
    base = replace(
        generate_mutation(schema, analysis), query_text="mutation { updateOrder { name } }"
    )
    query, variables = build_mutation_probe(
        schema, native, base, parse_mutation_cases(["updateOrder:id=abc"])[0]
    )
    assert variables == {"id": "abc"}
    root = parse(query).definitions[0].selection_set.selections[0]
    assert [item.name.value for item in root.selection_set.selections] == ["name", "id"]
    assert [item.name.value for item in root.arguments] == ["id"]


def test_shared_id_variable_cannot_change_unrelated_input(phase_ten_scan):
    safe = phase_ten_scan(
        "type Query { health: String } "
        "type Mutation { updateOrder(id: ID!, reference: ID!): Order } type Order { id: ID! }"
    )[0]
    scan = safe.query_generation.operation_analysis.schema_scan
    schema = scan.schemas[0].schema
    native = load_introspection_schema(scan.introspection.introspections[0].full_response.body)
    analysis = next(
        op
        for ep in safe.query_generation.operation_analysis.endpoints
        for op in ep.operations
        if op.name == "updateOrder"
    )
    base = replace(
        generate_mutation(schema, analysis),
        query_text=(
            "mutation ($shared: ID!) { updateOrder(id: $shared, reference: $shared) { id } }"
        ),
        variables={"shared": "1"},
    )
    with pytest.raises(SafeExecutionValidationError, match="unrelated input"):
        build_mutation_probe(schema, native, base, parse_mutation_cases(["updateOrder:id=123"])[0])


def test_generation_failure_and_retained_schema_tampering_skip(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL)[0]
    session = session_for(safe)
    scan = safe.query_generation.operation_analysis.schema_scan
    tampered_schema = replace(scan.schemas[0].schema, mutation_root=None)
    schemas = (replace(scan.schemas[0], schema=tampered_schema), *scan.schemas[1:])
    analysis = replace(
        safe.query_generation.operation_analysis, schema_scan=replace(scan, schemas=schemas)
    )
    tampered = replace(
        safe, query_generation=replace(safe.query_generation, operation_analysis=analysis)
    )
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid schema sent HTTP"))
    assert session_for(tampered).preview.probe is None
    from gqlsleuth.domain.exceptions import QueryGenerationError

    def fail(*args):
        raise QueryGenerationError("Target-derived detail must not leak")

    monkeypatch.setattr(application, "generate_mutation", fail)
    result = session.execute(preview=session.preview, confirmed=True)
    assert result.attempted_request_count == 0 and not result.evidence
    assert "Target-derived detail" not in repr(result)
