"""Schema-only matching, explicit typed values, exact AST changes and conservative outcomes."""

import json
from copy import deepcopy
from dataclasses import replace

import httpx
import pytest
from graphql import parse, print_ast
from graphql.language.ast import NameNode, VariableNode
from graphql.language.visitor import Visitor, visit

from fixtures.phase24_target import SDL
from gqlsleuth.application import sensitive_input as application
from gqlsleuth.application.sensitive_input_review import review_sensitive_inputs
from gqlsleuth.domain.exceptions import HttpConfigurationError, SafeExecutionValidationError
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.sensitive_input import parse_sensitive_case
from gqlsleuth.graphql.query_generation import generate_mutation
from gqlsleuth.graphql.schema_parser import load_introspection_schema
from gqlsleuth.graphql.sensitive_input import build_sensitive_probe, classify_sensitive_response
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.rules.sensitive_input import sensitive_category


@pytest.mark.parametrize(
    "name",
    [
        "isStaff",
        "is_staff",
        "IsAdmin",
        "is_admin",
        "role",
        "permissions",
        "ownerId",
        "tenant_id",
        "verified",
        "approved",
        "accessLevel",
    ],
)
def test_exact_sensitive_names(name):
    assert sensitive_category(name) is not None


@pytest.mark.parametrize(
    "name",
    [
        "administratorEmail",
        "roleDescription",
        "ownershipNote",
        "status",
        "type",
        "level",
        "notAdmin",
    ],
)
def test_no_substring_or_generic_matches(name):
    assert sensitive_category(name) is None


def test_review_is_local_one_level_ordered_and_preserves_existing_review(
    phase_ten_scan, monkeypatch
):
    safe, requests = phase_ten_scan(SDL, mode=ScanMode.SAFE)
    original = deepcopy(safe)
    count = len(requests)
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Local review sent HTTP"))
    candidates = review_sensitive_inputs(safe.query_generation.operation_analysis)
    assert candidates == safe.query_generation.sensitive_input_review
    assert candidates == review_sensitive_inputs(safe.query_generation.operation_analysis)
    assert safe == original and len(requests) == count
    assert [(c.operation, c.argument, c.field) for c in candidates] == sorted(
        (c.operation, c.argument, c.field) for c in candidates
    )
    assert {c.field for c in candidates} == {
        "isStaff",
        "role",
        "accessLevel",
        "ownerId",
        "tenantId",
        "permissions",
    }
    for item in candidates:
        assert not hasattr(item, "severity")
        assert not hasattr(item, "cvss")
        if item.operation == "deleteUser" or item.field == "permissions":
            assert item.case_template is None
        else:
            assert item.case_template == f"{item.operation}:input.{item.field}=<VALUE>"
            assert item.target_template == ("id=<ID>" if item.operation == "updateUser" else None)
    query_schema = SDL.replace("profile: User", "profile(input: UpdateUserInput): User")
    # Build a second offline fixture only after lifting the no-request guard.
    monkeypatch.undo()
    other = phase_ten_scan(query_schema)[0]
    assert all(
        item.operation != "profile" for item in other.query_generation.sensitive_input_review
    )


@pytest.mark.parametrize(
    "entries,target",
    [
        ([], None),
        (["x:input.role=A", "x:input.role=A"], None),
        (["x:input.nested.role=A"], None),
        (["x:input.roles[0]=A"], None),
        (["bad-name:input.role=A"], None),
        (["x:input.0role=A"], None),
        (["x:input.role="], None),
        (["x:input.role=a\n"], None),
        (["x:input.role=a\r"], None),
        (["x:input.role=a\0"], None),
        (["x:input.role=" + "é" * 129], None),
        (["x:input.role=A"], "bad:id=123"),
        (["x:input.role=A"], "id="),
        (["x:input.role=A"], "id=a\n"),
    ],
)
def test_invalid_syntax_secret_safe(entries, target):
    with pytest.raises(HttpConfigurationError) as error:
        parse_sensitive_case(entries, target)
    assert all(entry not in str(error.value) for entry in entries)


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("isStaff", "true", True),
        ("isStaff", "false", False),
        ("accessLevel", "0", 0),
        ("accessLevel", "-2147483648", -(2**31)),
        ("accessLevel", "2147483647", 2**31 - 1),
        ("role", "ADMIN", "ADMIN"),
        ("tenantId", " text=a:b ", " text=a:b "),
        ("ownerId", "001", "001"),
    ],
)
def test_typed_values_and_only_explicit_field(phase_ten_scan, field, value, expected):
    safe = phase_ten_scan(SDL)[0]
    case = parse_sensitive_case([f"updateUser:input.{field}={value}"], "id=abc123")
    session = application.SensitiveInputSession(safe, case=case, enabled=True)
    probe = session.preview.probe
    assert probe is not None, session.preview.limitations
    assert type(probe.typed_value) is type(expected) and probe.typed_value == expected
    assert probe.variables == {
        "id": "abc123",
        "input": {"displayName": "Test User", field: expected},
    }
    fields = parse(probe.query).definitions[0].selection_set.selections[0].selection_set.selections
    assert {item.name.value for item in fields} >= {"id", field}


@pytest.mark.parametrize(
    "field,value",
    [
        ("isStaff", "TRUE"),
        ("isStaff", "1"),
        ("isStaff", "yes"),
        ("accessLevel", "01"),
        ("accessLevel", "-0"),
        ("accessLevel", "+1"),
        ("accessLevel", "2147483648"),
        ("accessLevel", "-2147483649"),
        ("accessLevel", "1.0"),
        ("role", "admin"),
        ("role", "SUPERADMIN"),
        ("permissions", "A"),
        ("profile", "A"),
        ("roleDescription", "A"),
    ],
)
def test_unsupported_values_or_fields_do_not_execute(phase_ten_scan, monkeypatch, field, value):
    safe = phase_ten_scan(SDL)[0]
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Invalid probe sent HTTP"))
    session = application.SensitiveInputSession(
        safe,
        case=parse_sensitive_case([f"updateUser:input.{field}={value}"], "id=123"),
        enabled=True,
    )
    assert session.preview.probe is None
    result = session.execute(preview=session.preview, confirmed=True)
    assert result.attempted_request_count == 0 and not result.evidence


@pytest.mark.parametrize(
    "change",
    [
        "Float",
        "Custom",
        "missing",
        "mismatch",
        "abstract",
        "list-output",
        "multiple-id",
        "list-id",
        "list-input",
    ],
)
def test_incompatible_structures_have_no_hints_or_requests(phase_ten_scan, monkeypatch, change):
    input_type = "Float" if change == "Float" else "Custom" if change == "Custom" else "Boolean"
    output_field = (
        "name: String"
        if change == "missing"
        else "isStaff: String"
        if change == "mismatch"
        else f"isStaff: {input_type}"
    )
    id_arguments = (
        "id: ID, other: ID"
        if change == "multiple-id"
        else "id: [ID]"
        if change == "list-id"
        else "id: ID"
    )
    return_type = (
        "Node" if change == "abstract" else "[User]" if change == "list-output" else "User"
    )
    argument_type = "[Input]" if change == "list-input" else "Input"
    sdl = f"""scalar Custom
    type Query {{ health: String }}
    interface Node {{ id: ID }}
    type User {{ id: ID {output_field} }}
    input Input {{ isStaff: {input_type} }}
    type Mutation {{ updateUser({id_arguments}, input: {argument_type}): {return_type} }}
    """
    safe = phase_ten_scan(sdl)[0]
    assert all(c.case_template is None for c in safe.query_generation.sensitive_input_review)
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Unsupported HTTP"))
    session = application.SensitiveInputSession(
        safe, case=parse_sensitive_case(["updateUser:input.isStaff=true"], "id=123"), enabled=True
    )
    assert session.preview.probe is None


@pytest.mark.parametrize(
    "operation,target,eligible",
    [
        ("updateUser", None, False),
        ("updateUser", "other=123", False),
        ("updateProfile", "id=123", False),
        ("updateProfile", None, True),
        ("deleteUser", "id=123", False),
        ("profile", None, False),
    ],
)
def test_target_requirements_and_destructive_gate(phase_ten_scan, operation, target, eligible):
    safe = phase_ten_scan(SDL)[0]
    session = application.SensitiveInputSession(
        safe, case=parse_sensitive_case([f"{operation}:input.isStaff=true"], target), enabled=True
    )
    assert bool(session.preview.probe) is eligible


def test_actual_variable_mapping_and_unrelated_inputs_preserved(phase_ten_scan):
    safe = phase_ten_scan(SDL)[0]
    scan = safe.query_generation.operation_analysis.schema_scan
    schema = scan.schemas[0].schema
    native = load_introspection_schema(scan.introspection.introspections[0].full_response.body)
    op = next(
        o
        for ep in safe.query_generation.operation_analysis.endpoints
        for o in ep.operations
        if o.name == "updateUser"
    )
    base = generate_mutation(schema, op)

    class Rename(Visitor):
        def enter_variable(self, node, *_):
            return VariableNode(
                name=NameNode(
                    value={"id": "targetValue", "input": "changes"}.get(
                        node.name.value, node.name.value
                    )
                )
            )

    base = replace(
        base,
        query_text=print_ast(visit(parse(base.query_text), Rename())),
        variables={"targetValue": "1", "changes": base.variables["input"]},
    )
    original = deepcopy(base)
    case = parse_sensitive_case(["updateUser:input.isStaff=true"], "id=123")
    query, variables, value, name = build_sensitive_probe(schema, native, base, case)
    assert variables == {
        "targetValue": "123",
        "changes": {"displayName": "Test User", "isStaff": True},
    }
    assert base == original and value is True and name == "Boolean"
    assert build_sensitive_probe(schema, native, base, case) == (query, variables, value, name)
    for query_text in (
        base.query_text.replace("mutation", "query"),
        base.query_text.replace("updateUser(", "alias: updateUser("),
        base.query_text + ' mutation { deleteUser(id: 1, input: {displayName: "x"}) { id } }',
    ):
        with pytest.raises(SafeExecutionValidationError):
            build_sensitive_probe(schema, native, replace(base, query_text=query_text), case)


@pytest.mark.parametrize(
    "body,status,outcome",
    [
        ({"data": {"updateUser": {"id": "123", "isStaff": True}}}, 200, "target_value_returned"),
        ({"data": {"updateUser": {"id": 123, "isStaff": True}}}, 200, "target_value_returned"),
        ({"data": {"updateUser": {"id": "124", "isStaff": True}}}, 200, "indeterminate"),
        ({"data": {"updateUser": {"id": "123", "isStaff": 1}}}, 200, "indeterminate"),
        ({"data": {"updateUser": {"id": "123", "isStaff": "true"}}}, 200, "indeterminate"),
        ({"data": {"updateUser": {"id": "123", "isStaff": False}}}, 200, "indeterminate"),
        ({"data": {"updateUser": {"id": "123"}}}, 200, "indeterminate"),
        ({"data": {"updateUser": None}}, 200, "indeterminate"),
        ({"errors": [{"message": "business rule"}]}, 200, "indeterminate"),
        (
            {"errors": [{"message": "Forbidden", "path": ["updateUser", "isStaff"]}]},
            200,
            "explicit_denial",
        ),
        ({"errors": [{"message": "Forbidden", "path": ["other"]}]}, 200, "indeterminate"),
        (
            {
                "data": {"updateUser": {"id": "123", "isStaff": True}},
                "errors": [{"message": "partial"}],
            },
            200,
            "indeterminate",
        ),
        ({}, 401, "explicit_denial"),
        ({}, 403, "explicit_denial"),
        ({}, 400, "indeterminate"),
        ({}, 404, "indeterminate"),
        ({}, 500, "indeterminate"),
        ("malformed", 200, "indeterminate"),
    ],
)
def test_response_matching_is_typed_and_scoped(body, status, outcome):
    case = parse_sensitive_case(["updateUser:input.isStaff=true"], "id=123")
    actual, _, _ = classify_sensitive_response(
        status, json.dumps(body).encode(), case, True, "Boolean"
    )
    assert actual.value == outcome


@pytest.mark.parametrize(
    "mode,enabled,confirmed",
    [
        (ScanMode.SAFE, True, True),
        (ScanMode.ACTIVE, False, True),
        (ScanMode.ACTIVE, True, False),
        (ScanMode.ACTIVE, True, 1),
    ],
)
def test_independent_gates(phase_ten_scan, monkeypatch, mode, enabled, confirmed):
    safe = phase_ten_scan(SDL, mode=mode)[0]
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Unconfirmed HTTP"))
    session = application.SensitiveInputSession(
        safe,
        case=parse_sensitive_case(["updateUser:input.isStaff=true"], "id=123"),
        enabled=enabled,
    )
    result = session.execute(preview=session.preview, confirmed=confirmed)
    assert not result.evidence and result.attempted_request_count == 0


@pytest.mark.parametrize(
    "tamper", ["field", "value", "target", "other", "typed", "endpoint", "document"]
)
def test_altered_preview_cannot_send(phase_ten_scan, monkeypatch, tamper):
    safe = phase_ten_scan(SDL)[0]
    session = application.SensitiveInputSession(
        safe, case=parse_sensitive_case(["updateUser:input.isStaff=true"], "id=123"), enabled=True
    )
    preview = session.preview
    probe = preview.probe
    if tamper == "field":
        probe.variables["input"]["role"] = "ADMIN"
    elif tamper == "value":
        probe.variables["input"]["isStaff"] = False
    elif tamper == "target":
        probe.variables["id"] = "124"
    elif tamper == "other":
        probe.variables["input"]["displayName"] = "changed"
    elif tamper == "typed":
        preview = replace(preview, probe=replace(probe, typed_value=1))
    elif tamper == "endpoint":
        preview = replace(preview, probe=replace(probe, endpoint="https://other.example/graphql"))
    else:
        preview = replace(
            preview, probe=replace(probe, query=probe.query.replace("mutation", "query"))
        )
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Altered HTTP"))
    result = session.execute(preview=preview, confirmed=True)
    assert result.attempted_request_count == 0 and not result.evidence


def test_network_failure_counts_once_and_does_not_leak(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL)[0]
    attempts = []

    def handler(request):
        attempts.append(request)
        raise httpx.ConnectError("PHASE24_SECRET", request=request)

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    session = application.SensitiveInputSession(
        safe, case=parse_sensitive_case(["updateUser:input.isStaff=true"], "id=123"), enabled=True
    )
    result = session.execute(preview=session.preview, confirmed=True)
    assert session.execute(preview=session.preview, confirmed=True) == result
    assert len(attempts) == result.attempted_request_count == 1
    assert (
        result.execution.outcome.value == "network_failure"
        and result.evaluation.status.value == "unresolved"
    )
    assert "PHASE24_SECRET" not in repr(result)
