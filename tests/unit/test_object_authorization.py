"""Offline parsing, structural eligibility, AST preservation and exact identity boundaries."""

import json
from dataclasses import replace

import pytest
from graphql import build_schema, parse, validate

from fixtures.phase20_target import SDL
from gqlsleuth.application.object_authorization import prepare_object_authorization
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.object_authorization import ObjectOutcome as Outcome
from gqlsleuth.domain.object_authorization import parse_object_cases
from gqlsleuth.graphql.object_authorization import classify_object_response
from gqlsleuth.infrastructure.http import HttpClient


@pytest.mark.parametrize("value", ["123", "001", "abc:def", "a=b:c=d", "é" * 128, " x "])
def test_case_values_preserved(value):
    for names, prefix in [((), ""), (("foo",), ""), (("foo",), "foo:"), (("a", "b"), "a:")]:
        cases = parse_object_cases([prefix + "order:id=" + value], names)
        assert cases[0].identifier == value
        assert isinstance(cases[0].identifier, str)
        assert cases[0].declared_authorized_context == ("a" if len(names) == 2 else None)


@pytest.mark.parametrize(
    "entry,names",
    [
        ("order:id=", ()),
        ("order:id=" + "é" * 129, ()),
        ("order:id=SECRET\nVALUE", ()),
        ("order:id=SECRET\tVALUE", ()),
        ("order:id=SECRET\x00VALUE", ()),
        ("order:id=SECRET\x7fVALUE", ()),
        ("order:id=SECRET\x85VALUE", ()),
        ("order:id=SECRET\rVALUE", ()),
        ("order=SECRET", ()),
        ("a:b:order:id=SECRET", ()),
        ("9order:id=SECRET", ()),
        ("order:bad-name=SECRET", ()),
        ("a:order:id=SECRET", ()),
        ("a:order:id=SECRET", ("foo",)),
        ("order:id=SECRET", ("a", "b")),
        ("c:order:id=SECRET", ("a", "b")),
    ],
)
def test_invalid_cases_hide_values(entry, names):
    with pytest.raises(HttpConfigurationError) as error:
        parse_object_cases([entry], names)
    assert "object-auth-case #1" in str(error.value)
    assert "SECRET" not in str(error.value)


def test_limits_duplicates_and_order():
    cases = parse_object_cases(["order:id=2", "order:id=2", "order:id=1", "order:id=3"])
    assert [item.identifier for item in cases] == ["2", "1", "3"]
    assert [item.index for item in cases] == [1, 2, 3]
    with pytest.raises(HttpConfigurationError):
        parse_object_cases([f"order:id={index}" for index in range(4)])
    with pytest.raises(HttpConfigurationError):
        parse_object_cases([])


@pytest.fixture
def safe(phase_ten_scan):
    return phase_ten_scan(SDL, mode=ScanMode.SAFE)[0]


def test_preparation_is_local_and_does_not_require_placeholder_success(safe, monkeypatch):
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Preparation HTTP"))
    safe = replace(safe, executions=(), execution_evidence=())
    cases = parse_object_cases(["order:id=84639"])
    first = prepare_object_authorization(safe, cases=cases)
    assert first == prepare_object_authorization(safe, cases=cases)
    probe = first.probes[0]
    assert probe.variables == {"id": "84639"}
    assert probe.source_evidence_ids and probe.structural_source
    assert not validate(build_schema(SDL), parse(probe.query))
    assert not first.evidence and first.attempted_request_count == 0


@pytest.mark.parametrize(
    "query_type,output",
    [
        ("order(id: [ID]): Order", "type Order { id: ID }"),
        ("order(id: [ID!]): Order", "type Order { id: ID }"),
        ("order(id: String!): Order", "type Order { id: ID }"),
        ("order(filter: Filter): Order", "input Filter { id: ID } type Order { id: ID }"),
        ("order(id: ID!): [Order]", "type Order { id: ID }"),
        ("order(id: ID!): Order", "type Order { key: ID }"),
        ("order(id: ID!): Order", "type Order { id: String }"),
        ("order(id: ID!): Order", "interface Order { id: ID } type A implements Order { id: ID }"),
        ("order(id: ID!): Order", "union Order = A type A { id: ID }"),
        ("other(id: ID!): Order", "type Order { id: ID }"),
        ("order(key: ID!): Order", "type Order { id: ID }"),
    ],
)
def test_unsupported_structure_no_probe(phase_ten_scan, query_type, output):
    scan = phase_ten_scan(f"type Query {{ {query_type} }} {output}", mode=ScanMode.SAFE)[0]
    result = prepare_object_authorization(scan, cases=parse_object_cases(["order:id=123"]))
    assert not result.probes and result.limitations


@pytest.mark.parametrize(
    "document,variables",
    [
        (
            "query($objectIdentifier:ID!,$label:String!){order(id:$objectIdentifier,label:$label){total}}",
            {"objectIdentifier": "1", "label": "preserved"},
        ),
        ('query($label:String!){order(id:"old",label:$label){total}}', {"label": "preserved"}),
        ("query($label:String!){order(label:$label){total}}", {"label": "preserved"}),
        (
            "query($id:ID,$show:Boolean!,$label:String!)"
            "{order(id:$id,label:$label){total @include(if:$show)}}",
            {"id": "1", "show": False, "label": "preserved"},
        ),
    ],
)
def test_ast_substitution_preserves_other_inputs_and_adds_identity(
    phase_ten_scan, document, variables
):
    sdl = "type Query { order(id: ID, label: String!): Order } type Order { id: ID! total: Float }"
    scan = phase_ten_scan(sdl, mode=ScanMode.SAFE)[0]
    artifact = replace(scan.query_generation.queries[0], query_text=document, variables=variables)
    scan = replace(scan, query_generation=replace(scan.query_generation, queries=(artifact,)))
    result = prepare_object_authorization(scan, cases=parse_object_cases(["order:id=a:b=c"]))
    probe = result.probes[0]
    operation = parse(probe.query, no_location=True).definitions[0]
    root = operation.selection_set.selections[0]
    original = parse(document, no_location=True).definitions[0].selection_set.selections[0]
    assert root.selection_set.selections[:-1] == original.selection_set.selections
    assert root.selection_set.selections[-1].name.value == "id"
    assert next(item for item in root.arguments if item.name.value == "label") == next(
        item for item in original.arguments if item.name.value == "label"
    )
    variable_name = next(
        item.value.name.value for item in root.arguments if item.name.value == "id"
    )
    assert probe.variables[variable_name] == "a:b=c"
    assert all(
        probe.variables[key] == value for key, value in variables.items() if key != variable_name
    )
    assert variables == artifact.variables
    assert not validate(build_schema(sdl), parse(probe.query))


@pytest.mark.parametrize(
    "document",
    [
        "mutation { order { id } }",
        "subscription { order { id } }",
        "query { order(id:1){id} } query { order(id:1){id} }",
        "query { a:order(id:1){id} }",
        "query { order(id:1){a:id} }",
        "query { order(id:1){id} other:order(id:1){id} }",
        "query { order(id:1){...F} } fragment F on Order { id }",
    ],
)
def test_forged_artifacts_rejected(safe, document):
    artifact = replace(safe.query_generation.queries[0], query_text=document, variables={})
    scan = replace(safe, query_generation=replace(safe.query_generation, queries=(artifact,)))
    assert not prepare_object_authorization(scan, cases=parse_object_cases(["order:id=123"])).probes


@pytest.mark.parametrize(
    "requested,returned,expected",
    [
        ("123", "123", Outcome.TARGET_RETURNED),
        ("123", 123, Outcome.TARGET_RETURNED),
        ("123", "124", Outcome.INDETERMINATE),
        ("001", "1", Outcome.INDETERMINATE),
        ("True", True, Outcome.INDETERMINATE),
        ("1", True, Outcome.INDETERMINATE),
        ("1", 1.0, Outcome.INDETERMINATE),
        ("123", None, Outcome.INDETERMINATE),
        ("id", "ID", Outcome.INDETERMINATE),
        ("id", " id", Outcome.INDETERMINATE),
        ("1", {"id": "1"}, Outcome.INDETERMINATE),
    ],
)
def test_exact_identity_only(requested, returned, expected):
    outcomes = []
    for business in (
        {"total": 1, "email": "a", "name": "one"},
        {"total": 999, "email": "b", "name": "two", "items": [1, 2], "timestamp": 456},
    ):
        outcomes.append(
            classify_object_response(
                200,
                json.dumps({"data": {"order": {"id": returned, **business}}}).encode(),
                "order",
                requested,
            )
        )
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0] is expected


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (401, {}, Outcome.EXPLICIT_DENIAL),
        (403, {}, Outcome.EXPLICIT_DENIAL),
        (404, {}, Outcome.INDETERMINATE),
        (400, {}, Outcome.INDETERMINATE),
        (500, {}, Outcome.INDETERMINATE),
        (200, {"data": {"order": None}}, Outcome.INDETERMINATE),
        (200, {"data": {"order": {}}}, Outcome.INDETERMINATE),
        (200, {"data": {"order": [{"id": "123"}]}}, Outcome.INDETERMINATE),
        (
            200,
            {"errors": [{"extensions": {"code": "FORBIDDEN"}, "path": ["order"]}]},
            Outcome.EXPLICIT_DENIAL,
        ),
        (
            200,
            {"errors": [{"extensions": {"code": "FORBIDDEN"}, "path": ["other"]}]},
            Outcome.INDETERMINATE,
        ),
        (200, {"errors": [{"message": "business input invalid"}]}, Outcome.INDETERMINATE),
        (
            200,
            {"data": {"order": {"id": "123"}}, "errors": [{"message": "Forbidden"}]},
            Outcome.INDETERMINATE,
        ),
    ],
)
def test_outcomes(status, body, expected):
    assert (
        classify_object_response(status, json.dumps(body).encode(), "order", "123")[0] is expected
    )
    assert classify_object_response(200, b"not JSON", "order", "123")[0] is Outcome.INDETERMINATE
