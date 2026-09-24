"""Offline federation grammar, exact identity, canonical gates and presentation tests."""

import hashlib
import json
from dataclasses import replace
from io import StringIO

import httpx
import pytest
from graphql import parse
from rich.console import Console

from fixtures.phase29_target import SDL, response_for
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application import federation as application
from gqlsleuth.application.abuse_controls import prepare_abuse_controls
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.federation import (
    FederationOutcome,
    FederationPolicy,
    FederationProbe,
    parse_entity_case,
)
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.graphql.federation import classify_federation_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.federation import render_federation
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report

CASE = {"__typename": "User", "id": "123"}
SECRET = "PHASE29_AUTH_CANARY"


@pytest.fixture
def safe(phase_ten_scan):
    return phase_ten_scan(SDL)[0]


@pytest.fixture
def wire(monkeypatch):
    requests, settings = [], []
    behavior = {"scenario": "returned", "failure": None, "override": {}, "redirect": None}

    def handler(request):
        requests.append(request)
        index = len(requests)
        if behavior["failure"] == index:
            raise httpx.ConnectError(SECRET, request=request)
        if behavior["redirect"] and request.url.host == "example.com":
            return httpx.Response(307, headers={"location": behavior["redirect"]})
        if request.url.host == "other.example":
            assert not {"authorization", "cookie", "x-api-key"} & set(request.headers)
        status, body = behavior["override"].get(
            index, response_for(request.method, request.content, behavior["scenario"])
        )
        return httpx.Response(status, json=body, headers={"x-secret": SECRET})

    def factory(config):
        settings.append(config)
        return HttpClient(
            config.model_copy(update={"proxy": None}), transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(application, "HttpClient", factory)
    return requests, behavior, settings


def session(safe, **kwargs):
    return application.FederationSecuritySession(safe, enabled=True, entity_case=CASE, **kwargs)


def select(current, probes=tuple(FederationProbe)):
    return current.select(current.preview.candidates[0].endpoint, probes)


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        "null",
        "{}",
        '{"id":"1"}',
        '{"__typename":"User"}',
        '{"__typename":"User","id":null}',
        '{"__typename":"User","id":[]}',
        '{"__typename":"User","id":{}}',
        '{"__typename":"User","id":1.0}',
        '{"__typename":"User","id":NaN}',
        '{"__typename":"User","id":Infinity}',
        '{"__typename":"User","id":"1","id":"2"}',
        '{"__typename":"User","__typename":"Product","id":"1"}',
        '{"__typename":"User!","id":"1"}',
        '{"__typename":1,"id":"1"}',
        '{"__typename":"User","bad-key":"1"}',
        '{"__typename":"User","a":1,"b":2,"c":3,"d":4}',
        '{"__typename":"User","id":"' + "é" * 600 + '"}',
        "not-json",
    ],
)
def test_case_grammar_rejects_without_echo(raw):
    with pytest.raises(HttpConfigurationError) as error:
        parse_entity_case([raw])
    assert raw not in str(error.value)


def test_case_grammar_single_flat_bounded():
    assert parse_entity_case([]) is None
    assert parse_entity_case([json.dumps(CASE)]) == CASE
    assert parse_entity_case(['{"__typename":"User","age":1,"enabled":true}'])["enabled"] is True
    with pytest.raises(HttpConfigurationError):
        parse_entity_case([json.dumps(CASE)] * 2)


def test_prepare_uses_retained_phase16_zero_http(safe, wire):
    current = session(safe)
    candidate = current.preview.candidates[0]
    assert candidate.source in safe.query_generation.security_review.candidates
    assert candidate.source.source_evidence_ids
    assert candidate.possible_types == ("Product", "User")
    assert candidate.service_available and candidate.entities_available
    assert not wire[0]
    service, entity = candidate.plans
    assert service.query == "query {\n  _service {\n    sdl\n  }\n}"
    assert service.variables == {} and service.expected is FederationPolicy.OBSERVE
    assert entity.variables == {"representations": [CASE]}
    ast = parse(entity.query)
    assert len(ast.definitions) == 1 and ast.definitions[0].name is None
    field = ast.definitions[0].selection_set.selections[0]
    assert field.name.value == "_entities" and field.alias is None
    fragment = field.selection_set.selections[0]
    assert fragment.type_condition.name.value == "User"
    assert [f.name.value for f in fragment.selection_set.selections] == ["__typename", "id"]
    assert "$representations: [_Any!]!" in entity.query


@pytest.mark.parametrize(
    "case",
    [
        {"__typename": "Product", "upc": "001"},
        {"__typename": "User", "id": 123},
        {"__typename": "User", "username": "abc", "age": 1, "enabled": True},
        {"__typename": "User", "kind": "A"},
    ],
)
def test_valid_schema_keys(safe, case):
    result = application.prepare_federation(safe, enabled=True, entity_case=case)
    assert len(result.candidates[0].plans) == 2
    assert result.candidates[0].plans[1].variables == {"representations": [case]}


@pytest.mark.parametrize(
    "case",
    [
        {"__typename": "Missing", "id": "1"},
        {"__typename": "_Entity", "id": "1"},
        {"__typename": "User", "missing": "1"},
        {"__typename": "User", "id": True},
        {"__typename": "User", "age": True},
        {"__typename": "User", "age": "1"},
        {"__typename": "User", "age": 2147483648},
        {"__typename": "User", "age": -2147483649},
        {"__typename": "User", "enabled": 1},
        {"__typename": "User", "username": 1},
        {"__typename": "User", "kind": "C"},
        {"__typename": "User", "floatKey": 1},
        {"__typename": "User", "custom": "1"},
        {"__typename": "User", "nested": "1"},
        {"__typename": "User", "many": "1"},
        {"__typename": "User", "argument": "1"},
    ],
)
def test_incompatible_entity_retains_independent_service(safe, case, wire):
    current = application.FederationSecuritySession(safe, enabled=True, entity_case=case)
    assert [p.probe for p in current.preview.candidates[0].plans] == [FederationProbe.SERVICE]
    assert current.preview.candidates[0].limitations
    with pytest.raises(HttpConfigurationError):
        select(current)
    assert not wire[0]


@pytest.mark.parametrize(
    "status,body,outcome",
    [
        (200, {"data": {"_service": {"sdl": "type Query { x: String }"}}}, "sdl_returned"),
        (200, {"data": {"_service": {"sdl": ""}}}, "indeterminate"),
        (200, {"data": {"_service": {"sdl": "  "}}}, "indeterminate"),
        (200, {"data": {"_service": {"sdl": None}}}, "indeterminate"),
        (200, {"data": {"_service": {"sdl": 1}}}, "indeterminate"),
        (200, {"data": {"_service": []}}, "indeterminate"),
        (200, {"data": None}, "indeterminate"),
        (200, {"errors": [{"message": "Forbidden", "path": ["_service"]}]}, "explicit_denial"),
        (200, {"errors": [{"message": "Forbidden", "path": ["other"]}]}, "indeterminate"),
        (200, {"errors": [{"message": "Unknown item"}]}, "indeterminate"),
        (403, {}, "explicit_denial"),
        (401, {}, "explicit_denial"),
        (500, {}, "indeterminate"),
        (200, {"data": {"_service": {"sdl": "x"}}, "errors": [{}]}, "indeterminate"),
    ],
)
def test_service_classification(safe, status, body, outcome):
    plan = session(safe).preview.candidates[0].plans[0]
    result = classify_federation_response(status, json.dumps(body).encode(), plan)
    assert result.outcome.value == outcome
    if outcome == "sdl_returned":
        value = body["data"]["_service"]["sdl"].encode()
        assert result.sdl_bytes == len(value)
        assert result.sdl_sha256 == hashlib.sha256(value).hexdigest()


@pytest.mark.parametrize(
    "value,expected",
    [
        ([CASE], True),
        ([{**CASE, "id": 123}], True),
        ([{**CASE, "id": "0123"}], False),
        ([{**CASE, "id": 123.0}], False),
        ([{**CASE, "id": True}], False),
        ([{**CASE, "__typename": "Product"}], False),
        ([{"__typename": "User"}], False),
        ([{"id": "123"}], False),
        ([None], False),
        (None, False),
        ([], False),
        ([CASE, CASE], False),
        (CASE, False),
    ],
)
def test_exact_entity_identity(safe, value, expected):
    plan = session(safe).preview.candidates[0].plans[1]
    observation = classify_federation_response(
        200, json.dumps({"data": {"_entities": value}}).encode(), plan
    )
    assert (observation.outcome is FederationOutcome.ENTITY_RETURNED) is expected


@pytest.mark.parametrize(
    "key,wanted,actual,match",
    [
        ("id", "001", "001", True),
        ("id", "001", 1, False),
        ("username", "1", 1, False),
        ("age", 1, True, False),
        ("age", 1, 1.0, False),
        ("enabled", True, 1, False),
        ("kind", "A", "a", False),
        ("kind", "A", "A", True),
    ],
)
def test_typed_compound_matching(safe, key, wanted, actual, match):
    case = {"__typename": "User", key: wanted}
    result = application.prepare_federation(safe, enabled=True, entity_case=case)
    plan = result.candidates[0].plans[1]
    body = json.dumps({"data": {"_entities": [{"__typename": "User", key: actual}]}}).encode()
    assert (
        classify_federation_response(200, body, plan).outcome is FederationOutcome.ENTITY_RETURNED
    ) is match


@pytest.mark.parametrize(
    "enabled,mode,confirmed,selected",
    [
        (False, ScanMode.ACTIVE, True, False),
        (True, ScanMode.SAFE, True, False),
        (True, ScanMode.ACTIVE, False, True),
        (True, ScanMode.ACTIVE, True, False),
        (True, ScanMode.ACTIVE, 1, True),
        (True, ScanMode.ACTIVE, "yes", True),
    ],
)
def test_no_execution_without_all_gates(phase_ten_scan, wire, enabled, mode, confirmed, selected):
    safe = phase_ten_scan(SDL, mode=mode)[0]
    current = application.FederationSecuritySession(safe, enabled=enabled, entity_case=CASE)
    preview = select(current) if selected else current.preview
    result = current.execute(preview=preview, confirmed=confirmed)
    assert not result.attempts and not wire[0]


def test_two_requests_canonical_order_and_terminal(safe, wire):
    current = session(safe, deny_sdl=True)
    preview = select(current, tuple(reversed(tuple(FederationProbe))))
    result = current.execute(preview=preview, confirmed=True)
    assert [e.probe for e in result.attempts] == list(FederationProbe)
    assert len(wire[0]) == len(result.findings) == 2
    assert all(e.evaluation is PolicyStatus.VIOLATED for e in result.attempts)
    assert all(e.evidence_type is EvidenceType.FEDERATION_SECURITY_PROBE for e in result.evidence)
    for request, evidence in zip(wire[0], result.evidence, strict=True):
        payload = json.loads(request.content)
        assert request.method == "POST" and payload["query"] == evidence.query
        assert "operationName" not in payload
        assert payload.get("variables", {}) == evidence.variables
        assert evidence.response_body and evidence.duration_seconds >= 0
    assert current.execute(preview=preview, confirmed=True) == result
    assert len(wire[0]) == 2
    with pytest.raises(HttpConfigurationError):
        select(current)


def test_observe_is_not_deny(safe, wire):
    current = session(safe)
    result = current.execute(preview=select(current, (FederationProbe.SERVICE,)), confirmed=True)
    assert len(result.attempts) == 1 and not result.findings
    assert result.attempts[0].evaluation is None


@pytest.mark.parametrize(
    "scenario,outcome,status",
    [
        ("denied", FederationOutcome.EXPLICIT_DENIAL, PolicyStatus.SATISFIED),
        ("null", FederationOutcome.INDETERMINATE, PolicyStatus.UNRESOLVED),
        ("error", FederationOutcome.INDETERMINATE, PolicyStatus.UNRESOLVED),
        ("wrong-key", FederationOutcome.INDETERMINATE, PolicyStatus.UNRESOLVED),
        ("wrong-type", FederationOutcome.INDETERMINATE, PolicyStatus.UNRESOLVED),
    ],
)
def test_entity_deny_outcomes(safe, wire, scenario, outcome, status):
    wire[1]["scenario"] = scenario
    current = session(safe)
    result = current.execute(preview=select(current, (FederationProbe.ENTITY,)), confirmed=True)
    assert result.attempts[0].outcome is outcome
    assert result.attempts[0].evaluation is status
    assert not result.findings


def test_failure_counts_and_does_not_cancel_entity(safe, wire):
    wire[1]["failure"] = 1
    current = session(safe, deny_sdl=True)
    result = current.execute(preview=select(current), confirmed=True)
    assert len(wire[0]) == 2 and len(result.findings) == 1
    assert result.attempts[0].outcome is FederationOutcome.NETWORK_FAILURE
    assert result.attempts[0].error_message == "Federation transport failed."
    assert SECRET not in str(result)


@pytest.mark.parametrize(
    "change", ["query", "variables", "selected", "settings", "source", "schema"]
)
def test_tampering_sends_nothing(safe, wire, change):
    current = session(safe)
    preview = select(current)
    candidate = preview.candidates[0]
    if change == "query":
        plans = (replace(candidate.plans[0], query="query { health }"), candidate.plans[1])
        preview = replace(preview, candidates=(replace(candidate, plans=plans),))
    elif change == "variables":
        candidate.plans[1].variables["representations"] = [{**CASE, "id": "999"}]
    elif change == "selected":
        preview = replace(preview, selected_probes=(FederationProbe.ENTITY,))
    elif change == "settings":
        current._settings = HttpClientSettings(timeout_seconds=33)
    elif change == "source":
        current._safe = replace(
            safe, query_generation=replace(safe.query_generation, security_review=None)
        )
    else:
        scan = safe.query_generation.operation_analysis.schema_scan
        analysis = replace(
            safe.query_generation.operation_analysis, schema_scan=replace(scan, schemas=())
        )
        current._safe = replace(
            safe, query_generation=replace(safe.query_generation, operation_analysis=analysis)
        )
    result = current.execute(preview=preview, confirmed=True)
    assert not wire[0] and not result.attempts and result.limitations


@pytest.mark.parametrize(
    "probes", [(FederationProbe.SERVICE,) * 2, ("service",), (FederationProbe.ENTITY,) * 3]
)
def test_selection_not_forgeable(safe, probes):
    with pytest.raises(HttpConfigurationError):
        select(session(safe), probes)


def test_privacy_reports_ai_and_disabled_semantics(safe, wire):
    settings = HttpClientSettings(
        custom_headers=(("Authorization", "Bearer " + SECRET),),
        proxy="http://fake:PHASE29_PROXY_CANARY@localhost:8080",
    )
    current = session(safe, deny_sdl=True, http_settings=settings)
    result = current.execute(preview=select(current), confirmed=True)
    assert all(r.headers["authorization"] == "Bearer " + SECRET for r in wire[0])
    assert all(s == settings for s in wire[2])
    active = execute_selected_mutations(
        prepare_active_mutations(safe), selected_indices=(), confirmed=False
    )
    combined = replace(active, federation_security=result)
    assert combined.evidence[: len(active.evidence)] == active.evidence
    assert build_ai_context(active) == build_ai_context(combined)
    assert prepare_abuse_controls(active) == prepare_abuse_controls(combined)
    baseline = render_report(build_report(active), ReportFormat.JSON)
    assert '"federation_security"' not in baseline
    report = build_report(combined)
    canonical = render_report(report, ReportFormat.JSON)
    assert '"federation_security"' in canonical
    assert str(result.attempts[0].evidence_id) in canonical
    assert "FEDERATION_SDL_POLICY_VIOLATION" in canonical
    assert human_sections(report)[-1].title == "Safety Notice"
    texts = [canonical]
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "Federation Security Findings" in text
        assert text.rfind("Federation Security") < text.rfind("Safety Notice")
        assert "type Query { health: Boolean }" not in text
        texts.append(text)
    stream = StringIO()
    render_federation(Console(file=stream, theme=CONSOLE_THEME), result, preview=True)
    texts.append(stream.getvalue())
    for text in texts:
        assert SECRET not in text and "PHASE29_PROXY_CANARY" not in text


def test_echo_withheld_and_cross_origin_indeterminate(safe, wire):
    wire[1]["override"][1] = (200, {"data": {"_service": {"sdl": SECRET}}})
    current = session(
        safe, http_settings=HttpClientSettings(custom_headers=(("Authorization", SECRET),))
    )
    result = current.execute(preview=select(current, (FederationProbe.SERVICE,)), confirmed=True)
    assert result.attempts[0].response_material_withheld
    assert result.attempts[0].response_body is None and SECRET not in str(result)
    wire[1]["redirect"] = "https://other.example/graphql"
    current = session(
        safe,
        deny_sdl=True,
        http_settings=HttpClientSettings(
            custom_headers=(
                ("Authorization", SECRET),
                ("Cookie", "session=fake"),
                ("X-API-Key", SECRET),
            )
        ),
    )
    result = current.execute(preview=select(current, (FederationProbe.SERVICE,)), confirmed=True)
    assert result.attempts[0].outcome is FederationOutcome.INDETERMINATE
    assert not result.findings


@pytest.mark.parametrize(
    "path,denied",
    [
        (["_service", "sdl"], True),
        (["other", "sdl"], False),
        (["_entities", 0, "id"], True),
        (["_entities", 0, "unselected"], False),
    ],
)
def test_denial_scoped_to_selected_fields(safe, path, denied):
    plans = session(safe).preview.candidates[0].plans
    plan = plans[0] if path[0] in ("_service", "other") else plans[1]
    body = json.dumps({"errors": [{"message": "Forbidden", "path": path}]}).encode()
    outcome = classify_federation_response(200, body, plan).outcome
    assert (outcome is FederationOutcome.EXPLICIT_DENIAL) is denied


@pytest.mark.parametrize("body", [b"not json", b"\xff", b"[]", b"null", b"{}"])
def test_non_graphql_response_indeterminate(safe, body):
    for plan in session(safe).preview.candidates[0].plans:
        assert (
            classify_federation_response(200, body, plan).outcome is FederationOutcome.INDETERMINATE
        )


def test_compound_case_requires_every_key(safe):
    case = {"__typename": "User", "id": "001", "enabled": True, "age": 2}
    plan = (
        application.prepare_federation(safe, enabled=True, entity_case=case).candidates[0].plans[1]
    )
    assert [key for key, _ in plan.key_types] == ["age", "enabled", "id"]
    for returned in (
        case,
        {**case, "enabled": 1},
        {key: value for key, value in case.items() if key != "age"},
    ):
        outcome = classify_federation_response(
            200, json.dumps({"data": {"_entities": [returned]}}).encode(), plan
        ).outcome
        assert (outcome is FederationOutcome.ENTITY_RETURNED) is (returned is case)


@pytest.mark.parametrize(
    "forgery",
    [
        "typename",
        "extra-key",
        "second-representation",
        "query-operation",
        "subscription",
        "alias",
        "fragment",
    ],
)
def test_caller_cannot_expand_entity_probe(safe, wire, forgery):
    current = session(safe)
    preview = select(current, (FederationProbe.ENTITY,))
    candidate = preview.candidates[0]
    plan = candidate.plans[1]
    if forgery == "typename":
        plan.variables["representations"][0]["__typename"] = "Product"
    elif forgery == "extra-key":
        plan.variables["representations"][0]["username"] = "extra"
    elif forgery == "second-representation":
        plan.variables["representations"].append(CASE)
    else:
        query = {
            "query-operation": plan.query + " query { health }",
            "subscription": plan.query.replace("query", "subscription", 1),
            "alias": plan.query.replace("_entities(", "other: _entities("),
            "fragment": plan.query + " fragment Added on User { username }",
        }[forgery]
        candidate = replace(candidate, plans=(candidate.plans[0], replace(plan, query=query)))
        preview = replace(preview, candidates=(candidate,))
    assert not current.execute(preview=preview, confirmed=True).attempts
    assert not wire[0]


def test_every_send_revalidates_settings(safe, monkeypatch):
    requests = []
    current = session(safe)

    def handler(request):
        requests.append(request)
        current._settings = HttpClientSettings(timeout_seconds=77)
        status, body = response_for(request.method, request.content)
        return httpx.Response(status, json=body)

    monkeypatch.setattr(
        application,
        "HttpClient",
        lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
    )
    result = current.execute(preview=select(current), confirmed=True)
    assert len(requests) == len(result.attempts) == 1 and result.limitations


def test_sdl_and_entity_content_never_drive_requests(safe, wire):
    wire[1]["override"] = {
        1: (
            200,
            {
                "data": {
                    "_service": {
                        "sdl": 'type Admin @key(fields: "other") { url: String } # https://never-fetch.example/graphql'
                    }
                }
            },
        ),
        2: (
            200,
            {
                "data": {
                    "_entities": [{**CASE, "nextId": "124", "url": "https://never-fetch.example/"}]
                }
            },
        ),
    }
    current = session(safe, deny_sdl=True)
    result = current.execute(preview=select(current), confirmed=True)
    assert len(wire[0]) == 2 and len(result.findings) == 2
    assert json.loads(wire[0][1].content)["variables"] == {"representations": [CASE]}
    assert all(request.url.host == "example.com" for request in wire[0])


@pytest.mark.parametrize(
    "sdl,service,entity",
    [
        ("type Query { apollo: String service: String entities: [String] }", False, False),
        ("type _Service { sdl: String } type Query { _service: _Service }", True, False),
        (SDL.replace("  _service: _Service", ""), False, True),
        (SDL.replace("_service: _Service", "_service(required: Int!): _Service"), False, True),
        (
            SDL.replace(
                "_entities(representations: [_Any!]!)",
                "_entities(representations: [_Any!]!, required: Int!)",
            ),
            True,
            False,
        ),
        (SDL.replace("_service: _Service", "_service: [_Service]"), False, True),
    ],
)
def test_only_coherent_and_compatible_schema_surfaces(phase_ten_scan, wire, sdl, service, entity):
    safe = phase_ten_scan(sdl)[0]
    result = application.prepare_federation(safe, enabled=True, entity_case=CASE)
    probes = {plan.probe for candidate in result.candidates for plan in candidate.plans}
    assert (FederationProbe.SERVICE in probes) is service
    assert (FederationProbe.ENTITY in probes) is entity
    assert not wire[0]


def test_multiple_retained_endpoints_require_one_selection(safe, wire):
    from uuid import uuid4

    from gqlsleuth.application.security_review import review_analyzed_schemas

    endpoint = "https://example.com/second-graphql"
    analysis = safe.query_generation.operation_analysis
    scan = analysis.schema_scan
    copied_schema = replace(scan.schemas[0], endpoint=endpoint)
    copied_response = replace(scan.introspection.introspections[0], endpoint=endpoint)
    source = next(
        e for e in scan.schema_evidence if e.evidence_type is EvidenceType.SCHEMA_ARTIFACT
    )
    copied_evidence = source.model_copy(update={"endpoint": endpoint, "evidence_id": uuid4()})
    scan = replace(
        scan,
        schemas=(*scan.schemas, copied_schema),
        schema_evidence=(*scan.schema_evidence, copied_evidence),
        introspection=replace(
            scan.introspection, introspections=(*scan.introspection.introspections, copied_response)
        ),
    )
    analysis = replace(analysis, schema_scan=scan)
    generation = replace(
        safe.query_generation,
        operation_analysis=analysis,
        security_review=review_analyzed_schemas(analysis),
    )
    safe = replace(safe, query_generation=generation)
    current = session(safe)
    assert len(current.preview.candidates) == 2
    with pytest.raises(HttpConfigurationError):
        current.select("https://other.example", (FederationProbe.SERVICE,))
    preview = current.select(endpoint, (FederationProbe.SERVICE,))
    result = current.execute(preview=preview, confirmed=True)
    assert len(result.attempts) == len(wire[0]) == 1
    assert str(wire[0][0].url) == endpoint
