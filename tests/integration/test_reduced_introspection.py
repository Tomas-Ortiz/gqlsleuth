"""Bounded fallback, parser reuse, provenance and downstream offline regressions."""

import json
from dataclasses import replace
from io import StringIO

import httpx
import pytest
from graphql import FragmentDefinitionNode, FragmentSpreadNode, OperationDefinitionNode, parse
from rich.console import Console

from fixtures.reduced_introspection import SDL, introspection_body
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import MAX_AI_OPERATIONS, MAX_CONTEXT_BYTES, AIInterpretation
from gqlsleuth.application.active_execution import prepare_active_mutations
from gqlsleuth.application.differential_review import ContextScanResult, compare_context_scans
from gqlsleuth.application.introspection import _introspect_endpoint
from gqlsleuth.application.mutation_preparation import retained_mutation
from gqlsleuth.application.query_depth import prepare_query_depth
from gqlsleuth.application.safe_execution import run_safe_execution_scan
from gqlsleuth.application.schema_parsing import parse_introspection_schemas
from gqlsleuth.domain.differential import DifferenceKind
from gqlsleuth.domain.exceptions import SchemaParsingError
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.graphql.introspection import (
    FULL_INTROSPECTION_QUERY,
    MINIMAL_INTROSPECTION_QUERY,
    REDUCED_INTROSPECTION_QUERY,
    IntrospectionStatus,
    SchemaRetrievalStatus,
    reduced_introspection_fallback_reason,
)
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.assessment import build_assessment
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_pre_active_context, render_scan
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.differential import build_differential_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report

TARGET = "http://127.0.0.1:8123/graphql"


@pytest.mark.parametrize(
    "message,reason",
    [
        ("Query depth exceeded", "depth_limit"),
        ("Maximum query depth: 8", "depth_limit"),
        ("Max depth reached", "depth_limit"),
        ("Query too deep", "depth_limit"),
        ("Query depth limit exceeded.", "depth_limit"),
        ("Depth limit exceeded", "depth_limit"),
        ("Query complexity exceeded", "complexity_limit"),
        ("Maximum query complexity: 50", "complexity_limit"),
        ("Query too complex", "complexity_limit"),
        ("Complexity limit exceeded", "complexity_limit"),
        ("Query cost exceeded", "cost_limit"),
        ("Maximum query cost: 50", "cost_limit"),
        ("Cost limit exceeded", "cost_limit"),
    ],
)
def test_only_explicit_restriction_triggers_one_static_fallback(message, reason):
    requests = []

    def handler(request):
        query = json.loads(request.content)["query"]
        requests.append(query)
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(
                200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
            )
        if query == FULL_INTROSPECTION_QUERY:
            return httpx.Response(400, json={"errors": [{"message": message}]})
        assert query == REDUCED_INTROSPECTION_QUERY
        return httpx.Response(200, json=introspection_body())

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert requests == [
        MINIMAL_INTROSPECTION_QUERY,
        FULL_INTROSPECTION_QUERY,
        REDUCED_INTROSPECTION_QUERY,
    ]
    assert result.minimal_result.status is IntrospectionStatus.ENABLED
    assert result.full_result.status is IntrospectionStatus.ENDPOINT_ERROR
    assert result.status is IntrospectionStatus.ENDPOINT_ERROR  # legacy full result preserved
    assert result.fallback_reason.value == reason
    assert result.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
    assert result.selected_schema_response is result.reduced_response
    assert message in result.full_result.reason
    assert parse_introspection_response(result.selected_schema_response.body).query_root == "Query"


@pytest.mark.parametrize(
    "code",
    [
        "QUERY_TOO_COMPLEX",
        "QUERY_TOO_DEEP",
        "MAX_DEPTH_EXCEEDED",
        "COMPLEXITY_LIMIT_EXCEEDED",
        "COST_LIMIT_EXCEEDED",
    ],
)
def test_safe_extension_codes(code):
    body = json.dumps(
        {"errors": [{"message": "Request rejected", "extensions": {"code": code}}]}
    ).encode()
    assert reduced_introspection_fallback_reason(200, body) is not None
    queries = []

    def handler(request):
        query = json.loads(request.content)["query"]
        queries.append(query)
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": {"__schema": {}}})
        if query == FULL_INTROSPECTION_QUERY:
            return httpx.Response(422, content=body)
        assert query == REDUCED_INTROSPECTION_QUERY
        return httpx.Response(200, json=introspection_body())

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert queries == [
        MINIMAL_INTROSPECTION_QUERY,
        FULL_INTROSPECTION_QUERY,
        REDUCED_INTROSPECTION_QUERY,
    ]
    assert result.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
    assert result.selected_schema_response is result.reduced_response


NON_ELIGIBLE = [
    (401, {"errors": [{"message": "Query too deep"}]}),
    (403, {"errors": [{"message": "Query too deep"}]}),
    (413, {"errors": [{"message": "Query depth limit exceeded."}]}),
    (500, {"errors": [{"message": "Query too deep"}]}),
    (503, {"errors": [{"message": "Unavailable"}]}),
    (504, b"<html>Gateway Timeout</html>"),
    *(
        (
            status,
            {"errors": [{"message": "Request rejected", "extensions": {"code": "QUERY_TOO_DEEP"}}]},
        )
        for status in (502, 503, 504)
    ),
    (429, {"errors": [{"message": "Query too deep"}]}),
    (400, {"errors": [{"message": 'Cannot query field "other"'}]}),
    (400, {"errors": [{"message": "Business input rejected"}]}),
    (200, {"errors": [{"message": "Introspection is disabled"}]}),
    (200, {"errors": [{"message": 'Cannot query field "__schema"'}]}),
    (200, {"errors": [{"message": '"__schema" forbidden'}]}),
    (200, {"errors": [{"message": "authentication_required"}]}),
    (200, {"errors": [{"message": "authorization_denied"}]}),
    (200, {"errors": [{"message": "The stored cost is missing"}]}),
    (200, {"errors": [{"message": "Maximum cost for the order is invalid"}]}),
    (200, {"errors": [{"message": "Depth must be a valid business input"}]}),
    (200, {"errors": [{"message": "Query too deep"}, {"message": "Unauthorized"}]}),
    (200, {"errors": [{"message": "Query too deep"}, {"message": "Authorization denied"}]}),
    (200, {"errors": [{"message": "Query too deep"}, {"message": "Introspection disabled"}]}),
    (200, {"errors": [{"message": "Query too deep", "extensions": {"code": "FORBIDDEN"}}]}),
    (200, {"errors": [{"message": "Query too deep"}, {"message": "Resolver failed"}]}),
    (200, {"errors": [{"extensions": {"code": "QUERY_TOO_DEEP"}}]}),
    (200, {"data": None}),
    (200, b"{malformed"),
    (404, b"not here"),
]


@pytest.mark.parametrize(
    "message",
    [
        "Cannot query field __schema",
        "Authentication is required",
        "Authorization was denied",
        "Introspection disabled",
        "__schema is disabled",
    ],
)
def test_explicit_denial_overrides_a_limit_extension(message):
    body = json.dumps(
        {"errors": [{"message": message, "extensions": {"code": "QUERY_TOO_DEEP"}}]}
    ).encode()
    assert reduced_introspection_fallback_reason(200, body) is None


@pytest.mark.parametrize("stage", ["minimal", "full"])
@pytest.mark.parametrize("status,body", NON_ELIGIBLE)
def test_non_eligible_failures_do_not_fall_back(stage, status, body):
    requests = []

    def handler(request):
        query = json.loads(request.content)["query"]
        requests.append(query)
        if stage == "full" and query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": {"__schema": {}}})
        return (
            httpx.Response(status, content=body)
            if isinstance(body, bytes)
            else httpx.Response(status, json=body)
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert requests == [MINIMAL_INTROSPECTION_QUERY] + (
        [FULL_INTROSPECTION_QUERY] if stage == "full" else []
    )
    assert not result.reduced_retrieval_attempted
    assert result.selected_schema_response is None
    if stage == "full":
        assert "reduced fallback not attempted" in result.schema_retrieval_summary
        assert f"HTTP {status}" in result.schema_retrieval_summary
        assert "reduced fallback not attempted" in result.schema_retrieval_reason
    else:
        assert result.schema_retrieval_summary is None


@pytest.mark.parametrize(
    "failure",
    [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError, httpx.TooManyRedirects],
)
@pytest.mark.parametrize("stage,count", [("minimal", 1), ("full", 2), ("reduced", 3)])
def test_transport_failure_is_bounded(failure, stage, count):
    requests = []

    def handler(request):
        query = json.loads(request.content)["query"]
        requests.append(query)
        if len(requests) == count:
            raise failure("offline", request=request)
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": {"__schema": {}}})
        return httpx.Response(200, json={"errors": [{"message": "Query too deep"}]})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert len(requests) == count
    assert result.selected_schema_response is None
    assert result.schema_retrieval_status is (
        SchemaRetrievalStatus.NOT_ATTEMPTED if stage == "minimal" else SchemaRetrievalStatus.FAILED
    )
    if stage == "reduced":
        assert "one reduced fallback attempted and failed" in result.schema_retrieval_summary
    elif stage == "full":
        assert "reduced fallback not attempted" in result.schema_retrieval_summary


@pytest.mark.parametrize("transport_timeout", [False, True], ids=["http-504", "read-timeout"])
def test_full_gateway_timeout_and_transport_timeout_preserve_distinct_provenance(
    monkeypatch, transport_timeout
):
    requests = []
    gateway_body = b"<html>Gateway Timeout</html>"

    def handler(request):
        requests.append(request)
        assert str(request.url) == TARGET
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        query = json.loads(request.content)["query"]
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(
                200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
            )
        assert query == FULL_INTROSPECTION_QUERY, "Unexpected reduced or downstream request"
        if transport_timeout:
            raise httpx.ReadTimeout("offline timeout", request=request)
        return httpx.Response(504, content=gateway_body, headers={"X-Fixture": "gateway"})

    monkeypatch.setattr(
        "httpx._client.HTTPTransport", lambda **kwargs: httpx.MockTransport(handler)
    )
    safe = run_safe_execution_scan(TARGET)
    introspection = safe.query_generation.operation_analysis.schema_scan.introspection
    endpoint = introspection.introspections[0]
    assert [json.loads(r.content)["query"] for r in requests if r.method == "POST"] == [
        MINIMAL_INTROSPECTION_QUERY,
        FULL_INTROSPECTION_QUERY,
    ]
    assert len(requests) == 3  # Discovery GET plus exactly two introspection attempts.
    assert endpoint.minimal_result.status is IntrospectionStatus.ENABLED
    assert endpoint.minimal_result.reason == "Response contains a data.__schema object."
    expected_category = "network_failure" if transport_timeout else "endpoint_error"
    expected_status = "failed" if transport_timeout else "blocked"
    full_reason = (
        "HTTP request timed out." if transport_timeout else "HTTP 504 prevented introspection."
    )
    summary = (
        "Full retrieval unsuccessful"
        + ("" if transport_timeout else " (HTTP 504)")
        + "; reduced fallback not attempted."
    )
    assert endpoint.full_retrieval_attempted
    assert endpoint.full_result.status.value == endpoint.status.value == expected_category
    assert endpoint.full_result.reason == full_reason
    assert endpoint.reduced_result is None and endpoint.reduced_response is None
    assert not endpoint.reduced_retrieval_attempted
    assert endpoint.fallback_reason is None
    assert endpoint.selected_schema_response is None
    assert endpoint.schema_retrieval_status.value == expected_status
    assert endpoint.schema_retrieval_summary == summary
    assert endpoint.schema_retrieval_reason == summary + " " + full_reason
    if transport_timeout:
        assert endpoint.full_response is None
        assert endpoint.full_error_type == "HttpTimeoutError"
        assert endpoint.full_error_message == "HTTP request timed out."
    else:
        assert endpoint.full_error_type is None and endpoint.full_error_message is None
        assert endpoint.full_response.status_code == 504
        assert endpoint.full_response.body == gateway_body
        assert endpoint.full_response.headers["x-fixture"] == "gateway"
        assert endpoint.full_response.duration_seconds >= 0
    assert safe.query_generation.operation_analysis.schema_scan.schemas == ()
    assert safe.query_generation.queries == () and safe.executions == ()
    assert len(safe.evidence) == 3
    assert len(introspection.introspection_evidence) == 1
    evidence = introspection.introspection_evidence[0]
    assert evidence.evidence_type is EvidenceType.INTROSPECTION_RESULT
    assert evidence.summary.startswith(expected_category.upper())
    assert "Full retrieval attempted: yes" in evidence.notes
    assert "Reduced fallback attempted: yes" not in evidence.notes
    report = build_report(safe)
    canonical = render_report(report, ReportFormat.JSON)
    projected = json.loads(canonical)["endpoints"][0]
    assert projected["introspection_status"] == expected_category
    assert projected["minimal_introspection_status"] == "enabled"
    assert projected["schema_retrieval_status"] == expected_status
    assert projected["schema_retrieval_category"] == expected_category
    assert projected["schema_retrieval_reason"] == summary + " " + full_reason
    assert projected["schema_retrieval_summary"] == summary
    assert projected["schema_summary"] is None
    assert json.loads(canonical)["report_schema_version"] == 2
    assert report.evidence == safe.evidence
    assessment = build_assessment(report)
    assert not assessment.findings and assessment.additional_policy_violations == 0

    def unexpected(*args, **kwargs):
        pytest.fail("Rendering attempted another request")

    monkeypatch.setattr(HttpClient, "send", unexpected)
    for verbose in (False, True):
        output = StringIO()
        render_completed_assessment(
            Console(file=output, width=60, theme=CONSOLE_THEME), safe, verbose=verbose
        )
        text = " ".join(output.getvalue().split())
        assert summary in text
        assert "Introspection ENABLED: 1" in text
        assert "Schema retrieval " + expected_status.upper() + ": 1" in text
        assert "\x1b" not in text
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format).replace("\\", "")
        assert summary in text and expected_status.upper() in text
        assert "ENABLED" in text
        assert text.rfind("Safety Notice") > text.rfind("Introspection")
    assert render_report(report, ReportFormat.JSON) == canonical
    assert len(requests) == 3


@pytest.mark.parametrize(
    "body,expected",
    [
        ({"errors": [{"message": "Query too deep"}]}, SchemaRetrievalStatus.BLOCKED),
        (b"bad JSON", SchemaRetrievalStatus.FAILED),
    ],
)
def test_reduced_failure_never_gets_a_fourth_request(body, expected):
    queries = []

    def handler(request):
        queries.append(json.loads(request.content)["query"])
        if len(queries) == 1:
            return httpx.Response(200, json={"data": {"__schema": {}}})
        if len(queries) == 2:
            return httpx.Response(200, json={"errors": [{"message": "Query too deep"}]})
        assert len(queries) == 3
        return (
            httpx.Response(200, content=body)
            if isinstance(body, bytes)
            else httpx.Response(200, json=body)
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert len(queries) == 3
    assert result.schema_retrieval_status is expected
    assert result.selected_schema_response is None


def test_static_reduced_document_and_existing_parser_preserve_structure():
    def depth(query):
        document = parse(query)
        fragments = {
            n.name.value: n for n in document.definitions if isinstance(n, FragmentDefinitionNode)
        }

        def walk(selection):
            return max(
                (
                    walk(fragments[n.name.value].selection_set)
                    if isinstance(n, FragmentSpreadNode)
                    else 1 + (walk(n.selection_set) if n.selection_set else 0)
                    for n in selection.selections
                ),
                default=0,
            )

        operation = next(n for n in document.definitions if isinstance(n, OperationDefinitionNode))
        assert operation.name is None
        return walk(operation.selection_set)

    assert depth(REDUCED_INTROSPECTION_QUERY) == 9
    assert depth(FULL_INTROSPECTION_QUERY) == 13
    assert len(REDUCED_INTROSPECTION_QUERY) < len(FULL_INTROSPECTION_QUERY) * 0.75
    partial = parse_introspection_response(json.dumps(introspection_body()).encode())
    full = parse_introspection_response(
        json.dumps(introspection_body(FULL_INTROSPECTION_QUERY)).encode()
    )
    assert partial.summary == full.summary
    assert (partial.query_root, partial.mutation_root, partial.subscription_root) == (
        "Query",
        "Mutation",
        "Subscription",
    )
    query = partial.type_named("Query")
    fields = {f.name: f for f in query.fields}
    assert [
        fields[n].type.render()
        for n in ("plain", "required", "list", "listRequired", "requiredList")
    ] == ["String", "String!", "[String]", "[String!]", "[String!]!"]
    assert fields["legacyToken"].is_deprecated
    assert fields["legacyToken"].deprecation_reason == "Use other authentication"
    assert partial.type_named("User").interfaces == ("Node",)
    assert partial.type_named("Node").possible_types == ("User",)
    assert partial.type_named("SearchResult").possible_types == ("User",)
    assert partial.type_named("Options").input_fields[0].default_value == "FIRST"
    assert partial.type_named("Choice").enum_values[1].is_deprecated
    assert partial.directives


@pytest.mark.parametrize(
    "sdl", ["type Query { deep: [[String!]!]! }", "type Mutation { x: String }"]
)
def test_unrepresentable_or_missing_root_fails_without_guessed_structure(sdl):
    # Missing query roots are malformed retrievals, rather than valid executable schemas.
    if "type Query" not in sdl:
        body = introspection_body()
        body["data"]["__schema"]["queryType"] = None
    else:
        body = introspection_body(sdl=sdl)
    with pytest.raises(SchemaParsingError):
        parse_introspection_response(json.dumps(body).encode())


def scan_fixture(
    monkeypatch,
    *,
    fallback=True,
    mode=ScanMode.SAFE,
    sdl=SDL,
    full_status=200,
    reduced_outcome="success",
):
    requests = []
    configurations = []

    def handler(request):
        requests.append(request)
        assert request.url.host == "127.0.0.1"
        assert request.headers["x-test-secret"] == "SCHEMA001_FAKE_SECRET"
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        query = json.loads(request.content)["query"]
        assert not query.lstrip().startswith(("mutation", "subscription"))
        if query == FULL_INTROSPECTION_QUERY and fallback:
            return httpx.Response(
                full_status,
                json={"errors": [{"message": "Query depth limit exceeded. PRIVATE_ERROR_CANARY"}]},
            )
        if query == REDUCED_INTROSPECTION_QUERY:
            if reduced_outcome == "blocked":
                return httpx.Response(
                    200, json={"errors": [{"message": "Query depth limit exceeded."}]}
                )
            if reduced_outcome == "invalid":
                return httpx.Response(200, content=b"invalid JSON")
            if reduced_outcome == "transport":
                raise httpx.ReadTimeout("offline", request=request)
        if "__schema" in query:
            return httpx.Response(200, json=introspection_body(query, sdl))
        field = parse(query).definitions[0].selection_set.selections[0].name.value
        return httpx.Response(200, json={"data": {field: None}})

    def transport(**kwargs):
        configurations.append(kwargs)
        return httpx.MockTransport(handler)

    monkeypatch.setattr("httpx._client.HTTPTransport", transport)
    safe = run_safe_execution_scan(
        TARGET,
        mode=mode,
        http_settings=HttpClientSettings(
            timeout_seconds=17, custom_headers=(("X-Test-Secret", "SCHEMA001_FAKE_SECRET"),)
        ),
    )
    assert all(c["trust_env"] is False for c in configurations)
    assert all(r.extensions["timeout"]["read"] == 17 for r in requests if r.method == "POST")
    return safe, requests


@pytest.mark.parametrize("mode", [ScanMode.SAFE, ScanMode.ACTIVE])
@pytest.mark.parametrize(
    "fallback,full_status,reduced_outcome,status,category,count,provenance",
    [
        (False, 200, "success", "retrieved", "enabled", 2, None),
        (True, 200, "success", "partial", "enabled", 3, "attempted and succeeded"),
        (True, 200, "blocked", "blocked", "endpoint_error", 3, "attempted and was also rejected"),
        (True, 200, "invalid", "failed", "invalid_response", 3, "attempted and failed"),
        (True, 200, "transport", "failed", "network_failure", 3, "attempted and failed"),
        (True, 413, "success", "blocked", "endpoint_error", 2, "reduced fallback not attempted"),
    ],
)
def test_final_retrieval_path_survives_evidence_console_and_report_projection(
    monkeypatch, mode, fallback, full_status, reduced_outcome, status, category, count, provenance
):
    safe, requests = scan_fixture(
        monkeypatch,
        mode=mode,
        fallback=fallback,
        full_status=full_status,
        reduced_outcome=reduced_outcome,
    )
    original_count = len(requests)
    schema_scan = safe.query_generation.operation_analysis.schema_scan
    introspection = schema_scan.introspection
    endpoint = introspection.introspections[0]
    queries = [
        json.loads(r.content)["query"]
        for r in requests
        if r.method == "POST" and "__schema" in json.loads(r.content)["query"]
    ]
    assert queries == [MINIMAL_INTROSPECTION_QUERY, FULL_INTROSPECTION_QUERY] + (
        [REDUCED_INTROSPECTION_QUERY] if count == 3 else []
    )
    assert endpoint.minimal_result.status is IntrospectionStatus.ENABLED
    assert endpoint.full_response is not None
    assert endpoint.status.value == ("endpoint_error" if fallback else "enabled")
    assert endpoint.schema_retrieval_status.value == status
    if status in {"blocked", "failed"}:
        assert endpoint.selected_schema_response is None
        assert schema_scan.schemas == ()
        assert safe.executions == ()
    elif status == "partial":
        assert endpoint.selected_schema_response is endpoint.reduced_response
        assert schema_scan.schemas[0].success
    else:
        assert endpoint.selected_schema_response is endpoint.full_response
    evidence = introspection.introspection_evidence[0]
    assert evidence.evidence_type is EvidenceType.INTROSPECTION_RESULT
    if count == 3:
        assert endpoint.fallback_reason.value == "depth_limit"
        assert endpoint.reduced_result.status.value == category
        assert "Query depth limit exceeded." in endpoint.full_result.reason
        assert "Full restriction: depth_limit" in evidence.notes
        assert "Reduced fallback attempted: yes" in evidence.notes
        assert f"Reduced retrieval outcome: {category}" in evidence.notes
        assert f"Schema retrieval: {status}" in evidence.notes
    report = build_report(safe)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert canonical["report_schema_version"] == 2
    projected = canonical["endpoints"][0]
    assert projected["schema_retrieval_status"] == status
    assert projected["schema_retrieval_category"] == category
    assert projected["schema_retrieval_reason"] == endpoint.schema_retrieval_reason
    assert projected["schema_retrieval_summary"] == endpoint.schema_retrieval_summary
    assert report.evidence == safe.evidence
    for width in (60, 120):
        for renderer in (render_pre_active_context, render_completed_assessment):
            output = StringIO()
            renderer(Console(file=output, theme=CONSOLE_THEME, width=width), safe)
            text = " ".join(output.getvalue().split())
            if renderer is render_pre_active_context and mode is ScanMode.SAFE:
                assert not text
                continue
            if provenance:
                assert provenance in text
                assert "Full retrieval" in text
            else:
                assert "fallback" not in text.lower()
            assert "PRIVATE_ERROR_CANARY" not in text
            assert "SCHEMA001_FAKE_SECRET" not in text
            assert "__schema" not in text
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format)
        if provenance:
            assert provenance in rendered
        else:
            assert "fallback" not in rendered.lower()
        if status == "blocked" and count == 3:
            assert "Query depth limit exceeded" in rendered
            assert "no schema selected" in rendered
        if status == "partial":
            assert "PARTIAL" in rendered and "coverage may be incomplete" in rendered
        assert "SCHEMA001_FAKE_SECRET" not in rendered
        assert rendered.count("Safety Notice") == 1
        assert rendered.rfind("Safety Notice") > rendered.rfind("Introspection")
    assert len(requests) == original_count


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("mode", [ScanMode.SAFE, ScanMode.ACTIVE])
def test_complete_mock_pipeline_provenance_reports_ai_and_no_new_execution_authority(
    monkeypatch, fallback, mode
):
    safe, requests = scan_fixture(monkeypatch, fallback=fallback, mode=mode)
    count = len(requests)
    generation = safe.query_generation
    schemas = generation.operation_analysis.schema_scan
    endpoint = schemas.introspection.introspections[0]
    introspection_queries = [
        json.loads(r.content)["query"]
        for r in requests
        if r.method == "POST" and "__schema" in json.loads(r.content)["query"]
    ]
    assert introspection_queries == [MINIMAL_INTROSPECTION_QUERY, FULL_INTROSPECTION_QUERY] + (
        [REDUCED_INTROSPECTION_QUERY] if fallback else []
    )
    expected = SchemaRetrievalStatus.PARTIAL if fallback else SchemaRetrievalStatus.RETRIEVED
    assert endpoint.schema_retrieval_status is expected
    assert schemas.schemas[0].success
    assert schemas.schemas[0].schema_retrieval_status is expected
    assert len(generation.operation_analysis.endpoints[0].operations) == 12
    assert len(generation.queries) == 10
    assert len(safe.execution_evidence) == 10
    assert generation.security_review.candidates
    assert parse_introspection_schemas(schemas.introspection).schemas == schemas.schemas
    assert not any(e.evidence_type is EvidenceType.MUTATION_EXECUTION for e in safe.evidence)
    if mode is ScanMode.ACTIVE:
        preview = prepare_active_mutations(safe)
        assert len(preview.candidates) == 2
        assert any(not c.selectable for c in preview.candidates)
        # Later capabilities reconstruct from the selected bytes, not the rejected full response.
        assert retained_mutation(safe, "createUser")[2].name == "createUser"
        depth_preview = prepare_query_depth(safe)
        # This fixture's prioritized scalar Query cannot reach the cycle: the existing
        # structural gate must hold after native-schema reconstruction from either source.
        assert depth_preview.limitations == (
            TARGET + ": Representative Query cannot reach the retained recursive witness.",
        )
        output = StringIO()
        render_pre_active_context(Console(file=output, theme=CONSOLE_THEME, width=60), safe)
        assert expected.value.upper() in output.getvalue()
        if fallback:
            assert "Partial schema" in output.getvalue()

    report = build_report(safe)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert canonical["report_schema_version"] == 2
    assert canonical["endpoints"][0]["schema_retrieval_status"] == expected.value
    assert canonical["endpoints"][0]["schema_summary"]["query_field_count"] == 10
    assessment = build_assessment(report)
    assert dict(assessment.overview)["Schema retrieval"] == expected.value.upper() + ": 1"
    assert "No parsed schema was available" not in str(assessment)
    if fallback:
        assert "coverage may be incomplete" in str(assessment)
        assert "PARTIAL" in schemas.introspection.introspection_evidence[0].summary
    for render in (render_scan, render_completed_assessment):
        for verbose in (False, True):
            output = StringIO()
            render(Console(file=output, theme=CONSOLE_THEME, width=120), safe, verbose=verbose)
            assert expected.value.upper() in output.getvalue()
            assert "BLOCKED" not in output.getvalue()
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format)
        assert expected.value.upper() in rendered
        assert rendered.count("Safety Notice") == 1
        assert "AI-Assisted" not in rendered.split("Safety Notice")[-1]
    context = build_ai_context(safe)
    serialized = serialize_context(context)
    assert context.schemas[0].schema_retrieval == expected.value
    assert context.counts["introspection_unavailable"] == 0
    for secret in (
        TARGET,
        "SCHEMA001_FAKE_SECRET",
        "PRIVATE_ERROR_CANARY",
        "__schema",
        "depth_limit",
    ):
        assert secret not in serialized
    assert len(serialized.encode()) <= MAX_CONTEXT_BYTES == 12000
    assert len(context.operations) <= MAX_AI_OPERATIONS == 12
    assert "schema_retrieval" not in json.dumps(AIInterpretation.model_json_schema())
    assert len(requests) == count  # parsing/presentation/reports/AI projection are local


@pytest.mark.parametrize(
    "body",
    [
        {"data": {"__schema": {}}},
        introspection_body(sdl="type Query { deep: [[String!]!]! }"),
    ],
)
def test_unusable_reduced_structure_is_controlled_at_parsing(monkeypatch, body):
    safe, requests = scan_fixture(monkeypatch)
    schemas = safe.query_generation.operation_analysis.schema_scan
    endpoint = schemas.introspection.introspections[0]
    count = len(requests)
    malformed = replace(
        endpoint,
        reduced_response=endpoint.reduced_response.model_copy(
            update={"body": json.dumps(body).encode()}
        ),
    )
    result = parse_introspection_schemas(
        replace(schemas.introspection, introspections=(malformed,))
    )
    assert len(result.schemas) == 1
    assert result.schemas[0].schema is None
    assert result.schemas[0].error_type == "SchemaParsingError"
    assert result.schemas[0].schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
    assert len(requests) == count


def test_named_contexts_do_not_share_fallback_or_headers(monkeypatch):
    from gqlsleuth.application.differential_review import run_differential_scan
    from gqlsleuth.domain.differential import NamedAuthContext

    requests = []
    bodies = {
        "one": introspection_body(),
        "two": introspection_body(sdl="type Query { distinct: String }"),
    }

    def handler(request):
        context = request.headers["x-context"]
        requests.append((context, request))
        assert request.headers["authorization"] == f"Bearer SCHEMA001_{context}_SECRET"
        if request.method == "GET":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        query = json.loads(request.content)["query"]
        if query == MINIMAL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"data": {"__schema": {}}})
        if query == FULL_INTROSPECTION_QUERY:
            return httpx.Response(200, json={"errors": [{"message": "Query too complex"}]})
        if query == REDUCED_INTROSPECTION_QUERY:
            return httpx.Response(200, json=bodies[context])
        return httpx.Response(200, json={"data": None})

    monkeypatch.setattr("httpx._client.HTTPTransport", lambda **kw: httpx.MockTransport(handler))
    result = run_differential_scan(
        TARGET,
        contexts=tuple(
            NamedAuthContext(
                name, (("X-Context", name), ("Authorization", f"Bearer SCHEMA001_{name}_SECRET"))
            )
            for name in ("one", "two")
        ),
    )
    for context in result.contexts:
        schemas = context.scan.query_generation.operation_analysis.schema_scan
        assert schemas.schemas[0].schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
        queries = [
            json.loads(r.content)["query"]
            for name, r in requests
            if name == context.name
            and r.method == "POST"
            and "__schema" in json.loads(r.content)["query"]
        ]
        assert queries == [
            MINIMAL_INTROSPECTION_QUERY,
            FULL_INTROSPECTION_QUERY,
            REDUCED_INTROSPECTION_QUERY,
        ]
    first, second = (
        c.scan.query_generation.operation_analysis.schema_scan.schemas[0] for c in result.contexts
    )
    assert first.summary.query_field_count == 10
    assert second.summary.query_field_count == 1
    assert not any(
        c.kind is DifferenceKind.OPERATION_VISIBILITY_DIFFERENCE for c in result.pairs[0].candidates
    )
    count = len(requests)
    report = build_differential_report(result)
    for format in ReportFormat:
        text = render_report(report, format)
        assert "SCHEMA001_one_SECRET" not in text
        assert "SCHEMA001_two_SECRET" not in text
    assert len(requests) == count


def test_partial_context_never_proves_operation_absence(monkeypatch):
    partial, _ = scan_fixture(monkeypatch, sdl=SDL.replace("  plain: String", ""))
    full, _ = scan_fixture(monkeypatch, fallback=False)
    schema_scan = full.query_generation.operation_analysis.schema_scan
    target = schema_scan.introspection.detection.discovery.target
    result = compare_context_scans(
        target, (ContextScanResult("first", partial), ContextScanResult("second", full))
    )
    assert not any(
        c.kind is DifferenceKind.OPERATION_VISIBILITY_DIFFERENCE for c in result.pairs[0].candidates
    )
    assert any("Partial schema" in item.reason for item in result.pairs[0].limitations)
    report = build_differential_report(result)
    for format in ReportFormat:
        text = render_report(report, format)
        assert "partial" in text.lower() and "retrieved" in text.lower()


def test_full_parse_failure_does_not_trigger_fallback(monkeypatch):
    safe, requests = scan_fixture(monkeypatch, fallback=False)
    schemas = safe.query_generation.operation_analysis.schema_scan
    endpoint = schemas.introspection.introspections[0]
    malformed = replace(
        endpoint,
        full_response=endpoint.full_response.model_copy(
            update={"body": b'{"data":{"__schema":{}}}'}
        ),
    )
    parsed = parse_introspection_schemas(
        replace(schemas.introspection, introspections=(malformed,))
    )
    assert not parsed.schemas[0].success
    assert not malformed.reduced_retrieval_attempted
    assert (
        len(
            [
                r
                for r in requests
                if r.method == "POST" and "__schema" in json.loads(r.content)["query"]
            ]
        )
        == 2
    )
