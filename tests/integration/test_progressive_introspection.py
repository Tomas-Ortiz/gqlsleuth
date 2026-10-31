"""Bounded recovery, faithful local assembly, and partial facts without execution authority."""

import json
from io import StringIO

import httpx
import pytest
from graphql import graphql_sync
from rich.console import Console

from fixtures.progressive_introspection import QUERY_ONLY, SDL, mock_recovery, query_depth
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.application.active_execution import prepare_active_mutations
from gqlsleuth.application.introspection import _introspect_endpoint
from gqlsleuth.application.mutation_preparation import retained_mutation
from gqlsleuth.application.progressive_introspection import MAX_PROGRESSIVE_REQUESTS, recover_schema
from gqlsleuth.application.safe_execution import run_safe_execution_scan
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.graphql.introspection import (
    FULL_INTROSPECTION_QUERY,
    SchemaRetrievalStatus,
)
from gqlsleuth.graphql.progressive_introspection import (
    CATALOGUE_QUERY,
    DIRECTIVES_QUERY,
    MAX_RECOVERY_DEPTH,
    MAX_RECOVERY_QUERY_BYTES,
    TYPE_QUERIES,
    AssembledSchema,
)
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.infrastructure.redirect_consent import RedirectConsent
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_pre_active_context
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report

TARGET = "http://127.0.0.1:8123/graphql"


@pytest.mark.parametrize("sdl", [SDL, QUERY_ONLY])
@pytest.mark.parametrize("depth", [8, 6, 3, 2])
def test_real_graphql_execution_under_fixed_depth_policies(sdl, depth):
    handler, seen, schema = mock_recovery(sdl, depth=depth)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    recovery = result.progressive
    assert recovery is not None
    assert len(seen) == 3 + len(recovery.attempts) <= 35
    assert result.selected_schema_response is None  # No fabricated HTTP response.
    requests = [json.loads(request.content) for request in seen]
    assert len({json.dumps(p, sort_keys=True) for p in requests}) == len(requests)
    if depth == 8:
        assert result.schema_retrieval_status is SchemaRetrievalStatus.RETRIEVED
        assert isinstance(result.selected_schema_source, AssembledSchema)
        recovered = parse_introspection_response(result.selected_schema_source.body)
        full = parse_introspection_response(
            json.dumps(graphql_sync(schema, FULL_INTROSPECTION_QUERY).formatted).encode()
        )
        assert recovered.summary == full.summary
        assert recovered.query_root == schema.query_type.name
        if sdl == SDL:
            assert recovered.type_named("Person").fields[0].type.render() == "[Person!]!"
            assert recovered.type_named("Person").interfaces == ("Node",)
            assert recovered.type_named("Search").possible_types == ("Person",)
            assert recovered.type_named("Filter").input_fields
            assert recovered.type_named("Role").enum_values
    elif depth >= 3:
        assert result.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
        assert result.selected_schema_source is None
        assert recovery.types[0].field_names
        assert not recovery.types[0].complete
        assert "Known Queries:" in recovery.summary and "Unknown" not in recovery.summary
        assert "automatic Query generation/execution is unavailable" in recovery.summary
    else:
        assert result.schema_retrieval_status is SchemaRetrievalStatus.BLOCKED
        assert recovery.catalogue is None and len(recovery.attempts) == 1
    for attempt in recovery.attempts:
        assert attempt.response is not None
        if attempt.variables:
            assert attempt.variables["name"] in dict(recovery.catalogue.types)


def test_fixed_query_shapes_are_bounded_standard_graphql():
    queries = [CATALOGUE_QUERY, *(query for _, query in TYPE_QUERIES), DIRECTIVES_QUERY]
    assert [query_depth(q) for q in queries] == [3, 8, 6, 3, 8]
    assert max(query_depth(q) for q in queries) == MAX_RECOVERY_DEPTH
    assert all(len(q.encode()) <= MAX_RECOVERY_QUERY_BYTES for q in queries)
    assert all("mutation " not in q and "subscription " not in q for q in queries)


def test_deeper_unresolved_wrappers_never_become_executable():
    handler, _, _ = mock_recovery("type Query { deep: [[String!]!]! }")
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert result.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
    assert result.progressive.types[0].field_names == ("deep",)
    assert not result.progressive.types[0].complete
    assert result.selected_schema_source is None


def test_catalogue_order_does_not_change_request_order_or_assembly():
    results = []
    schema = mock_recovery()[2]
    for reverse in (False, True):

        def reorder(request, count, reverse=reverse):
            if count == 4 and reverse:
                data = graphql_sync(schema, CATALOGUE_QUERY).data
                data["__schema"]["types"].reverse()
                return httpx.Response(200, json={"data": data})
            return None

        handler, seen, _ = mock_recovery(override=reorder)
        with HttpClient(transport=httpx.MockTransport(handler)) as client:
            result = _introspect_endpoint(TARGET, client)
        results.append(([json.loads(r.content) for r in seen], result.selected_schema_source.body))
    assert results[0] == results[1]


@pytest.mark.parametrize("approve", [None, False, True])
def test_progressive_redirect_consent_and_header_context_isolation(approve):
    consent = RedirectConsent(None if approve is None else lambda _: approve)
    for secret in ("FAKE_PROGRESSIVE_A", "FAKE_PROGRESSIVE_B"):

        def redirect(request, count, secret=secret):
            assert request.headers["authorization"] == secret
            if (
                "__type(" in json.loads(request.content)["query"]
                and request.url.host == "127.0.0.1"
            ):
                return httpx.Response(307, headers={"location": "https://other.example/graphql"})
            return None

        handler, seen, _ = mock_recovery(override=redirect)
        with HttpClient(
            HttpClientSettings(
                custom_headers=(("Authorization", secret),), redirect_consent=consent
            ),
            transport=httpx.MockTransport(handler),
        ) as client:
            result = _introspect_endpoint(TARGET, client)
        destinations = [r for r in seen if r.url.host == "other.example"]
        assert bool(destinations) is bool(approve)
        assert result.progressive.status is (
            SchemaRetrievalStatus.RETRIEVED if approve else SchemaRetrievalStatus.PARTIAL
        )
        assert secret not in result.reason


@pytest.mark.parametrize("failure", ["interface", "deprecated", "directives", "missing_reference"])
def test_contradictory_metadata_prevents_complete_assembly(failure):
    def alter(request, count):
        payload = json.loads(request.content)
        query = payload["query"]
        if payload.get("variables", {}).get("name") == "Person":
            data = graphql_sync(schema, query, variable_values=payload["variables"]).data
            if failure == "interface":
                data["__type"]["interfaces"] = []
            elif failure == "deprecated":
                data["__type"]["fields"][0]["isDeprecated"] = True
            elif failure == "missing_reference":
                data["__type"]["fields"][0]["type"] = {"kind": "SCALAR", "name": "UnknownScalar"}
            return httpx.Response(200, json={"data": data})
        if query == DIRECTIVES_QUERY and failure == "directives":
            return httpx.Response(200, json={"data": {"__schema": {"directives": [{}]}}})
        return None

    handler, _, schema = mock_recovery(override=alter)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert result.selected_schema_source is None
    assert result.progressive.status is SchemaRetrievalStatus.PARTIAL


def test_per_type_field_expansion_is_bounded():
    sdl = "type Query { " + " ".join(f"f{i}: String" for i in range(257)) + " }"
    handler, seen, _ = mock_recovery(sdl)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert len(seen) == 5
    assert not result.progressive.types
    assert "local limit" in result.progressive.limitation
    assert "Known Queries: Unknown" in result.progressive.summary


@pytest.mark.parametrize("depth", [8, 6, 3])
def test_global_request_budget_includes_rejected_shapes(depth):
    sdl = "type Query { " + " ".join(f"field{i}: T{i}" for i in range(40)) + " } "
    sdl += " ".join(f"type T{i} {{ id: ID! }}" for i in range(40))
    handler, seen, _ = mock_recovery(sdl, depth=depth)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    recovery = result.progressive
    assert len(recovery.attempts) == MAX_PROGRESSIVE_REQUESTS == 32
    assert len(seen) == 35
    assert recovery.status is SchemaRetrievalStatus.PARTIAL
    assert recovery.assembled is None
    assert "budget exhausted" in recovery.limitation
    assert len(recovery.types) <= 31
    assert recovery.types[0].name == "Query"


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_intermediate_denial_stops_without_losing_verified_inventory(status):
    def deny(request, count):
        if count == 6:
            return httpx.Response(status, json={"errors": [{"message": "Query too deep"}]})
        return None

    handler, seen, _ = mock_recovery(override=deny)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert len(seen) == 6
    assert result.progressive.types[0].name == "Read"
    assert result.progressive.attempts[-1].response.status_code == status
    assert result.progressive.status is SchemaRetrievalStatus.PARTIAL
    assert result.selected_schema_source is None


@pytest.mark.parametrize(
    "failure",
    ["malformed", "identity", "missing", "conflicting_kind", "duplicates", "invalid_kind"],
)
def test_bad_segments_do_not_become_a_schema(failure):
    def change(request, count):
        payload = json.loads(request.content)
        if failure == "invalid_kind":
            if (
                payload["query"] != TYPE_QUERIES[0][1]
                or payload.get("variables", {}).get("name") != "Read"
            ):
                return None
        elif count != 5:
            return None
        if failure == "malformed":
            return httpx.Response(200, text="invalid")
        if failure == "missing":
            return httpx.Response(200, json={"data": {"__type": None}})
        item = graphql_sync(schema, payload["query"], variable_values=payload["variables"]).data[
            "__type"
        ]
        if failure == "identity":
            item["name"] = "Invented"
        elif failure == "conflicting_kind":
            item["kind"] = "SCALAR"
        elif failure == "duplicates":
            item["fields"].append(item["fields"][0])
        else:
            item["fields"][0]["type"]["kind"] = []
        return httpx.Response(200, json={"data": {"__type": item}})

    handler, seen, schema = mock_recovery(override=change)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    assert result.selected_schema_source is None
    assert result.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
    if failure != "invalid_kind":
        assert len(seen) == 5


@pytest.mark.parametrize("variant", ["duplicate", "contradictory", "malformed", "oversized"])
def test_catalogue_validation_and_type_cap(variant):
    def change(request, count):
        if count != 4:
            return None
        data = graphql_sync(schema, CATALOGUE_QUERY).data
        entries = data["__schema"]["types"]
        if variant == "duplicate":
            entries.append(entries[0])
        elif variant == "contradictory":
            entries.append({"name": entries[0]["name"], "kind": "SCALAR"})
        elif variant == "malformed":
            entries.append({"name": "bad-name", "kind": "OBJECT"})
        else:
            entries.extend({"name": f"Extra{i}", "kind": "SCALAR"} for i in range(130))
        return httpx.Response(200, json={"data": data})

    handler, seen, schema = mock_recovery(override=change)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = _introspect_endpoint(TARGET, client)
    recovery = result.progressive
    assert len(recovery.attempts) <= 32
    if variant == "duplicate":
        assert recovery.assembled is not None
        assert len({t.name for t in recovery.types}) == len(recovery.types)
    elif variant == "contradictory":
        assert recovery.status is SchemaRetrievalStatus.FAILED and len(seen) == 4
    else:
        assert not recovery.catalogue.complete
        assert len(recovery.catalogue.types) <= 128
        assert recovery.assembled is None


@pytest.mark.parametrize("failure", ["timeout", "size", "cancel"])
def test_transport_limits_and_cancel_preserve_no_later_dispatch(failure):
    def fail(request, count):
        if count == 5:
            if failure == "timeout":
                raise httpx.ReadTimeout("fake timeout")
            if failure == "cancel":
                raise KeyboardInterrupt
            return httpx.Response(200, content=b" " * 4097)
        return None

    handler, seen, _ = mock_recovery(override=fail)
    with HttpClient(
        HttpClientSettings(max_response_body_bytes=4096), transport=httpx.MockTransport(handler)
    ) as client:
        if failure == "cancel":
            with pytest.raises(KeyboardInterrupt):
                _introspect_endpoint(TARGET, client)
        else:
            result = _introspect_endpoint(TARGET, client)
            assert result.progressive.attempts[-1].error_type == (
                "HttpTimeoutError" if failure == "timeout" else "ResponseTooLargeError"
            )
            assert result.selected_schema_source is None
    assert len(seen) == 5


def test_elapsed_dispatch_budget_and_timeout_override(monkeypatch):
    clock = [0.0]

    def advance(request, count):
        assert request.extensions["timeout"]["read"] == 17
        clock[0] += 31
        return None

    monkeypatch.setattr(
        "gqlsleuth.application.progressive_introspection.monotonic", lambda: clock[0]
    )
    handler, seen, _ = mock_recovery(override=advance)
    with HttpClient(
        HttpClientSettings(timeout_seconds=17), transport=httpx.MockTransport(handler)
    ) as client:
        recovery = recover_schema(TARGET, client)
    assert len(seen) == 2
    assert recovery.types[0].name == "Read"
    assert "budget exhausted" in recovery.limitation


def test_aggregate_response_budget_reserves_room_before_dispatch(monkeypatch):
    handler, seen, _ = mock_recovery()
    monkeypatch.setattr(
        "gqlsleuth.application.progressive_introspection.MAX_PROGRESSIVE_RESPONSE_BYTES", 4096
    )
    with HttpClient(
        HttpClientSettings(max_response_body_bytes=4096), transport=httpx.MockTransport(handler)
    ) as client:
        recovery = recover_schema(TARGET, client)
    assert len(seen) == 1
    assert recovery.catalogue is not None and not recovery.types
    assert "budget exhausted" in recovery.limitation


@pytest.mark.parametrize("depth", [8, 6, 3])
@pytest.mark.parametrize("mode", [ScanMode.SAFE, ScanMode.ACTIVE])
def test_complete_workflow_evidence_reports_ai_and_execution_boundaries(monkeypatch, depth, mode):
    handler, seen, _ = mock_recovery(depth=depth)
    monkeypatch.setattr(
        "httpx._client.HTTPTransport", lambda **kwargs: httpx.MockTransport(handler)
    )
    result = run_safe_execution_scan(
        TARGET,
        mode=mode,
        http_settings=HttpClientSettings(custom_headers=(("X-Secret", "FAKE_RECOVERY_CANARY"),)),
    )
    assert all(r.headers["x-secret"] == "FAKE_RECOVERY_CANARY" for r in seen)
    scan = result.query_generation.operation_analysis.schema_scan
    endpoint = scan.introspection.introspections[0]
    recovery = endpoint.progressive
    attempts = [e for e in scan.introspection.introspection_evidence if e.query]
    assert len(attempts) == len(recovery.attempts)
    for evidence, attempt in zip(attempts, recovery.attempts, strict=True):
        assert evidence.query == attempt.query
        assert evidence.variables == attempt.variables
        assert evidence.response_body == attempt.response.body
        assert evidence.response_status_code == attempt.response.status_code
    assert not any(e.evidence_type is EvidenceType.MUTATION_EXECUTION for e in result.evidence)
    if depth == 8:
        assert scan.schemas[0].success and result.executions
        assert "locally assembled" in " ".join(scan.schema_evidence[0].notes)
        assert retained_mutation(result, "createPerson")[2].name == "createPerson"
    else:
        assert not scan.schemas and not result.executions and not result.query_generation.queries
        if mode is ScanMode.ACTIVE:
            assert not prepare_active_mutations(result).candidates
    request_count = len(seen)
    report = build_report(result)
    canonical = render_report(report, ReportFormat.JSON)
    assert json.loads(canonical)["report_schema_version"] == 2
    assert "FAKE_RECOVERY_CANARY" not in canonical
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "PROGRESSIVE" in text and "Known Queries" in text
        assert "FAKE_RECOVERY_CANARY" not in text
        assert text.count("Safety Notice") == 1
    for renderer in (render_completed_assessment, render_pre_active_context):
        output = StringIO()
        renderer(Console(file=output, theme=CONSOLE_THEME, width=55, color_system=None), result)
        if renderer is render_pre_active_context and mode is ScanMode.SAFE:
            continue
        text = " ".join(output.getvalue().split())
        assert (
            "PROGRESSIVE" in text
            and "Recovery method" in text
            and "FAKE_RECOVERY_CANARY" not in text
        )
    context = serialize_context(build_ai_context(result))
    assert (
        "__schema" not in context
        and TARGET not in context
        and "FAKE_RECOVERY_CANARY" not in context
    )
    assert len(seen) == request_count
    assert render_report(report, ReportFormat.JSON) == canonical
