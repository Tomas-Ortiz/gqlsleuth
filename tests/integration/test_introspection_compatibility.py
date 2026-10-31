"""Evidence-driven legacy argument variants; no public traffic or schema fabrication."""

import json
from io import StringIO
from itertools import combinations

import httpx
import pytest
from graphql import graphql_sync, parse
from rich.console import Console

from fixtures.progressive_introspection import (
    QUERY_ONLY,
    legacy_recovery,
    mock_recovery,
    query_depth,
)
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.application.active_execution import prepare_active_mutations
from gqlsleuth.application.introspection import _introspect_endpoint
from gqlsleuth.application.safe_execution import run_safe_execution_scan
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.graphql.introspection import (
    FULL_INTROSPECTION_QUERY,
    MINIMAL_INTROSPECTION_QUERY,
    SchemaRetrievalStatus,
)
from gqlsleuth.graphql.introspection_compatibility import (
    OPTIONAL_ARGUMENTS,
    QUERY_ARGUMENTS,
    compatible_query,
    unsupported_optional_arguments,
)
from gqlsleuth.graphql.progressive_introspection import ROOT_INVENTORY_QUERY, TYPE_QUERIES
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.infrastructure.redirect_consent import RedirectConsent
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.recovery import present_recovery
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report

TARGET = "http://127.0.0.1:8123/graphql"
SDL = """
schema { query: Read }
enum Choice { ONE OLD @deprecated }
input Options { term: String old: String @deprecated }
type Item { id: ID! old: String @deprecated }
type Read { items(options: Options, old: String @deprecated): [Item!]! legacy: String @deprecated }
directive @tag(old: String @deprecated) on FIELD
"""


def error(key, *, dotted=False):
    owner, field = key.split(".")
    message = (
        f"Unknown argument 'includeDeprecated' on field '{key}'."
        if dotted
        else f'Unknown argument "includeDeprecated" on field "{field}" of type "{owner}".'
    )
    return {"message": message}


@pytest.mark.parametrize("key", sorted(OPTIONAL_ARGUMENTS))
@pytest.mark.parametrize("dotted", [False, True])
def test_exact_compatibility_messages(key, dotted):
    body = json.dumps({"errors": [error(key, dotted=dotted)]}).encode()
    assert unsupported_optional_arguments(400, body, OPTIONAL_ARGUMENTS) == {key}
    assert not unsupported_optional_arguments(400, body, OPTIONAL_ARGUMENTS - {key})


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_status_denials_never_authorize_compatibility(status):
    body = json.dumps({"errors": [error("__Type.fields")]}).encode()
    assert not unsupported_optional_arguments(status, body, OPTIONAL_ARGUMENTS)


@pytest.mark.parametrize(
    "value",
    [
        {"errors": [error("Query.fields")]},
        {"errors": [error("__Type.unknown")]},
        {"errors": [{"message": "Unknown operation name"}]},
        {"errors": [{"message": "Unknown argument 'other' on field '__Type.fields'."}]},
        {"errors": [error("__Type.fields"), {"message": "Query too deep"}]},
        {"errors": [error("__Type.fields"), {"message": "Forbidden"}]},
        {"errors": [error("__Type.fields"), {"message": "Introspection is disabled"}]},
        {"errors": [{**error("__Type.fields"), "extensions": {"code": "FORBIDDEN"}}]},
        {"errors": [{**error("__Type.fields"), "extensions": {"code": []}}]},
        {"errors": [{**error("__Type.fields"), "extensions": []}]},
        {"errors": [error("__Type.fields")], "data": {"__type": None}},
        {"errors": []},
        {"errors": [None]},
        {"error": "Bad request"},
    ],
)
def test_mixed_unrelated_and_malformed_errors_are_ineligible(value):
    assert not unsupported_optional_arguments(400, json.dumps(value).encode(), OPTIONAL_ARGUMENTS)


@pytest.mark.parametrize("body", [b"not json", b"<html>Bad request</html>", b"[]"])
def test_non_graphql_bodies_do_not_authorize_compatibility(body):
    assert not unsupported_optional_arguments(400, body, OPTIONAL_ARGUMENTS)


@pytest.mark.parametrize("status", [200, 400, 413, 422])
def test_exact_validation_extensions_are_eligible(status):
    body = json.dumps(
        {
            "errors": [
                {**error("__Type.fields"), "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}}
            ]
        }
    ).encode()
    assert unsupported_optional_arguments(status, body, OPTIONAL_ARGUMENTS) == {"__Type.fields"}


def test_all_fixed_omission_combinations_preserve_query_depth_and_size():
    # Enumerating only in tests proves the finite template space; runtime never searches it.
    for query, allowed in QUERY_ARGUMENTS.items():
        for count in range(len(allowed) + 1):
            for keys in combinations(sorted(allowed), count):
                variant, omitted = compatible_query(query, set(keys))
                parse(variant)
                assert omitted == keys
                assert query_depth(variant) == query_depth(query) <= 8
                assert len(variant.encode()) <= len(query.encode()) <= 2048


def test_dedicated_root_inventory_avoids_confirmed_legacy_failure():
    handler, seen, _ = legacy_recovery(SDL, unsupported={"__Type.inputFields"}, depth=3)
    # Prove the former inventory fails for exactly the operator's reported reason.
    old = handler(
        httpx.Request(
            "POST", TARGET, json={"query": TYPE_QUERIES[-1][1], "variables": {"name": "Read"}}
        )
    )
    assert old.status_code == 400
    assert old.json()["errors"] == [error("__Type.inputFields")]
    seen.clear()
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        endpoint = _introspect_endpoint(TARGET, client)
    root = endpoint.progressive.types[0]
    assert root.field_names == ("items", "legacy")
    first = endpoint.progressive.attempts[1]
    assert first.query == ROOT_INVENTORY_QUERY and first.response.status_code == 200
    assert "inputFields" not in first.query and "enumValues" not in first.query
    assert endpoint.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
    assert endpoint.selected_schema_source is None
    assert len(endpoint.progressive.attempts) <= 32


@pytest.mark.parametrize("key", sorted(OPTIONAL_ARGUMENTS))
def test_matching_variant_cache_and_coverage_are_conservative(key):
    handler, _, _ = legacy_recovery(SDL, unsupported={key})
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        endpoint = _introspect_endpoint(TARGET, client)
    recovery = endpoint.progressive
    rejected = [a for a in recovery.attempts if a.unsupported_arguments]
    assert len(rejected) == 1 and rejected[0].unsupported_arguments == (key,)
    index = recovery.attempts.index(rejected[0])
    fallback = recovery.attempts[index + 1]
    field = key.split(".")[1]
    assert fallback.query == rejected[0].query.replace(f"{field}(includeDeprecated: true)", field)
    assert fallback.omitted_arguments == (key,)
    assert all(a.response.status_code == 200 for a in recovery.attempts[index + 1 :])
    assert recovery.structurally_validated
    assert recovery.compatibility_omissions == (key,)
    assert endpoint.schema_retrieval_status is SchemaRetrievalStatus.PARTIAL
    assert endpoint.selected_schema_source is None and recovery.assembled is None
    rows = dict(present_recovery(recovery).rows)
    assert "Legacy" in rows["Compatibility"] and "may be omitted" in rows["Coverage note"]
    assert rows["Structure validated"] == "Yes"
    if key == "__Type.fields":
        assert recovery.types[0].field_names == ("items",)
    assert len({(a.query, json.dumps(a.variables)) for a in recovery.attempts}) == len(
        recovery.attempts
    )


def test_multiple_exact_errors_are_applied_together_not_searched():
    keys = {"__Type.inputFields", "__Type.enumValues", "__Field.args"}
    handler, _, _ = legacy_recovery(SDL, unsupported=keys)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        recovery = _introspect_endpoint(TARGET, client).progressive
    errors = [a for a in recovery.attempts if a.unsupported_arguments]
    assert len(errors) == 1 and set(errors[0].unsupported_arguments) == keys
    assert set(recovery.compatibility_omissions) == keys
    assert recovery.structurally_validated and recovery.assembled is None


def test_modern_inventory_is_retained_when_legacy_details_omit_deprecated_names():
    def modern_inventory(request, count):
        payload = json.loads(request.content)
        if payload["query"] == ROOT_INVENTORY_QUERY:
            return httpx.Response(
                200,
                json=graphql_sync(
                    schema, payload["query"], variable_values=payload["variables"]
                ).formatted,
            )
        return None

    handler, _, schema = legacy_recovery(
        SDL, unsupported={"__Type.fields"}, override=modern_inventory
    )
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        endpoint = _introspect_endpoint(TARGET, client)
    recovery = endpoint.progressive
    root = recovery.types[0]
    assert root.field_names == ("items", "legacy")
    assert [f["name"] for f in root.definition["fields"]] == ["items"]
    assert not root.complete and endpoint.selected_schema_source is None
    assert recovery.compatibility_omissions == ("__Type.fields",)
    assert "contradict" not in recovery.limitation


def test_repeated_rejection_of_already_omitted_argument_stops_without_loop():
    def repeated_error(request, count):
        if count == 6:
            return httpx.Response(400, json={"errors": [error("__Type.fields")]})
        return None

    handler, seen, _ = legacy_recovery(SDL, unsupported={"__Type.fields"}, override=repeated_error)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        recovery = _introspect_endpoint(TARGET, client).progressive
    assert len(seen) == 6 and len(recovery.attempts) == 3
    assert recovery.stop_reason == "Noneligible response"
    assert recovery.types == () and recovery.assembled is None
    assert dict(present_recovery(recovery).rows)["Known Queries"] == "Unknown"


@pytest.mark.parametrize("status", [403, 429, 500])
def test_compatibility_wording_does_not_override_http_denial(status):
    def denied(request, count):
        if count == 5:
            return httpx.Response(status, json={"errors": [error("__Type.fields")]})
        return None

    handler, seen, _ = legacy_recovery(SDL, override=denied)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        recovery = _introspect_endpoint(TARGET, client).progressive
    assert len(seen) == 5 and len(recovery.attempts) == 2
    assert recovery.catalogue and not recovery.compatibility_omissions
    assert recovery.assembled is None
    assert dict(present_recovery(recovery).rows)["Known Queries"] == "Unknown"


def test_cache_does_not_cross_scans_endpoints_or_auth_contexts():
    for target, header, legacy in [
        (TARGET, "FAKE_CONTEXT_A", True),
        (TARGET, "FAKE_CONTEXT_B", False),
        (TARGET + "2", "FAKE_CONTEXT_C", True),
        (TARGET, "FAKE_CONTEXT_A", True),
    ]:
        handler, seen, _ = legacy_recovery(
            SDL, unsupported={"__Type.inputFields"} if legacy else ()
        )
        with HttpClient(
            HttpClientSettings(custom_headers=(("X-Context", header),)),
            transport=httpx.MockTransport(handler),
        ) as client:
            recovery = _introspect_endpoint(target, client).progressive
        assert all(r.headers["x-context"] == header for r in seen)
        assert len([a for a in recovery.attempts if a.unsupported_arguments]) == int(legacy)
        assert bool(recovery.assembled) is not legacy


def test_countries_style_six_query_modern_reconstruction_has_no_extra_requests():
    sdl = QUERY_ONLY.replace(
        "places(filter: Filter): [Place!]!",
        " ".join(f"places{i}(filter: Filter): [Place!]!" for i in range(6)),
    )
    handler, seen, _ = mock_recovery(sdl)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        endpoint = _introspect_endpoint(TARGET, client)
    parsed = parse_introspection_response(endpoint.selected_schema_source.body)
    assert (
        parsed.summary.query_field_count,
        parsed.summary.mutation_field_count,
        parsed.summary.subscription_field_count,
    ) == (6, 0, 0)
    assert len(seen) == 14 and len(endpoint.progressive.attempts) == 11
    assert not any(
        a.unsupported_arguments or a.omitted_arguments for a in endpoint.progressive.attempts
    )


def test_six_query_modern_recovery_still_runs_the_safe_pipeline(monkeypatch):
    sdl = QUERY_ONLY.replace(
        "places(filter: Filter): [Place!]!",
        " ".join(f"places{i}(filter: Filter): [Place!]!" for i in range(6)),
    )
    handler, seen, schema = mock_recovery(sdl)
    for field in schema.query_type.fields.values():
        field.resolve = lambda *_args, **_kwargs: []
    monkeypatch.setattr("httpx._client.HTTPTransport", lambda **_: httpx.MockTransport(handler))
    result = run_safe_execution_scan(TARGET)
    assert len(result.executions) == 6
    assert all(e.attempted and e.status is QueryExecutionStatus.SUCCESS for e in result.executions)
    introspection = result.query_generation.operation_analysis.schema_scan.introspection
    assert len(introspection.introspections[0].progressive.attempts) == 11
    assert len(seen) == 21  # Discovery + 14 introspection + six normal SAFE requests.


def test_full_thirteen_queries_nineteen_mutations_never_enters_progressive():
    sdl = (
        "type Query { "
        + " ".join(f"q{i}: String" for i in range(13))
        + " } type Mutation { "
        + " ".join(f"m{i}: String" for i in range(19))
        + " }"
    )

    def full(request, count):
        query = json.loads(request.content)["query"]
        assert query in {MINIMAL_INTROSPECTION_QUERY, FULL_INTROSPECTION_QUERY}
        return httpx.Response(200, json=graphql_sync(schema, query).formatted)

    handler, seen, schema = mock_recovery(sdl, override=full)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        endpoint = _introspect_endpoint(TARGET, client)
    parsed = parse_introspection_response(endpoint.selected_schema_source.body)
    assert (parsed.summary.query_field_count, parsed.summary.mutation_field_count) == (13, 19)
    assert len(seen) == 2 and endpoint.progressive is None


@pytest.mark.parametrize("mode", [ScanMode.SAFE, ScanMode.ACTIVE])
def test_legacy_structure_cannot_execute_and_reports_retain_original_evidence(monkeypatch, mode):
    handler, seen, _ = legacy_recovery(SDL, unsupported={"__Type.inputFields"})
    monkeypatch.setattr("httpx._client.HTTPTransport", lambda **_: httpx.MockTransport(handler))
    result = run_safe_execution_scan(
        TARGET,
        mode=mode,
        http_settings=HttpClientSettings(custom_headers=(("Authorization", "FAKE_LEGACY_SECRET"),)),
    )
    assert not result.executions and not result.query_generation.queries
    assert not any(
        e.evidence_type
        in {
            EvidenceType.QUERY_EXECUTION,
            EvidenceType.MUTATION_EXECUTION,
            EvidenceType.SCHEMA_ARTIFACT,
        }
        for e in result.evidence
    )
    if mode is ScanMode.ACTIVE:
        assert not prepare_active_mutations(result).candidates
    report = build_report(result)
    assert report.endpoints[0].schema_retrieval_status == "partial"
    assert report.endpoints[0].recovery is not None
    assert (
        "Account for incomplete schema and operation coverage "
        "when reviewing partial schema retrieval."
    ) in report.recommendations
    attempts = [e for e in result.evidence if e.query]
    rejected = next(e for e in attempts if e.response_status_code == 400)
    assert json.loads(rejected.response_body)["errors"] == [error("__Type.inputFields")]
    assert "inputFields(includeDeprecated: true)" in rejected.query
    assert any("Compatibility omission:" in note for e in attempts for note in e.notes)
    count = len(seen)
    for format in ReportFormat:
        text = render_report(report, format)
        assert "FAKE_LEGACY_SECRET" not in text
        if format is ReportFormat.JSON:
            assert json.loads(text)["report_schema_version"] == 2
        else:
            assert "Legacy introspection fallback used" in text and "may be omitted" in text
            assert text.count("Safety Notice") == 1
    context = serialize_context(build_ai_context(result))
    assert "FAKE_LEGACY_SECRET" not in context and "includeDeprecated" not in context
    monkeypatch.setenv("NO_COLOR", "1")
    output = StringIO()
    render_completed_assessment(
        Console(file=output, width=45, theme=CONSOLE_THEME), result, verbose=True
    )
    human = " ".join(output.getvalue().split())
    assert "Legacy introspection fallback used" in human
    assert "Deprecated input fields may be omitted." in human
    assert "FAKE_LEGACY_SECRET" not in human and "\x1b" not in human
    assert len(seen) == count


@pytest.mark.parametrize("approve", [False, True])
def test_legacy_variant_uses_existing_redirect_consent(approve):
    legacy_root = ROOT_INVENTORY_QUERY.replace("fields(includeDeprecated: true)", "fields")

    def redirect(request, count):
        assert request.headers["authorization"] == "FAKE_LEGACY_REDIRECT_SECRET"
        if json.loads(request.content)["query"] == legacy_root and request.url.port == 8123:
            return httpx.Response(307, headers={"location": "http://127.0.0.1:8124/graphql"})
        return None

    handler, seen, _ = legacy_recovery(SDL, unsupported={"__Type.fields"}, override=redirect)
    with HttpClient(
        HttpClientSettings(
            custom_headers=(("Authorization", "FAKE_LEGACY_REDIRECT_SECRET"),),
            redirect_consent=RedirectConsent(lambda _: approve),
        ),
        transport=httpx.MockTransport(handler),
    ) as client:
        recovery = _introspect_endpoint(TARGET, client).progressive
    assert any(r.url.port == 8124 for r in seen) is approve
    assert recovery.status is SchemaRetrievalStatus.PARTIAL
    assert recovery.structurally_validated is approve
    assert "FAKE_LEGACY_REDIRECT_SECRET" not in recovery.summary


def test_compatibility_attempts_consume_global_budget():
    sdl = (
        "type Query { "
        + " ".join(f"f{i}: T{i}" for i in range(40))
        + " } "
        + " ".join(f"type T{i} {{ id: ID }}" for i in range(40))
    )
    handler, seen, _ = legacy_recovery(sdl, unsupported=OPTIONAL_ARGUMENTS)
    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        recovery = _introspect_endpoint(TARGET, client).progressive
    assert len(recovery.attempts) == 32 and len(seen) == 35
    assert recovery.stop_reason == "Request budget exhausted"
    assert recovery.assembled is None
    assert sum(bool(a.unsupported_arguments) for a in recovery.attempts) == 2


@pytest.mark.parametrize("failure", ["denied", "size", "timeout", "cancel"])
def test_compatibility_fallback_stops_on_transport_or_access_failures(failure):
    def fail(request, count):
        if count != 6:
            return None
        if failure == "cancel":
            raise KeyboardInterrupt
        if failure == "timeout":
            raise httpx.ReadTimeout("fake timeout")
        return (
            httpx.Response(403) if failure == "denied" else httpx.Response(200, content=b" " * 4097)
        )

    handler, seen, _ = legacy_recovery(SDL, unsupported={"__Type.fields"}, override=fail)
    with HttpClient(
        HttpClientSettings(max_response_body_bytes=4096), transport=httpx.MockTransport(handler)
    ) as client:
        if failure == "cancel":
            with pytest.raises(KeyboardInterrupt):
                _introspect_endpoint(TARGET, client)
        else:
            recovery = _introspect_endpoint(TARGET, client).progressive
            assert recovery.assembled is None
            assert (
                recovery.stop_reason
                == {
                    "denied": "Access denied",
                    "size": "Response size limit",
                    "timeout": "Transport failure",
                }[failure]
            )
    assert len(seen) == 6
