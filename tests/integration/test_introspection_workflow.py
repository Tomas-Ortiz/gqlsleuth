"""Offline integration tests for the Phase 5 introspection workflow."""

import json
from io import StringIO
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from gqlsleuth.application.endpoint_discovery import (
    EndpointDiscoveryResult,
    EndpointProbeResult,
)
from gqlsleuth.application.graphql_detection import (
    CandidateDetectionResult,
    GraphQLDetectionResult,
)
from gqlsleuth.application.introspection import introspect_detected_endpoints
from gqlsleuth.application.operation_analysis import analyze_schema_results
from gqlsleuth.application.query_generation import generate_analyzed_queries
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.application.schema_parsing import parse_introspection_schemas
from gqlsleuth.domain.models import (
    ConfidenceLevel,
    Evidence,
    EvidenceType,
    ScanMode,
    Target,
)
from gqlsleuth.graphql.introspection import (
    FULL_INTROSPECTION_QUERY,
    MINIMAL_INTROSPECTION_QUERY,
    IntrospectionStatus,
    SchemaRetrievalStatus,
)
from gqlsleuth.infrastructure.http import DEFAULT_TIMEOUT_SECONDS, HttpClient, HttpResponse
from gqlsleuth.presentation.assessment import build_assessment
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME, render_scan
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.rules.loader import load_bundled_rules


def test_enabled_introspection_retrieves_one_full_response_and_evidence() -> None:
    detection = _detection(ConfidenceLevel.CONFIRMED)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        query = json.loads(request.content)["query"]
        if query == MINIMAL_INTROSPECTION_QUERY:
            return _httpx_schema_response(request, {"queryType": {"name": "Query"}})
        return _httpx_schema_response(
            request,
            {
                "queryType": {"name": "Query"},
                "types": [{"kind": "OBJECT", "name": "Query"}],
            },
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = introspect_detected_endpoints(detection, client=client)

    introspection = result.introspections[0]
    assert [json.loads(request.content)["query"] for request in requests] == [
        MINIMAL_INTROSPECTION_QUERY,
        FULL_INTROSPECTION_QUERY,
    ]
    assert {request.extensions["timeout"]["read"] for request in requests} == {
        DEFAULT_TIMEOUT_SECONDS
    }
    assert introspection.status is IntrospectionStatus.ENABLED
    assert introspection.minimal_result.status is IntrospectionStatus.ENABLED
    assert introspection.full_result.status is IntrospectionStatus.ENABLED
    assert introspection.schema_retrieval_status is SchemaRetrievalStatus.RETRIEVED
    assert introspection.full_retrieval_attempted is True
    assert introspection.minimal_response is not None
    assert introspection.full_response is not None
    assert result.detection is detection
    assert result.evidence[: len(detection.evidence)] == detection.evidence
    evidence = result.introspection_evidence[0]
    assert evidence.evidence_type is EvidenceType.INTROSPECTION_RESULT
    assert evidence.endpoint == introspection.endpoint
    assert evidence.source == "gqlsleuth.application.introspection"
    assert "Full retrieval attempted: yes" in evidence.notes


def test_disabled_introspection_does_not_retrieve_full_schema() -> None:
    detection = _detection(ConfidenceLevel.PROBABLE)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            400,
            json={"errors": [{"message": "Introspection is not allowed."}]},
            request=request,
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = introspect_detected_endpoints(detection, client=client)

    introspection = result.introspections[0]
    assert len(requests) == 1
    assert introspection.status is IntrospectionStatus.DISABLED
    assert introspection.minimal_result.status is IntrospectionStatus.DISABLED
    assert introspection.full_result is None
    assert introspection.schema_retrieval_status is SchemaRetrievalStatus.NOT_ATTEMPTED
    assert introspection.full_retrieval_attempted is False
    assert introspection.full_response is None


def test_network_failure_does_not_stop_other_eligible_endpoints() -> None:
    detection = _detection(ConfidenceLevel.CONFIRMED, ConfidenceLevel.PROBABLE)
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path == "/graphql":
            raise httpx.ConnectError("unavailable", request=request)
        return _httpx_schema_response(request, {"queryType": {"name": "Query"}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = introspect_detected_endpoints(detection, client=client)

    assert requested_paths == ["/graphql", "/api/graphql", "/api/graphql"]
    assert result.introspections[0].status is IntrospectionStatus.NETWORK_FAILURE
    assert result.introspections[0].minimal_result.status is IntrospectionStatus.NETWORK_FAILURE
    assert result.introspections[0].schema_retrieval_status is SchemaRetrievalStatus.NOT_ATTEMPTED
    assert result.introspections[0].minimal_error_type == "HttpTransportError"
    assert result.introspections[1].status is IntrospectionStatus.ENABLED


def test_full_retrieval_failure_preserves_the_enabled_minimal_probe() -> None:
    detection = _detection(ConfidenceLevel.CONFIRMED)
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        if request_count == 1:
            return _httpx_schema_response(request, {"queryType": {"name": "Query"}})
        raise httpx.ReadTimeout("slow full response", request=request)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = introspect_detected_endpoints(detection, client=client)

    introspection = result.introspections[0]
    assert request_count == 2
    assert introspection.status is IntrospectionStatus.NETWORK_FAILURE
    assert introspection.minimal_result.status is IntrospectionStatus.ENABLED
    assert introspection.full_result.status is IntrospectionStatus.NETWORK_FAILURE
    assert introspection.schema_retrieval_status is SchemaRetrievalStatus.FAILED
    assert introspection.minimal_response is not None
    assert introspection.full_retrieval_attempted is True
    assert introspection.full_response is None
    assert introspection.full_error_type == "HttpTimeoutError"


@pytest.mark.parametrize("message", ["Query depth limit exceeded.", "Resolver execution failed."])
def test_enabled_probe_and_rejected_schema_remain_distinct_through_reports(message):
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return _httpx_schema_response(request, {"queryType": {"name": "Query"}})
        assert len(requests) == 2, "No downstream operation may execute without a schema"
        return httpx.Response(200, json={"errors": [{"message": message}]})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = introspect_detected_endpoints(_detection(ConfidenceLevel.CONFIRMED), client=client)
        endpoint = result.introspections[0]
        retained_evidence = result.evidence
        assert endpoint.minimal_result.status is IntrospectionStatus.ENABLED
        assert endpoint.full_result.status is IntrospectionStatus.ENDPOINT_ERROR
        assert endpoint.schema_retrieval_status is SchemaRetrievalStatus.BLOCKED
        assert message in endpoint.full_result.reason
        assert json.loads(endpoint.full_response.body)["errors"][0]["message"] == message
        schema_scan = parse_introspection_schemas(result)
        assert schema_scan.schemas == ()
        generated = generate_analyzed_queries(
            analyze_schema_results(schema_scan, load_bundled_rules())
        )
        safe = execute_generated_queries(generated, client=client)
    assert len(requests) == 2
    assert not safe.executions and not generated.queries
    assert not generated.security_review.candidates
    assert safe.evidence == retained_evidence

    report = build_report(safe)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    projected = canonical["endpoints"][0]
    # Legacy final-stage status and evidence remain compatible; new facts are additive.
    assert projected["introspection_status"] == "endpoint_error"
    assert projected["minimal_introspection_status"] == "enabled"
    assert projected["schema_retrieval_status"] == "blocked"
    assert projected["schema_retrieval_category"] == "endpoint_error"
    assert message in projected["schema_retrieval_reason"]
    assert report.evidence == retained_evidence
    assessment = build_assessment(report)
    assert dict(assessment.overview)["Introspection"] == "ENABLED: 1"
    assert dict(assessment.overview)["Schema retrieval"] == "BLOCKED: 1"
    for renderer in (render_scan, render_completed_assessment):
        for verbose in (False, True):
            output = StringIO()
            renderer(Console(file=output, theme=CONSOLE_THEME, width=120), safe, verbose=verbose)
            text = output.getvalue()
            assert "ENABLED" in text and "BLOCKED" in text
            assert "Introspection was unavailable" not in text
            assert "Schema" in text
            if verbose:
                assert message in " ".join(text.split())
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "Schema retrieval" in text and "BLOCKED" in text and "ENABLED" in text
        assert message in text.replace("\\.", ".")
        assert "Introspection was unavailable" not in text
        assert text.rfind("Safety Notice") > text.rfind("Introspection")


def test_enabled_probe_and_valid_full_schema_can_still_be_parsed():
    body = (Path(__file__).parents[1] / "fixtures" / "introspection_schema.json").read_bytes()
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return _httpx_schema_response(request, {"queryType": {"name": "Query"}})
        return httpx.Response(200, content=body)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = introspect_detected_endpoints(_detection(ConfidenceLevel.CONFIRMED), client=client)
    assert len(requests) == 2
    assert result.introspections[0].schema_retrieval_status is SchemaRetrievalStatus.RETRIEVED
    assert parse_introspection_schemas(result).schemas[0].success


def test_only_confirmed_and_probable_candidates_are_introspected() -> None:
    detection = _detection(
        ConfidenceLevel.CONFIRMED,
        ConfidenceLevel.PROBABLE,
        ConfidenceLevel.POSSIBLE,
        ConfidenceLevel.NOT_DETECTED,
    )
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        return httpx.Response(
            400,
            json={"errors": [{"message": "Introspection is disabled."}]},
            request=request,
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = introspect_detected_endpoints(detection, client=client)

    assert requested_paths == ["/graphql", "/api/graphql"]
    assert [item.endpoint for item in result.introspections] == [
        "https://example.com/graphql",
        "https://example.com/api/graphql",
    ]


def _detection(*confidences: ConfidenceLevel) -> GraphQLDetectionResult:
    target = Target.parse("https://example.com/graphql")
    paths = ("/graphql", "/api/graphql", "/gql", "/api/gql")
    endpoints = tuple(f"https://example.com{path}" for path in paths[: len(confidences)])
    probes = tuple(
        EndpointProbeResult(candidate_url=endpoint, response=_response(endpoint))
        for endpoint in endpoints
    )
    discovery_evidence = tuple(
        Evidence(
            evidence_type=EvidenceType.ENDPOINT_CANDIDATE,
            target=target,
            endpoint=endpoint,
            summary="GET candidate response retained.",
            source="test_introspection_workflow",
        )
        for endpoint in endpoints
    )
    discovery = EndpointDiscoveryResult(
        target=target,
        mode=ScanMode.SAFE,
        probes=probes,
        evidence=discovery_evidence,
    )
    detections = tuple(
        CandidateDetectionResult(
            candidate_url=endpoint,
            get_signals=(),
            post_probe_required=False,
            post_response=None,
            post_signals=(),
            post_error_type=None,
            post_error_message=None,
            confidence=confidence,
            reason="Deterministic test classification.",
        )
        for endpoint, confidence in zip(endpoints, confidences, strict=True)
    )
    confirmation_evidence = tuple(
        Evidence(
            evidence_type=EvidenceType.GRAPHQL_CONFIRMATION,
            target=target,
            endpoint=endpoint,
            summary=f"{confidence.value.upper()} GraphQL behavior.",
            source="test_introspection_workflow",
            confidence=confidence,
        )
        for endpoint, confidence in zip(endpoints, confidences, strict=True)
    )
    return GraphQLDetectionResult(
        discovery=discovery,
        detections=detections,
        confirmation_evidence=confirmation_evidence,
    )


def _response(endpoint: str) -> HttpResponse:
    return HttpResponse(
        request_url=endpoint,
        final_url=endpoint,
        status_code=200,
        headers={"content-type": "application/json"},
        body=b'{"data":{"__typename":"Query"}}',
        duration_seconds=0,
        redirect_count=0,
    )


def _httpx_schema_response(
    request: httpx.Request,
    schema: dict[str, object],
) -> httpx.Response:
    return httpx.Response(200, json={"data": {"__schema": schema}}, request=request)
