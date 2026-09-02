"""Offline integration tests for Phase 6 schema-result composition."""

from pathlib import Path

from gqlsleuth.application.endpoint_discovery import EndpointDiscoveryResult
from gqlsleuth.application.graphql_detection import (
    CandidateDetectionResult,
    GraphQLDetectionResult,
)
from gqlsleuth.application.introspection import (
    EndpointIntrospectionResult,
    IntrospectionScanResult,
)
from gqlsleuth.application.schema_parsing import (
    SCHEMA_SOURCE,
    parse_introspection_schemas,
)
from gqlsleuth.domain.models import (
    ConfidenceLevel,
    Evidence,
    EvidenceType,
    ScanMode,
    Target,
)
from gqlsleuth.graphql.introspection import IntrospectionStatus
from gqlsleuth.infrastructure.http import HttpResponse

FIXTURE_BODY = (Path(__file__).parents[1] / "fixtures" / "introspection_schema.json").read_bytes()


def test_one_schema_failure_does_not_stop_another_enabled_endpoint() -> None:
    introspection = _phase_five_result(
        ("https://example.com/graphql", IntrospectionStatus.ENABLED, b"{malformed"),
        ("https://example.com/api/graphql", IntrospectionStatus.ENABLED, FIXTURE_BODY),
    )

    result = parse_introspection_schemas(introspection)

    assert [item.success for item in result.schemas] == [False, True]
    assert result.schemas[0].error_type == "SchemaParsingError"
    assert result.schemas[0].schema is None
    assert result.schemas[1].schema is not None
    assert result.schemas[1].schema.query_root == "Query"


def test_only_enabled_endpoints_with_full_responses_are_parsed() -> None:
    introspection = _phase_five_result(
        ("https://example.com/graphql", IntrospectionStatus.ENABLED, FIXTURE_BODY),
        ("https://example.com/api/graphql", IntrospectionStatus.DISABLED, None),
        ("https://example.com/gql", IntrospectionStatus.ENABLED, None),
    )

    result = parse_introspection_schemas(introspection)

    assert [item.endpoint for item in result.schemas] == ["https://example.com/graphql"]
    assert result.schemas[0].success is True


def test_schema_artifact_evidence_preserves_all_previous_evidence() -> None:
    introspection = _phase_five_result(
        ("https://example.com/graphql", IntrospectionStatus.ENABLED, FIXTURE_BODY),
    )

    result = parse_introspection_schemas(introspection)

    assert result.introspection is introspection
    assert result.evidence[: len(introspection.evidence)] == introspection.evidence
    assert result.evidence == introspection.evidence + result.schema_evidence
    assert len(result.schema_evidence) == 1
    evidence = result.schema_evidence[0]
    assert evidence.evidence_type is EvidenceType.SCHEMA_ARTIFACT
    assert evidence.endpoint == "https://example.com/graphql"
    assert evidence.source == SCHEMA_SOURCE
    assert "query=Query" in evidence.summary
    assert "13 types" in evidence.summary


def _phase_five_result(
    *entries: tuple[str, IntrospectionStatus, bytes | None],
) -> IntrospectionScanResult:
    target = Target.parse("https://example.com")
    discovery_evidence = tuple(
        _evidence(EvidenceType.ENDPOINT_CANDIDATE, target, endpoint, "discovery")
        for endpoint, _, _ in entries
    )
    discovery = EndpointDiscoveryResult(
        target=target,
        mode=ScanMode.SAFE,
        probes=(),
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
            confidence=ConfidenceLevel.CONFIRMED,
            reason="Test endpoint confirmed.",
        )
        for endpoint, _, _ in entries
    )
    confirmation_evidence = tuple(
        _evidence(EvidenceType.GRAPHQL_CONFIRMATION, target, endpoint, "detection")
        for endpoint, _, _ in entries
    )
    detection = GraphQLDetectionResult(
        discovery=discovery,
        detections=detections,
        confirmation_evidence=confirmation_evidence,
    )
    introspections = tuple(
        _endpoint_introspection(endpoint, status, body) for endpoint, status, body in entries
    )
    introspection_evidence = tuple(
        _evidence(EvidenceType.INTROSPECTION_RESULT, target, endpoint, "introspection")
        for endpoint, _, _ in entries
    )
    return IntrospectionScanResult(
        detection=detection,
        introspections=introspections,
        introspection_evidence=introspection_evidence,
    )


def _endpoint_introspection(
    endpoint: str,
    status: IntrospectionStatus,
    body: bytes | None,
) -> EndpointIntrospectionResult:
    response = _response(endpoint, body) if body is not None else None
    return EndpointIntrospectionResult(
        endpoint=endpoint,
        status=status,
        minimal_response=response,
        minimal_error_type=None,
        minimal_error_message=None,
        full_retrieval_attempted=response is not None,
        full_response=response,
        full_error_type=None,
        full_error_message=None,
        reason="Deterministic test result.",
    )


def _response(endpoint: str, body: bytes) -> HttpResponse:
    return HttpResponse(
        request_url=endpoint,
        final_url=endpoint,
        status_code=200,
        headers={"content-type": "application/json"},
        body=body,
        duration_seconds=0,
        redirect_count=0,
    )


def _evidence(
    evidence_type: EvidenceType,
    target: Target,
    endpoint: str,
    source: str,
) -> Evidence:
    return Evidence(
        evidence_type=evidence_type,
        target=target,
        endpoint=endpoint,
        summary="Test evidence.",
        source=source,
    )
