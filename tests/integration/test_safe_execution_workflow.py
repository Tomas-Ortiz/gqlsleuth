"""Offline integration tests for sequential Phase 9 execution and evidence."""

import json

import httpx

from gqlsleuth.application.endpoint_discovery import EndpointDiscoveryResult
from gqlsleuth.application.graphql_detection import GraphQLDetectionResult
from gqlsleuth.application.introspection import IntrospectionScanResult
from gqlsleuth.application.operation_analysis import (
    EndpointOperationAnalysisResult,
    OperationAnalysisScanResult,
)
from gqlsleuth.application.query_generation import QueryGenerationScanResult
from gqlsleuth.application.safe_execution import (
    MAX_QUERY_EXECUTIONS,
    execute_generated_queries,
)
from gqlsleuth.application.schema_parsing import EndpointSchemaResult, SchemaScanResult
from gqlsleuth.domain.analysis import (
    InterestPriority,
    OperationAnalysis,
    OperationCategory,
    OperationKind,
)
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode, Target
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import (
    ParsedSchema,
    SchemaField,
    SchemaNamedType,
    SchemaSummary,
    SchemaTypeKind,
    TypeReference,
)
from gqlsleuth.infrastructure.http import HttpClient

ENDPOINT = "https://example.com/graphql"


def test_requests_are_exact_sequential_classified_and_failure_isolated() -> None:
    names = (
        "users",
        "country",
        "timeout",
        "failure",
        "search",
        "invalid",
        "serverError",
    )
    generation = _generation(names)
    requested: list[str] = []
    request_documents: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert isinstance(payload, dict)
        requested.append(str(payload["query"]).split("{")[1].strip().split()[0])
        request_documents.append(payload)
        index = len(requested) - 1
        if index == 0:
            return httpx.Response(200, json={"data": {"users": []}})
        if index == 1:
            return httpx.Response(
                200,
                json={"data": {"country": None}, "errors": [{"message": "Invalid ID"}]},
            )
        if index == 2:
            raise httpx.ReadTimeout("offline timeout", request=request)
        if index == 3:
            raise httpx.ConnectError("offline failure", request=request)
        if index == 4:
            return httpx.Response(200, json={"data": {"search": []}})
        if index == 5:
            return httpx.Response(200, text="not graphql")
        return httpx.Response(500, text="server failed")

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = execute_generated_queries(generation, client=client)

    assert requested == list(names)
    assert [item.status for item in result.executions] == [
        QueryExecutionStatus.SUCCESS,
        QueryExecutionStatus.GRAPHQL_ERROR,
        QueryExecutionStatus.NETWORK_FAILURE,
        QueryExecutionStatus.NETWORK_FAILURE,
        QueryExecutionStatus.SUCCESS,
        QueryExecutionStatus.INVALID_RESPONSE,
        QueryExecutionStatus.HTTP_ERROR,
    ]
    assert request_documents[0] == {
        "query": "query ($id: ID!) { users }",
        "variables": {"id": "1"},
    }
    assert all("operationName" not in payload for payload in request_documents)
    assert result.query_generation is generation
    assert result.evidence == generation.evidence + result.execution_evidence
    assert len(result.execution_evidence) == len(names)
    first_evidence = result.execution_evidence[0]
    assert first_evidence.evidence_type is EvidenceType.QUERY_EXECUTION
    assert first_evidence.request_method == "POST"
    assert first_evidence.query == "query ($id: ID!) { users }"
    assert first_evidence.variables == {"id": "1"}
    assert first_evidence.response_status_code == 200
    assert first_evidence.response_body == b'{"data":{"users":[]}}'
    assert result.execution_evidence[2].error_type == "HttpTimeoutError"
    assert result.execution_evidence[3].error_type == "HttpTransportError"


def test_side_effecting_query_is_skipped_without_request_or_evidence() -> None:
    generation = _generation(("readAndBurn", "users"))
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        return httpx.Response(200, json={"data": {"users": []}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = execute_generated_queries(generation, client=client)

    assert requested == ["/graphql"]
    assert result.executions[0].status is QueryExecutionStatus.SKIPPED_SAFETY
    assert "burn" in result.executions[0].reason
    assert result.executions[1].status is QueryExecutionStatus.SUCCESS
    assert len(result.execution_evidence) == 1


def test_execution_limit_requests_only_first_twenty_in_existing_order() -> None:
    names = tuple(f"query{index:02d}" for index in range(MAX_QUERY_EXECUTIONS + 2))
    generation = _generation(names)
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert isinstance(payload, dict)
        requested.append(str(payload["query"]))
        return httpx.Response(200, json={"data": {"value": True}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = execute_generated_queries(generation, client=client)

    assert len(requested) == MAX_QUERY_EXECUTIONS
    assert [item.operation_name for item in result.executions[:MAX_QUERY_EXECUTIONS]] == list(
        names[:MAX_QUERY_EXECUTIONS]
    )
    assert all(item.attempted for item in result.executions[:MAX_QUERY_EXECUTIONS])
    assert all(
        item.status is QueryExecutionStatus.SKIPPED_LIMIT
        for item in result.executions[MAX_QUERY_EXECUTIONS:]
    )
    assert len(result.execution_evidence) == MAX_QUERY_EXECUTIONS


def test_safe_and_active_modes_use_identical_query_only_execution() -> None:
    outcomes: list[tuple[QueryExecutionStatus, bool]] = []
    for mode in (ScanMode.SAFE, ScanMode.ACTIVE):
        generation = _generation(("users",), mode=mode)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"users": []}})

        with HttpClient(transport=httpx.MockTransport(handler)) as client:
            result = execute_generated_queries(generation, client=client)
        assert (
            result.query_generation.operation_analysis.schema_scan.introspection.detection.discovery.mode
            is mode
        )
        outcomes.append((result.executions[0].status, result.executions[0].attempted))

    assert outcomes == [
        (QueryExecutionStatus.SUCCESS, True),
        (QueryExecutionStatus.SUCCESS, True),
    ]


def _generation(
    names: tuple[str, ...],
    *,
    mode: ScanMode = ScanMode.SAFE,
) -> QueryGenerationScanResult:
    schema = _schema(names)
    target = Target.parse("https://example.com")
    discovery = EndpointDiscoveryResult(target=target, mode=mode, probes=(), evidence=())
    detection = GraphQLDetectionResult(
        discovery=discovery,
        detections=(),
        confirmation_evidence=(),
    )
    introspection = IntrospectionScanResult(
        detection=detection,
        introspections=(),
        introspection_evidence=(),
    )
    schema_scan = SchemaScanResult(
        introspection=introspection,
        schemas=(
            EndpointSchemaResult(
                endpoint=ENDPOINT,
                success=True,
                schema=schema,
                error_type=None,
                error_message=None,
            ),
        ),
        schema_evidence=(),
    )
    operations = tuple(_operation(name) for name in names)
    analysis = OperationAnalysisScanResult(
        schema_scan=schema_scan,
        endpoints=(
            EndpointOperationAnalysisResult(
                endpoint=ENDPOINT,
                success=True,
                operations=operations,
                error_type=None,
                error_message=None,
            ),
        ),
        operation_evidence=(),
    )
    artifacts = tuple(
        QueryGenerationResult(
            operation=operation,
            query_text=(
                "query ($id: ID!) { users }"
                if operation.name == "users"
                else f"query {{ {operation.name} }}"
            ),
            variables={"id": "1"} if operation.name == "users" else {},
            manual_adjustments=(),
            failure_reason=None,
        )
        for operation in operations
    )
    return QueryGenerationScanResult(
        operation_analysis=analysis,
        queries=artifacts,
        query_evidence=(_evidence(target),),
    )


def _operation(name: str) -> OperationAnalysis:
    return OperationAnalysis(
        endpoint=ENDPOINT,
        kind=OperationKind.QUERY,
        name=name,
        return_type=TypeReference.named("String"),
        categories=(OperationCategory.READ_ONLY_BUSINESS_DATA,),
        interest_score=0,
        priority=InterestPriority.INFORMATIONAL,
        matched_rules=(),
        reasons=(),
    )


def _schema(names: tuple[str, ...]) -> ParsedSchema:
    fields = tuple(SchemaField(name=name, type=TypeReference.named("String")) for name in names)
    types = (
        SchemaNamedType(name="Query", kind=SchemaTypeKind.OBJECT, fields=fields),
        SchemaNamedType(name="String", kind=SchemaTypeKind.SCALAR),
    )
    return ParsedSchema(
        query_root="Query",
        mutation_root=None,
        subscription_root=None,
        types=types,
        directives=(),
        summary=SchemaSummary(
            query_root="Query",
            mutation_root=None,
            subscription_root=None,
            total_type_count=2,
            object_type_count=1,
            input_object_type_count=0,
            scalar_type_count=1,
            custom_scalar_type_count=0,
            enum_type_count=0,
            interface_type_count=0,
            union_type_count=0,
            directive_count=0,
            query_field_count=len(fields),
            mutation_field_count=0,
            subscription_field_count=0,
        ),
    )


def _evidence(target: Target) -> Evidence:
    return Evidence(
        evidence_type=EvidenceType.GENERATED_QUERY,
        target=target,
        endpoint=ENDPOINT,
        summary="Preserved generated query.",
        source="test",
    )
