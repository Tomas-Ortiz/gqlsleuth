"""Offline integration tests for Phase 8 composition and evidence."""

from gqlsleuth.application.endpoint_discovery import EndpointDiscoveryResult
from gqlsleuth.application.graphql_detection import GraphQLDetectionResult
from gqlsleuth.application.introspection import IntrospectionScanResult
from gqlsleuth.application.operation_analysis import (
    EndpointOperationAnalysisResult,
    OperationAnalysisScanResult,
)
from gqlsleuth.application.query_generation import (
    QUERY_GENERATION_SOURCE,
    generate_analyzed_queries,
)
from gqlsleuth.application.schema_parsing import EndpointSchemaResult, SchemaScanResult
from gqlsleuth.domain.analysis import (
    InterestPriority,
    OperationAnalysis,
    OperationCategory,
    OperationKind,
)
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode, Target
from gqlsleuth.domain.schema import (
    ParsedSchema,
    SchemaArgument,
    SchemaField,
    SchemaInputField,
    SchemaNamedType,
    SchemaSummary,
    SchemaTypeKind,
    TypeReference,
)

ENDPOINT = "https://example.com/graphql"


def test_generation_preserves_phase_seven_and_isolates_query_failures() -> None:
    recursive_input = SchemaNamedType(
        name="RecursiveInput",
        kind=SchemaTypeKind.INPUT_OBJECT,
        input_fields=(
            SchemaInputField(
                name="child",
                type=TypeReference.non_null(TypeReference.named("RecursiveInput")),
            ),
        ),
    )
    query_fields = (
        SchemaField(
            name="broken",
            type=TypeReference.named("String"),
            arguments=(
                SchemaArgument(
                    name="input",
                    type=TypeReference.non_null(TypeReference.named("RecursiveInput")),
                ),
            ),
        ),
        SchemaField(name="health", type=TypeReference.named("String")),
    )
    schema = _schema(query_fields, recursive_input)
    schema_scan = _schema_scan(schema)
    operations = (
        _operation("broken", OperationKind.QUERY),
        _operation("deleteUser", OperationKind.MUTATION),
        _operation("health", OperationKind.QUERY),
    )
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
        operation_evidence=(_evidence(schema_scan, EvidenceType.INTERESTING_OPERATION),),
    )

    result = generate_analyzed_queries(analysis)

    assert result.operation_analysis is analysis
    assert [item.operation_name for item in result.queries] == ["broken", "health"]
    assert not result.queries[0].success
    assert "cycle" in (result.queries[0].failure_reason or "").casefold()
    assert result.queries[1].success
    assert result.evidence[: len(analysis.evidence)] == analysis.evidence
    assert result.evidence == analysis.evidence + result.query_evidence
    assert len(result.query_evidence) == 1
    evidence = result.query_evidence[0]
    assert evidence.evidence_type is EvidenceType.GENERATED_QUERY
    assert evidence.endpoint == ENDPOINT
    assert evidence.source == QUERY_GENERATION_SOURCE
    assert evidence.query == result.queries[1].query_text
    assert evidence.variables == {}
    assert "not executed" in " ".join(evidence.notes)
    assert all(item.operation_kind is OperationKind.QUERY for item in result.queries)


def _operation(name: str, kind: OperationKind) -> OperationAnalysis:
    fallback = (
        OperationCategory.READ_ONLY_BUSINESS_DATA
        if kind is OperationKind.QUERY
        else OperationCategory.STATE_CHANGING_BUSINESS_OPERATION
    )
    return OperationAnalysis(
        endpoint=ENDPOINT,
        kind=kind,
        name=name,
        return_type=TypeReference.named("String"),
        categories=(fallback,),
        interest_score=0,
        priority=InterestPriority.INFORMATIONAL,
        matched_rules=(),
        reasons=(),
    )


def _schema(
    query_fields: tuple[SchemaField, ...],
    recursive_input: SchemaNamedType,
) -> ParsedSchema:
    types = (
        SchemaNamedType(name="Query", kind=SchemaTypeKind.OBJECT, fields=query_fields),
        recursive_input,
        SchemaNamedType(name="String", kind=SchemaTypeKind.SCALAR),
    )
    return ParsedSchema(
        query_root="Query",
        mutation_root="Mutation",
        subscription_root=None,
        types=types,
        directives=(),
        summary=SchemaSummary(
            query_root="Query",
            mutation_root="Mutation",
            subscription_root=None,
            total_type_count=len(types),
            object_type_count=1,
            input_object_type_count=1,
            scalar_type_count=1,
            custom_scalar_type_count=0,
            enum_type_count=0,
            interface_type_count=0,
            union_type_count=0,
            directive_count=0,
            query_field_count=len(query_fields),
            mutation_field_count=1,
            subscription_field_count=0,
        ),
    )


def _schema_scan(schema: ParsedSchema) -> SchemaScanResult:
    target = Target.parse("https://example.com")
    discovery = EndpointDiscoveryResult(
        target=target,
        mode=ScanMode.SAFE,
        probes=(),
        evidence=(_plain_evidence(target, EvidenceType.ENDPOINT_CANDIDATE),),
    )
    detection = GraphQLDetectionResult(
        discovery=discovery,
        detections=(),
        confirmation_evidence=(_plain_evidence(target, EvidenceType.GRAPHQL_CONFIRMATION),),
    )
    introspection = IntrospectionScanResult(
        detection=detection,
        introspections=(),
        introspection_evidence=(_plain_evidence(target, EvidenceType.INTROSPECTION_RESULT),),
    )
    return SchemaScanResult(
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
        schema_evidence=(_plain_evidence(target, EvidenceType.SCHEMA_ARTIFACT),),
    )


def _evidence(schema_scan: SchemaScanResult, evidence_type: EvidenceType) -> Evidence:
    return _plain_evidence(schema_scan.introspection.detection.discovery.target, evidence_type)


def _plain_evidence(target: Target, evidence_type: EvidenceType) -> Evidence:
    return Evidence(
        evidence_type=evidence_type,
        target=target,
        summary="Preserved test evidence.",
        source="test",
    )
