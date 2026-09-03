"""Offline integration tests for Phase 7 workflow composition and evidence."""

from gqlsleuth.application.endpoint_discovery import EndpointDiscoveryResult
from gqlsleuth.application.graphql_detection import GraphQLDetectionResult
from gqlsleuth.application.introspection import IntrospectionScanResult
from gqlsleuth.application.operation_analysis import (
    ANALYSIS_SOURCE,
    analyze_schema_results,
)
from gqlsleuth.application.schema_parsing import EndpointSchemaResult, SchemaScanResult
from gqlsleuth.domain.analysis import (
    OperationCategory,
    OperationRule,
    PriorityThresholds,
    RuleSet,
    RuleSurface,
)
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode, Target
from gqlsleuth.domain.schema import (
    ParsedSchema,
    SchemaField,
    SchemaNamedType,
    SchemaSummary,
    SchemaTypeKind,
    TypeReference,
)


def test_analysis_preserves_phase_six_result_and_emits_only_candidate_evidence() -> None:
    schema_scan = _schema_scan(
        EndpointSchemaResult(
            endpoint="https://example.com/graphql",
            success=True,
            schema=_schema(
                "Query",
                (
                    SchemaField(name="searchUsers", type=TypeReference.named("String")),
                    SchemaField(name="health", type=TypeReference.named("String")),
                ),
            ),
            error_type=None,
            error_message=None,
        )
    )

    result = analyze_schema_results(schema_scan, _rules())

    assert result.schema_scan is schema_scan
    assert result.evidence[: len(schema_scan.evidence)] == schema_scan.evidence
    assert result.evidence == schema_scan.evidence + result.operation_evidence
    assert [operation.name for operation in result.endpoints[0].operations] == [
        "searchUsers",
        "health",
    ]
    assert len(result.operation_evidence) == 1
    evidence = result.operation_evidence[0]
    assert evidence.evidence_type is EvidenceType.INTERESTING_OPERATION
    assert evidence.endpoint == "https://example.com/graphql"
    assert evidence.source == ANALYSIS_SOURCE
    assert "searchUsers" in evidence.summary
    assert "interest score" in evidence.summary
    assert "vulnerab" not in evidence.summary.casefold()
    assert any("operation.name" in note for note in evidence.notes)


def test_one_analysis_failure_does_not_discard_other_endpoint_or_previous_results() -> None:
    valid = EndpointSchemaResult(
        endpoint="https://example.com/graphql",
        success=True,
        schema=_schema(
            "Query",
            (SchemaField(name="searchUsers", type=TypeReference.named("String")),),
        ),
        error_type=None,
        error_message=None,
    )
    invalid = EndpointSchemaResult(
        endpoint="https://example.com/api/graphql",
        success=True,
        schema=_schema("MissingQuery", ()),
        error_type=None,
        error_message=None,
    )
    already_failed = EndpointSchemaResult(
        endpoint="https://example.com/gql",
        success=False,
        schema=None,
        error_type="SchemaParsingError",
        error_message="Invalid schema.",
    )
    schema_scan = _schema_scan(valid, invalid, already_failed)

    result = analyze_schema_results(schema_scan, _rules())

    assert [endpoint.success for endpoint in result.endpoints] == [True, False]
    assert result.endpoints[1].error_type == "OperationAnalysisError"
    assert result.endpoints[1].operations == ()
    assert result.schema_scan.schemas == (valid, invalid, already_failed)


def _rules() -> RuleSet:
    return RuleSet(
        thresholds=PriorityThresholds(critical=8, high=5, medium=3, low=1),
        rules=(
            OperationRule(
                id="search",
                category=OperationCategory.SEARCH,
                keywords=("search",),
                surfaces=(RuleSurface.PRIMARY, RuleSurface.INPUT),
                weight=1,
                reason="Search terminology.",
            ),
            OperationRule(
                id="users",
                category=OperationCategory.USER_MANAGEMENT,
                keywords=("user",),
                surfaces=(RuleSurface.PRIMARY, RuleSurface.INPUT),
                weight=2,
                reason="User terminology.",
            ),
        ),
    )


def _schema(query_root: str, fields: tuple[SchemaField, ...]) -> ParsedSchema:
    represented_types = (
        SchemaNamedType(name="Query", kind=SchemaTypeKind.OBJECT, fields=fields),
        SchemaNamedType(name="String", kind=SchemaTypeKind.SCALAR),
    )
    return ParsedSchema(
        query_root=query_root,
        mutation_root=None,
        subscription_root=None,
        types=represented_types,
        directives=(),
        summary=SchemaSummary(
            query_root=query_root,
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


def _schema_scan(*schemas: EndpointSchemaResult) -> SchemaScanResult:
    target = Target.parse("https://example.com")
    discovery = EndpointDiscoveryResult(
        target=target,
        mode=ScanMode.SAFE,
        probes=(),
        evidence=(_evidence(target, EvidenceType.ENDPOINT_CANDIDATE),),
    )
    detection = GraphQLDetectionResult(
        discovery=discovery,
        detections=(),
        confirmation_evidence=(_evidence(target, EvidenceType.GRAPHQL_CONFIRMATION),),
    )
    introspection = IntrospectionScanResult(
        detection=detection,
        introspections=(),
        introspection_evidence=(_evidence(target, EvidenceType.INTROSPECTION_RESULT),),
    )
    return SchemaScanResult(
        introspection=introspection,
        schemas=schemas,
        schema_evidence=(_evidence(target, EvidenceType.SCHEMA_ARTIFACT),),
    )


def _evidence(target: Target, evidence_type: EvidenceType) -> Evidence:
    return Evidence(
        evidence_type=evidence_type,
        target=target,
        summary="Preserved test evidence.",
        source="test",
    )
