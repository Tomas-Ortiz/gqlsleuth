"""Retained schema/operation selection shared by independently consented Mutation capabilities."""

from uuid import UUID

from graphql import GraphQLSchema

from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.discovery.endpoint_candidates import normalize_discovery_url
from gqlsleuth.domain.analysis import OperationAnalysis, OperationKind
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.models import EvidenceType
from gqlsleuth.domain.schema import ParsedSchema
from gqlsleuth.graphql.schema_parser import load_introspection_schema, parse_introspection_response


def retained_mutation(
    safe: SafeExecutionScanResult,
    name: str,
) -> tuple[ParsedSchema, GraphQLSchema, OperationAnalysis, tuple[UUID, ...]]:
    scan = safe.query_generation.operation_analysis.schema_scan
    discovery = scan.introspection.detection.discovery
    operations = tuple(
        operation
        for endpoint in safe.query_generation.operation_analysis.endpoints
        if endpoint.success
        for operation in endpoint.operations
        if operation.kind is OperationKind.MUTATION and operation.name == name
    )
    exact = tuple(
        op
        for op in operations
        if op.endpoint == normalize_discovery_url(discovery.target.original_url)
    )
    operations = exact or operations
    if len(operations) != 1:
        raise SafeExecutionValidationError("Requires one unambiguous Mutation operation/endpoint.")
    operation = operations[0]
    schemas = tuple(
        item.schema
        for item in scan.schemas
        if item.endpoint == operation.endpoint and item.success and item.schema is not None
    )
    responses = tuple(
        item.full_response
        for item in scan.introspection.introspections
        if item.endpoint == operation.endpoint and item.full_response is not None
    )
    if (
        len(schemas) != 1
        or len(responses) != 1
        or parse_introspection_response(responses[0].body) != schemas[0]
    ):
        raise SafeExecutionValidationError("Retained schema is unavailable or inconsistent.")
    references = tuple(
        item.evidence_id
        for item in safe.evidence
        if item.endpoint == operation.endpoint
        and item.evidence_type is EvidenceType.SCHEMA_ARTIFACT
    )
    return schemas[0], load_introspection_schema(responses[0].body), operation, references
