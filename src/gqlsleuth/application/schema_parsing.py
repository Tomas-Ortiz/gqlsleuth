"""Compose Phase 5 introspection with deterministic Phase 6 schema parsing."""

from dataclasses import dataclass

from gqlsleuth.application.introspection import IntrospectionScanResult, run_introspection_scan
from gqlsleuth.domain.exceptions import SchemaParsingError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.schema import ParsedSchema, SchemaSummary
from gqlsleuth.graphql.introspection import SchemaRetrievalStatus
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.infrastructure.http import HttpClientSettings

SCHEMA_SOURCE = "gqlsleuth.application.schema_parsing"


@dataclass(frozen=True)
class EndpointSchemaResult:
    """Schema parsing outcome for one eligible introspection endpoint."""

    endpoint: str
    success: bool
    schema: ParsedSchema | None
    error_type: str | None
    error_message: str | None
    schema_retrieval_status: SchemaRetrievalStatus = SchemaRetrievalStatus.RETRIEVED

    @property
    def summary(self) -> SchemaSummary | None:
        """Return the parsed schema summary when parsing succeeded."""
        return self.schema.summary if self.schema is not None else None


@dataclass(frozen=True)
class SchemaScanResult:
    """Complete Phase 5 result and ordered Phase 6 schema outcomes."""

    introspection: IntrospectionScanResult
    schemas: tuple[EndpointSchemaResult, ...]
    schema_evidence: tuple[Evidence, ...]

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        """Return Phase 3 through Phase 6 evidence in production order."""
        return self.introspection.evidence + self.schema_evidence


def run_schema_scan(
    target_url: str,
    *,
    mode: ScanMode = ScanMode.SAFE,
    http_settings: HttpClientSettings | None = None,
) -> SchemaScanResult:
    """Run Phases 3–6, parsing selected retained responses without new parsing requests."""
    return parse_introspection_schemas(
        run_introspection_scan(target_url, mode=mode, http_settings=http_settings)
    )


def parse_introspection_schemas(introspection: IntrospectionScanResult) -> SchemaScanResult:
    """Parse the selected retained schema response, without network or recovery requests."""
    results: list[EndpointSchemaResult] = []
    evidence: list[Evidence] = []

    for endpoint_result in introspection.introspections:
        response = endpoint_result.selected_schema_source
        if response is None:
            continue
        try:
            schema = parse_introspection_response(response.body)
        except SchemaParsingError as error:
            results.append(
                EndpointSchemaResult(
                    endpoint=endpoint_result.endpoint,
                    success=False,
                    schema=None,
                    error_type=type(error).__name__,
                    error_message=str(error),
                    schema_retrieval_status=endpoint_result.schema_retrieval_status,
                )
            )
            continue

        result = EndpointSchemaResult(
            endpoint=endpoint_result.endpoint,
            success=True,
            schema=schema,
            error_type=None,
            error_message=None,
            schema_retrieval_status=endpoint_result.schema_retrieval_status,
        )
        results.append(result)
        evidence.append(_schema_evidence(introspection, result))

    return SchemaScanResult(
        introspection=introspection,
        schemas=tuple(results),
        schema_evidence=tuple(evidence),
    )


def _schema_evidence(
    introspection: IntrospectionScanResult,
    result: EndpointSchemaResult,
) -> Evidence:
    summary = result.summary
    if summary is None:
        raise ValueError("Successful schema result is missing its summary.")
    roots = [f"query={summary.query_root}"]
    if summary.mutation_root is not None:
        roots.append(f"mutation={summary.mutation_root}")
    if summary.subscription_root is not None:
        roots.append(f"subscription={summary.subscription_root}")
    recovered = next(
        (
            item
            for item in introspection.introspections
            if item.endpoint == result.endpoint and item.progressive is not None
        ),
        None,
    )
    return Evidence(
        evidence_type=EvidenceType.SCHEMA_ARTIFACT,
        target=introspection.detection.discovery.target,
        endpoint=result.endpoint,
        summary=(
            f"Parsed schema ({', '.join(roots)}; {summary.total_type_count} types; "
            f"{summary.query_field_count} queries; {summary.mutation_field_count} mutations; "
            f"{summary.subscription_field_count} subscriptions)."
        ),
        source=SCHEMA_SOURCE,
        notes=(
            f"Objects: {summary.object_type_count}",
            f"Input objects: {summary.input_object_type_count}",
            f"Scalars: {summary.scalar_type_count}",
            f"Enums: {summary.enum_type_count}",
            f"Interfaces: {summary.interface_type_count}",
            f"Unions: {summary.union_type_count}",
            f"Schema retrieval: {result.schema_retrieval_status.value}",
            *(
                (
                    "Source: locally assembled progressive schema; not a single server response.",
                    "Source request evidence: "
                    + ", ".join(
                        str(e.evidence_id)
                        for e in introspection.introspection_evidence
                        if e.endpoint == result.endpoint and e.query is not None
                    ),
                )
                if recovered
                else ()
            ),
        ),
    )
