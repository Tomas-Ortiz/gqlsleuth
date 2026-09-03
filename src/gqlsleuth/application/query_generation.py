"""Compose Phase 7 analysis with local Phase 8 read-only query generation."""

from dataclasses import dataclass

from gqlsleuth.application.operation_analysis import (
    OperationAnalysisScanResult,
    run_operation_analysis_scan,
)
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.exceptions import QueryGenerationError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.graphql.query_generation import DEFAULT_MAX_SELECTION_DEPTH, generate_query

QUERY_GENERATION_SOURCE = "gqlsleuth.application.query_generation"


@dataclass(frozen=True)
class QueryGenerationScanResult:
    """Complete Phase 7 result plus ordered Phase 8 generation outcomes."""

    operation_analysis: OperationAnalysisScanResult
    queries: tuple[QueryGenerationResult, ...]
    query_evidence: tuple[Evidence, ...]

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        """Return Phase 3 through Phase 8 evidence in production order."""
        return self.operation_analysis.evidence + self.query_evidence


def run_query_generation_scan(
    target_url: str,
    *,
    mode: ScanMode = ScanMode.SAFE,
) -> QueryGenerationScanResult:
    """Run Phases 3–8 without executing any generated query."""
    return generate_analyzed_queries(run_operation_analysis_scan(target_url, mode=mode))


def generate_analyzed_queries(
    operation_analysis: OperationAnalysisScanResult,
    *,
    max_selection_depth: int = DEFAULT_MAX_SELECTION_DEPTH,
) -> QueryGenerationScanResult:
    """Generate each analyzed Query while isolating per-operation failures."""
    schemas = {
        result.endpoint: result.schema
        for result in operation_analysis.schema_scan.schemas
        if result.success and result.schema is not None
    }
    results: list[QueryGenerationResult] = []
    evidence: list[Evidence] = []

    for endpoint_result in operation_analysis.endpoints:
        if not endpoint_result.success:
            continue
        schema = schemas.get(endpoint_result.endpoint)
        if schema is None:
            continue
        for operation in endpoint_result.operations:
            if operation.kind is not OperationKind.QUERY:
                continue
            try:
                result = generate_query(
                    schema,
                    operation,
                    max_selection_depth=max_selection_depth,
                )
            except QueryGenerationError as error:
                result = QueryGenerationResult(
                    operation=operation,
                    query_text=None,
                    variables={},
                    manual_adjustments=(),
                    failure_reason=str(error),
                )
            results.append(result)
            if result.success:
                evidence.append(_query_evidence(operation_analysis, result))

    return QueryGenerationScanResult(
        operation_analysis=operation_analysis,
        queries=tuple(results),
        query_evidence=tuple(evidence),
    )


def _query_evidence(
    operation_analysis: OperationAnalysisScanResult,
    result: QueryGenerationResult,
) -> Evidence:
    if result.query_text is None:
        raise ValueError("Successful query result is missing query text.")
    notes = (
        "Generated placeholders may require manual adjustment and were not executed.",
        *result.manual_adjustments,
    )
    return Evidence(
        evidence_type=EvidenceType.GENERATED_QUERY,
        target=operation_analysis.schema_scan.introspection.detection.discovery.target,
        endpoint=result.endpoint,
        summary=f"Generated a minimal read-only query for Query '{result.operation_name}'.",
        source=QUERY_GENERATION_SOURCE,
        notes=notes,
        query=result.query_text,
        variables=result.variables,
    )
