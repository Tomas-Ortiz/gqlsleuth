"""Compose Phase 6 schema parsing with deterministic Phase 7 prioritization."""

from dataclasses import dataclass

from gqlsleuth.application.schema_parsing import SchemaScanResult, run_schema_scan
from gqlsleuth.domain.analysis import OperationAnalysis, RuleSet
from gqlsleuth.domain.exceptions import OperationAnalysisError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.rules.loader import load_bundled_rules
from gqlsleuth.rules.operation_analysis import analyze_schema_operations

ANALYSIS_SOURCE = "gqlsleuth.application.operation_analysis"


@dataclass(frozen=True)
class EndpointOperationAnalysisResult:
    """Operation-analysis outcome for one successfully parsed endpoint schema."""

    endpoint: str
    success: bool
    operations: tuple[OperationAnalysis, ...]
    error_type: str | None
    error_message: str | None

    @property
    def review_candidates(self) -> tuple[OperationAnalysis, ...]:
        """Return operations that matched at least one security-interest rule."""
        return tuple(operation for operation in self.operations if operation.interest_score > 0)


@dataclass(frozen=True)
class OperationAnalysisScanResult:
    """Complete Phase 6 result and ordered Phase 7 analysis outcomes."""

    schema_scan: SchemaScanResult
    endpoints: tuple[EndpointOperationAnalysisResult, ...]
    operation_evidence: tuple[Evidence, ...]

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        """Return Phase 3 through Phase 7 evidence in production order."""
        return self.schema_scan.evidence + self.operation_evidence


def run_operation_analysis_scan(
    target_url: str,
    *,
    mode: ScanMode = ScanMode.SAFE,
) -> OperationAnalysisScanResult:
    """Run Phases 3–7 using bundled deterministic operation-analysis rules."""
    rules = load_bundled_rules()
    return analyze_schema_results(run_schema_scan(target_url, mode=mode), rules)


def analyze_schema_results(
    schema_scan: SchemaScanResult,
    rules: RuleSet,
) -> OperationAnalysisScanResult:
    """Analyze successful schemas while preserving isolated endpoint failures."""
    results: list[EndpointOperationAnalysisResult] = []
    evidence: list[Evidence] = []
    for schema_result in schema_scan.schemas:
        if not schema_result.success or schema_result.schema is None:
            continue
        try:
            operations = analyze_schema_operations(
                schema_result.endpoint,
                schema_result.schema,
                rules,
            )
        except OperationAnalysisError as error:
            results.append(
                EndpointOperationAnalysisResult(
                    endpoint=schema_result.endpoint,
                    success=False,
                    operations=(),
                    error_type=type(error).__name__,
                    error_message=str(error),
                )
            )
            continue

        result = EndpointOperationAnalysisResult(
            endpoint=schema_result.endpoint,
            success=True,
            operations=operations,
            error_type=None,
            error_message=None,
        )
        results.append(result)
        evidence.extend(
            _operation_evidence(schema_scan, operation) for operation in result.review_candidates
        )

    return OperationAnalysisScanResult(
        schema_scan=schema_scan,
        endpoints=tuple(results),
        operation_evidence=tuple(evidence),
    )


def _operation_evidence(
    schema_scan: SchemaScanResult,
    operation: OperationAnalysis,
) -> Evidence:
    categories = ", ".join(category.value for category in operation.categories)
    rule_ids = ", ".join(match.rule_id for match in operation.matched_rules)
    reasons = tuple(match.reason for match in operation.matched_rules)
    return Evidence(
        evidence_type=EvidenceType.INTERESTING_OPERATION,
        target=schema_scan.introspection.detection.discovery.target,
        endpoint=operation.endpoint,
        summary=(
            f"{operation.kind.value.title()} '{operation.name}' received "
            f"{operation.priority.value.upper()} review priority (interest score "
            f"{operation.interest_score}) from rules: {rule_ids}."
        ),
        source=ANALYSIS_SOURCE,
        notes=(f"Categories: {categories}", *reasons),
    )
