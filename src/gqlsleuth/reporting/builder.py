"""Project existing results into a deterministic report without scanning or new safety rules."""

from collections import Counter
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime

from gqlsleuth import __version__
from gqlsleuth.ai.models import AIInterpretationResult
from gqlsleuth.application.active_execution import (
    ActiveExecutionScanResult,
    MutationExecutionResult,
)
from gqlsleuth.application.safe_execution import QueryExecutionResult, SafeExecutionScanResult
from gqlsleuth.domain.active import MutationDecision
from gqlsleuth.domain.analysis import InterestPriority, OperationCategory
from gqlsleuth.domain.models import ConfidenceLevel, Evidence, EvidenceType
from gqlsleuth.domain.query_generation import OperationGenerationResult
from gqlsleuth.reporting.models import (
    ActiveReport,
    EndpointReport,
    ExecutionReport,
    OperationReport,
    ReportContext,
    ReportIssue,
)

SAFETY_NOTICE = (
    "GQLSleuth is intended only for authorized testing. Review priority is not vulnerability "
    "severity. Execution success is not proof of exploitability or an authorization bypass. "
    "Automated results require professional validation. "
    "This report creates no vulnerability findings."
)


def build_report(
    result: SafeExecutionScanResult | ActiveExecutionScanResult,
    *,
    generated_at: datetime | None = None,
    ai_interpretation: AIInterpretationResult | None = None,
) -> ReportContext:
    """Snapshot existing facts; a supplied timestamp makes builds reproducible."""
    safe = result.safe_execution if isinstance(result, ActiveExecutionScanResult) else result
    analysis = safe.query_generation.operation_analysis
    schema_scan = analysis.schema_scan
    introspection = schema_scan.introspection
    detection = introspection.detection
    discovery = detection.discovery
    evidence = result.evidence
    queries = tuple(
        OperationReport(
            generated=artifact,
            execution=_execution(
                next((item for item in safe.executions if item.generated_query == artifact), None),
                artifact,
                evidence,
                EvidenceType.QUERY_EXECUTION,
            ),
        )
        for artifact in safe.query_generation.queries
    )
    active = None
    if isinstance(result, ActiveExecutionScanResult):
        mutations = []
        for index, candidate in enumerate(result.preview.candidates, 1):
            artifact = candidate.generated_mutation
            execution = next(
                (
                    item
                    for item in result.executions
                    if item.preview.generated_mutation.operation == artifact.operation
                ),
                None,
            )
            mutations.append(
                OperationReport(
                    generated=artifact,
                    execution=_execution(
                        execution, artifact, evidence, EvidenceType.MUTATION_EXECUTION
                    ),
                    candidate_index=index,
                    preview_decision=candidate.decision.value,
                    preview_reason=candidate.reason,
                    selected=index in result.selected_indices,
                )
            )
        active = ActiveReport(tuple(mutations), result.selected_indices, result.confirmed)

    urls = tuple(
        dict.fromkeys(
            [item.candidate_url for item in discovery.probes]
            + [item.candidate_url for item in detection.detections]
            + [item.endpoint for item in introspection.introspections]
            + [item.endpoint for item in schema_scan.schemas]
            + [item.endpoint for item in analysis.endpoints]
        )
    )
    endpoints = []
    for url in urls:
        detected = next((item for item in detection.detections if item.candidate_url == url), None)
        introspected = next(
            (item for item in introspection.introspections if item.endpoint == url), None
        )
        schema = next((item for item in schema_scan.schemas if item.endpoint == url), None)
        analyzed = next((item for item in analysis.endpoints if item.endpoint == url), None)
        endpoints.append(
            EndpointReport(
                endpoint=url,
                confidence=detected.confidence if detected else None,
                detection_reason=detected.reason if detected else None,
                get_signals=tuple(item.value for item in detected.get_signals) if detected else (),
                post_signals=tuple(item.value for item in detected.post_signals)
                if detected
                else (),
                introspection_status=introspected.status.value if introspected else None,
                introspection_reason=introspected.reason if introspected else None,
                schema_summary=schema.summary if schema else None,
                analyzed_operation_count=len(analyzed.operations)
                if analyzed and analyzed.success
                else None,
            )
        )
    issues = _issues(safe, queries, active)
    review = tuple(operation for item in analysis.endpoints for operation in item.review_candidates)
    counts = dict(sorted(Counter(item.evidence_type.value for item in evidence).items()))
    timestamp = generated_at or datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    context = ReportContext(
        report_schema_version=1,
        gqlsleuth_version=__version__,
        generated_at=timestamp.astimezone(UTC),
        target=discovery.target,
        mode=discovery.mode,
        summary=_summary(tuple(endpoints), queries, active, evidence, len(review)),
        endpoints=tuple(endpoints),
        review_candidates=review,
        queries=queries,
        active=active,
        evidence=evidence,
        evidence_counts=counts,
        errors_and_limitations=issues,
        recommendations=(),
        safety_notice=SAFETY_NOTICE,
        ai_interpretation=ai_interpretation,
        graphql_security_review=safe.query_generation.security_review,
        object_authorization_review=safe.object_authorization_review,
        authorization_policy_validation=safe.authorization_policy_validation,
        multiplicity=result.multiplicity if isinstance(result, ActiveExecutionScanResult) else None,
        query_depth=result.query_depth if isinstance(result, ActiveExecutionScanResult) else None,
        sequential_object_discovery=(
            result.sequential_object_discovery
            if isinstance(result, ActiveExecutionScanResult)
            else None
        ),
    )
    return deepcopy(replace(context, recommendations=_recommendations(context)))


def _execution(
    execution: QueryExecutionResult | MutationExecutionResult | None,
    artifact: OperationGenerationResult,
    evidence: tuple[Evidence, ...],
    kind: EvidenceType,
) -> ExecutionReport | None:
    if execution is None:
        return None
    ids = tuple(
        item.evidence_id
        for item in evidence
        if item.evidence_type is kind
        and item.endpoint == artifact.endpoint
        and item.query == artifact.query_text
        and item.variables == artifact.variables
    )
    return ExecutionReport(
        status=execution.status.value if execution.status else None,
        decision=execution.decision.value
        if isinstance(execution, MutationExecutionResult)
        else None,
        attempted=bool(ids),
        recorded_attempted=execution.attempted,
        reason=execution.reason,
        response=execution.response,
        error_type=execution.error_type,
        error_message=execution.error_message,
        evidence_ids=ids,
    )


def _summary(
    endpoints: tuple[EndpointReport, ...],
    queries: tuple[OperationReport, ...],
    active: ActiveReport | None,
    evidence: tuple[Evidence, ...],
    review_count: int,
) -> dict[str, int]:
    mutations = active.candidates if active else ()
    executions = [item.execution for item in queries if item.execution is not None]
    mutation_executions = [item.execution for item in mutations if item.execution is not None]
    return {
        "graphql_endpoint_count": sum(
            item.confidence in {ConfidenceLevel.CONFIRMED, ConfidenceLevel.PROBABLE}
            for item in endpoints
        ),
        "query_count": sum(
            item.schema_summary.query_field_count for item in endpoints if item.schema_summary
        ),
        "mutation_count": sum(
            item.schema_summary.mutation_field_count for item in endpoints if item.schema_summary
        ),
        "security_review_candidate_count": review_count,
        "generated_query_count": sum(item.generated.success for item in queries),
        "query_execution_count": sum(
            item.evidence_type is EvidenceType.QUERY_EXECUTION for item in evidence
        ),
        "successful_query_count": sum(
            item.attempted and item.status == "success" for item in executions
        ),
        "query_graphql_error_count": sum(
            item.attempted and item.status == "graphql_error" for item in executions
        ),
        "query_safety_skip_count": sum(item.status == "skipped_safety" for item in executions),
        "query_limit_skip_count": sum(item.status == "skipped_limit" for item in executions),
        "mutation_candidate_count": len(mutations),
        "generated_mutation_count": sum(item.generated.success for item in mutations),
        "mutation_safety_block_count": sum(
            item.preview_decision == "blocked_safety" for item in mutations
        ),
        "selected_mutation_count": sum(item.selected for item in mutations),
        "mutation_execution_count": sum(
            item.evidence_type is EvidenceType.MUTATION_EXECUTION for item in evidence
        ),
        "successful_mutation_count": sum(
            item.attempted and item.status == "success" for item in mutation_executions
        ),
    }


def _issues(
    safe: SafeExecutionScanResult,
    queries: tuple[OperationReport, ...],
    active: ActiveReport | None,
) -> tuple[ReportIssue, ...]:
    analysis = safe.query_generation.operation_analysis
    introspection = analysis.schema_scan.introspection
    issues = []
    for probe in introspection.detection.discovery.probes:
        if probe.error_type:
            issues.append(
                ReportIssue(
                    "discovery",
                    probe.candidate_url,
                    None,
                    probe.error_type,
                    probe.error_message or "",
                )
            )
    for detected in introspection.detection.detections:
        if detected.post_error_type:
            issues.append(
                ReportIssue(
                    "detection",
                    detected.candidate_url,
                    None,
                    detected.post_error_type,
                    detected.post_error_message or "",
                )
            )
    for item in introspection.introspections:
        if item.status.value != "enabled":
            issues.append(
                ReportIssue("introspection", item.endpoint, None, item.status.value, item.reason)
            )
        for error_type, message in (
            (item.minimal_error_type, item.minimal_error_message),
            (item.full_error_type, item.full_error_message),
        ):
            if error_type:
                issues.append(
                    ReportIssue("introspection", item.endpoint, None, error_type, message or "")
                )
    for schema in analysis.schema_scan.schemas:
        if not schema.success:
            issues.append(
                ReportIssue(
                    "schema",
                    schema.endpoint,
                    None,
                    schema.error_type or "schema_failed",
                    schema.error_message or "",
                )
            )
    for endpoint in analysis.endpoints:
        if not endpoint.success:
            issues.append(
                ReportIssue(
                    "analysis",
                    endpoint.endpoint,
                    None,
                    endpoint.error_type or "analysis_failed",
                    endpoint.error_message or "",
                )
            )
    for operation in (*queries, *(active.candidates if active else ())):
        artifact = operation.generated
        stage = artifact.operation.kind.value
        if artifact.failure_reason:
            issues.append(
                ReportIssue(
                    stage,
                    artifact.endpoint,
                    artifact.operation_name,
                    "generation_failed",
                    artifact.failure_reason,
                )
            )
        execution = operation.execution
        if execution:
            if (
                execution.status != "success"
                and execution.decision != MutationDecision.NOT_SELECTED.value
            ):
                issues.append(
                    ReportIssue(
                        stage,
                        artifact.endpoint,
                        artifact.operation_name,
                        execution.status or execution.decision or "not_executed",
                        execution.reason,
                    )
                )
            if execution.error_type:
                issues.append(
                    ReportIssue(
                        stage,
                        artifact.endpoint,
                        artifact.operation_name,
                        execution.error_type,
                        execution.error_message or "",
                    )
                )
            if execution.recorded_attempted and not execution.attempted:
                issues.append(
                    ReportIssue(
                        stage,
                        artifact.endpoint,
                        artifact.operation_name,
                        "missing_execution_evidence",
                        "Execution record has no matching execution evidence.",
                    )
                )
        elif operation.preview_decision:
            issues.append(
                ReportIssue(
                    stage,
                    artifact.endpoint,
                    artifact.operation_name,
                    operation.preview_decision,
                    operation.preview_reason or "",
                )
            )
    return tuple(issues)


def _recommendations(context: ReportContext) -> tuple[str, ...]:
    recommendations = []
    if any(
        item.priority in {InterestPriority.CRITICAL_INTEREST, InterestPriority.HIGH_INTEREST}
        for item in context.review_candidates
    ):
        recommendations.append(
            "Manually review operations marked CRITICAL INTEREST or HIGH INTEREST "
            "and their recorded rule matches."
        )
    if any(
        set(item.categories)
        & {OperationCategory.TOKENS_AND_SESSIONS, OperationCategory.SECRETS_AND_CREDENTIALS}
        for item in context.review_candidates
    ):
        recommendations.append(
            "Review operations with recorded token/session or credential categories "
            "and their supporting schema context."
        )
    if any(item.code == "graphql_error" for item in context.errors_and_limitations):
        recommendations.append(
            "Review recorded GraphQL errors; manually adjust generated placeholders "
            "when application semantics require it."
        )
    if any(
        item.generated.manual_adjustments
        for item in (*context.queries, *(context.active.candidates if context.active else ()))
    ):
        recommendations.append(
            "Review the generated artifacts' manual-adjustment notes before "
            "using their placeholder values."
        )
    if context.active and any(
        item.preview_decision == MutationDecision.BLOCKED_SAFETY.value
        for item in context.active.candidates
    ):
        recommendations.append(
            "Review BLOCKED_SAFETY Mutations manually; do not execute them automatically."
        )
    if any(item.stage in {"introspection", "schema"} for item in context.errors_and_limitations):
        recommendations.append(
            "Investigate the recorded introspection or schema-parsing failures manually."
        )
    if any(item.code.startswith("Http") for item in context.errors_and_limitations):
        recommendations.append(
            "Investigate recorded transport failures before drawing conclusions "
            "about endpoint availability."
        )
    return tuple(recommendations)
