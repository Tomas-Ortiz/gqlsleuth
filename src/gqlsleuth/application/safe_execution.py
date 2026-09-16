"""Coordinate sequential Phase 9 execution of validated generated Query artifacts."""

from dataclasses import dataclass

from gqlsleuth.application.query_generation import (
    QueryGenerationScanResult,
    run_query_generation_scan,
)
from gqlsleuth.domain.exceptions import HttpError, SafeExecutionValidationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.object_authorization import ObjectAuthorizationResult
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.graphql.safe_execution import (
    classify_execution_response,
    side_effect_tokens,
    validate_safe_artifact,
)
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest, HttpResponse

MAX_QUERY_EXECUTIONS = 20
EXECUTION_SOURCE = "gqlsleuth.application.safe_execution"


@dataclass(frozen=True)
class QueryExecutionResult:
    """Outcome of validating and optionally executing one generated Query artifact."""

    generated_query: QueryGenerationResult
    status: QueryExecutionStatus
    attempted: bool
    response: HttpResponse | None
    error_type: str | None
    error_message: str | None
    reason: str

    @property
    def endpoint(self) -> str:
        return self.generated_query.endpoint

    @property
    def operation_name(self) -> str:
        return self.generated_query.operation_name


@dataclass(frozen=True)
class SafeExecutionScanResult:
    """Complete Phase 8 result plus ordered Phase 9 execution outcomes."""

    query_generation: QueryGenerationScanResult
    executions: tuple[QueryExecutionResult, ...]
    execution_evidence: tuple[Evidence, ...]
    object_authorization_review: ObjectAuthorizationResult | None = None

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        """Return Phase 3 through Phase 9 evidence in production order."""
        return (
            self.query_generation.evidence
            + self.execution_evidence
            + (
                self.object_authorization_review.evidence
                if self.object_authorization_review
                else ()
            )
        )


def run_safe_execution_scan(
    target_url: str,
    *,
    mode: ScanMode = ScanMode.SAFE,
    http_settings: HttpClientSettings | None = None,
) -> SafeExecutionScanResult:
    """Run Phases 3–9, executing only validated generated Query operations."""
    generation = run_query_generation_scan(target_url, mode=mode, http_settings=http_settings)
    with HttpClient(http_settings) as client:
        return execute_generated_queries(generation, client=client)


def execute_generated_queries(
    query_generation: QueryGenerationScanResult,
    *,
    client: HttpClient,
) -> SafeExecutionScanResult:
    """Validate and sequentially execute safe artifacts in Phase 7 priority order."""
    schemas = {
        result.endpoint: result.schema
        for result in query_generation.operation_analysis.schema_scan.schemas
        if result.success and result.schema is not None
    }
    results: list[QueryExecutionResult] = []
    evidence: list[Evidence] = []
    attempted_count = 0

    for artifact in query_generation.queries:
        if not artifact.success:
            continue
        schema = schemas.get(artifact.endpoint)
        try:
            if schema is None:
                raise SafeExecutionValidationError(
                    "Parsed schema is unavailable for this endpoint."
                )
            validate_safe_artifact(schema, artifact)
        except SafeExecutionValidationError as error:
            results.append(_skipped(artifact, QueryExecutionStatus.SKIPPED_SAFETY, str(error)))
            continue

        action_tokens = side_effect_tokens(artifact.operation_name)
        if action_tokens:
            tokens = ", ".join(action_tokens)
            results.append(
                _skipped(
                    artifact,
                    QueryExecutionStatus.SKIPPED_SAFETY,
                    f"Query name contains explicit state-changing action token(s): {tokens}.",
                )
            )
            continue
        if attempted_count >= MAX_QUERY_EXECUTIONS:
            results.append(
                _skipped(
                    artifact,
                    QueryExecutionStatus.SKIPPED_LIMIT,
                    f"Per-scan safe execution limit of {MAX_QUERY_EXECUTIONS} was reached.",
                )
            )
            continue

        attempted_count += 1
        result = _execute_one(artifact, client)
        results.append(result)
        evidence.append(_execution_evidence(query_generation, result))

    return SafeExecutionScanResult(
        query_generation=query_generation,
        executions=tuple(results),
        execution_evidence=tuple(evidence),
    )


def _execute_one(artifact: QueryGenerationResult, client: HttpClient) -> QueryExecutionResult:
    if artifact.query_text is None:
        raise ValueError("Successful query artifact is missing query text.")
    try:
        response = client.send(
            HttpRequest(
                method="POST",
                url=artifact.endpoint,
                json_body={"query": artifact.query_text, "variables": artifact.variables},
            )
        )
    except HttpError as error:
        error_type = type(error).__name__
        return QueryExecutionResult(
            generated_query=artifact,
            status=QueryExecutionStatus.NETWORK_FAILURE,
            attempted=True,
            response=None,
            error_type=error_type,
            error_message=str(error),
            reason=f"Query request failed with {error_type}.",
        )

    classification = classify_execution_response(response.status_code, response.body)
    return QueryExecutionResult(
        generated_query=artifact,
        status=classification.status,
        attempted=True,
        response=response,
        error_type=None,
        error_message=None,
        reason=classification.reason,
    )


def _skipped(
    artifact: QueryGenerationResult,
    status: QueryExecutionStatus,
    reason: str,
) -> QueryExecutionResult:
    return QueryExecutionResult(
        generated_query=artifact,
        status=status,
        attempted=False,
        response=None,
        error_type=None,
        error_message=None,
        reason=reason,
    )


def _execution_evidence(
    query_generation: QueryGenerationScanResult,
    result: QueryExecutionResult,
) -> Evidence:
    artifact = result.generated_query
    response = result.response
    priority = artifact.operation.priority.value
    return Evidence(
        evidence_type=EvidenceType.QUERY_EXECUTION,
        target=(
            query_generation.operation_analysis.schema_scan.introspection.detection.discovery.target
        ),
        endpoint=artifact.endpoint,
        summary=(
            f"Query '{artifact.operation_name}' execution produced "
            f"{result.status.value.upper()}: {result.reason}"
        ),
        source=EXECUTION_SOURCE,
        notes=(
            f"Operation kind: {artifact.operation_kind.value}",
            f"Review priority: {priority}",
            f"Interest score: {artifact.operation.interest_score}",
            *artifact.manual_adjustments,
        ),
        query=artifact.query_text,
        variables=artifact.variables,
        request_method="POST",
        response_status_code=response.status_code if response is not None else None,
        response_headers=response.headers if response is not None else None,
        response_body=response.body if response is not None else None,
        duration_seconds=response.duration_seconds if response is not None else None,
        error_type=result.error_type,
        error_message=result.error_message,
    )
