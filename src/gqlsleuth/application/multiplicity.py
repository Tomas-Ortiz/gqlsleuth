"""Prepare and independently gate at most two sequential behavior-probe requests."""

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter

from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.exceptions import GQLSleuthError, HttpError, SafeExecutionValidationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.multiplicity import (
    ALIAS_COUNT,
    BATCH_SIZE,
    MAX_PHASE17_REQUESTS,
    MultiplicityDecision,
    MultiplicityEvidence,
    MultiplicityObservation,
    MultiplicityProbeExecutionResult,
    MultiplicityProbePreview,
    MultiplicityProbeType,
    MultiplicityValidationResult,
)
from gqlsleuth.graphql.multiplicity import classify_probe_response, prepare_probe
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest


@dataclass(frozen=True)
class MultiplicityPreviewResult:
    safe_execution: SafeExecutionScanResult
    candidates: tuple[MultiplicityProbePreview, ...]
    limitations: tuple[str, ...]

    @property
    def mode(self) -> ScanMode:
        schema_scan = self.safe_execution.query_generation.operation_analysis.schema_scan
        return schema_scan.introspection.detection.discovery.mode


def prepare_multiplicity(safe: SafeExecutionScanResult) -> MultiplicityPreviewResult:
    """One representative per endpoint: successful attempts first, then retained Query order."""
    preview = MultiplicityPreviewResult(safe, (), ())
    if preview.mode is not ScanMode.ACTIVE:
        return preview
    schemas = safe.query_generation.operation_analysis.schema_scan.schemas
    candidates: list[MultiplicityProbePreview] = []
    limitations = []
    for parsed in schemas:
        chosen = None
        if parsed.schema is not None:
            artifacts = [
                item for item in safe.query_generation.queries if item.endpoint == parsed.endpoint
            ]
            for success_only in (True, False):
                for artifact in artifacts:
                    attempt = next(
                        (
                            item
                            for item in safe.executions
                            if item.generated_query == artifact
                            and item.attempted
                            and item.status
                            in {
                                QueryExecutionStatus.SUCCESS,
                                QueryExecutionStatus.GRAPHQL_ERROR,
                                QueryExecutionStatus.HTTP_ERROR,
                                QueryExecutionStatus.INVALID_RESPONSE,
                                QueryExecutionStatus.NETWORK_FAILURE,
                            }
                        ),
                        None,
                    )
                    if attempt is None or (
                        success_only and attempt.status is not QueryExecutionStatus.SUCCESS
                    ):
                        continue
                    try:
                        chosen = tuple(
                            prepare_probe(parsed.schema, artifact, kind)
                            for kind in MultiplicityProbeType
                        )
                    except SafeExecutionValidationError:
                        continue
                    break
                if chosen:
                    break
        if chosen:
            candidates.extend(chosen)
        else:
            limitations.append(f"{parsed.endpoint}: no eligible attempted safe Query is available.")
    if not schemas:
        limitations.append("No retained schema is available for representative Query selection.")
    return MultiplicityPreviewResult(safe, tuple(candidates), tuple(limitations))


def execute_multiplicity(
    preview: MultiplicityPreviewResult,
    *,
    selected_indices: tuple[int, ...] = (),
    confirmed: bool = False,
    client: HttpClient | None = None,
    http_settings: HttpClientSettings | None = None,
) -> MultiplicityValidationResult:
    """Rebuild exact expected candidates; neither metadata nor CLI confirmation is trusted."""
    if any(
        type(index) is not int or not 1 <= index <= len(preview.candidates)
        for index in selected_indices
    ):
        raise GQLSleuthError("Query-Shape selection contains an unknown candidate index.")
    if client is None:
        with HttpClient(http_settings) as owned:
            return execute_multiplicity(
                preview, selected_indices=selected_indices, confirmed=confirmed, client=owned
            )
    canonical = prepare_multiplicity(preview.safe_execution)
    selected = frozenset(selected_indices)
    used_types: set[MultiplicityProbeType] = set()
    results = []
    for index, candidate in enumerate(preview.candidates, 1):
        evidence = None
        if preview.mode is not ScanMode.ACTIVE:
            decision, reason = (
                MultiplicityDecision.MODE_DISABLED,
                "Query-Shape checks require ACTIVE mode.",
            )
        elif index > len(canonical.candidates) or not _matches(
            candidate, canonical.candidates[index - 1]
        ):
            decision, reason = (
                MultiplicityDecision.INVALID_ARTIFACT,
                "Candidate does not match the retained safe Query and expected probe.",
            )
        elif index not in selected:
            decision, reason = MultiplicityDecision.NOT_SELECTED, "Probe was not selected."
        elif confirmed is not True:
            decision, reason = (
                MultiplicityDecision.DECLINED,
                "Explicit final batch confirmation was not given.",
            )
        elif len(used_types) >= MAX_PHASE17_REQUESTS or candidate.probe_type in used_types:
            decision, reason = (
                MultiplicityDecision.SKIPPED_LIMIT,
                "At most one request per probe type and two requests per scan are allowed.",
            )
        else:
            used_types.add(candidate.probe_type)
            evidence = _execute_one(candidate, preview.safe_execution, client)
            decision, reason = MultiplicityDecision.EXECUTED, evidence.summary
        results.append(
            MultiplicityProbeExecutionResult(
                candidate, index in selected, decision, reason, evidence
            )
        )
    return MultiplicityValidationResult(
        preview.candidates,
        tuple(sorted(selected)),
        confirmed is True,
        tuple(results),
        canonical.limitations,
    )


def _matches(candidate: MultiplicityProbePreview, expected: MultiplicityProbePreview) -> bool:
    # JSON distinguishes booleans, integers and floats that Python equality conflates.
    if not isinstance(candidate.probe_type, MultiplicityProbeType) or candidate != expected:
        return False
    try:
        return all(
            json.dumps(left, sort_keys=True, allow_nan=False)
            == json.dumps(right, sort_keys=True, allow_nan=False)
            for left, right in (
                (candidate.request_json, expected.request_json),
                (candidate.base.variables, expected.base.variables),
            )
        )
    except (TypeError, ValueError, RecursionError):
        return False


def _execute_one(
    candidate: MultiplicityProbePreview, safe: SafeExecutionScanResult, client: HttpClient
) -> MultiplicityEvidence:
    timestamp = datetime.now(UTC)
    started = perf_counter()
    response = None
    statuses: tuple[QueryExecutionStatus, ...]
    error_type = error_message = None
    request = deepcopy(candidate.request_json)
    try:
        response = client.send(
            HttpRequest(method="POST", url=candidate.base.endpoint, json_body=request)
        )
    except HttpError as error:
        observation = MultiplicityObservation.NETWORK_FAILURE
        error_type, error_message = type(error).__name__, str(error)
        reason, statuses = "Probe request failed with a normalized transport error.", ()
    else:
        observation, reason, statuses = classify_probe_response(
            candidate.probe_type, response.status_code, response.body
        )
    return MultiplicityEvidence(
        target=safe.query_generation.operation_analysis.schema_scan.introspection.detection.discovery.target,
        endpoint=candidate.base.endpoint,
        timestamp=timestamp,
        source="gqlsleuth.application.multiplicity",
        summary=reason,
        probe_type=candidate.probe_type,
        representative_operation=candidate.base.operation_name,
        multiplicity=ALIAS_COUNT
        if candidate.probe_type is MultiplicityProbeType.ALIAS_MULTIPLICITY
        else BATCH_SIZE,
        query=candidate.query,
        variables=deepcopy(candidate.base.variables),
        request_json=request,
        request_method="POST",
        observation=observation,
        entry_statuses=statuses,
        response_status_code=response.status_code if response else None,
        response_headers=response.headers if response else None,
        response_body=response.body if response else None,
        duration_seconds=response.duration_seconds if response else perf_counter() - started,
        error_type=error_type,
        error_message=error_message,
    )
