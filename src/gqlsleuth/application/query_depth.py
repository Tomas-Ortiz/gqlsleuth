"""Independent ACTIVE depth preparation and one-request execution budget."""

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter

from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.exceptions import (
    GQLSleuthError,
    HttpError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.query_depth import (
    MAX_PHASE18_REQUESTS,
    QueryDepthDecision,
    QueryDepthEvidence,
    QueryDepthExecutionResult,
    QueryDepthObservation,
    QueryDepthProbePreview,
    QueryDepthValidationResult,
)
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.graphql.query_depth import build_depth_query, classify_depth_response
from gqlsleuth.graphql.schema_parser import load_introspection_schema
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest
from gqlsleuth.rules.schema_graph import build_type_graph, cycle_witnesses, format_path


@dataclass(frozen=True)
class QueryDepthPreviewResult:
    safe_execution: SafeExecutionScanResult
    candidates: tuple[QueryDepthProbePreview, ...]
    limitations: tuple[str, ...]

    @property
    def mode(self) -> ScanMode:
        schema_scan = self.safe_execution.query_generation.operation_analysis.schema_scan
        return schema_scan.introspection.detection.discovery.mode


def prepare_query_depth(safe: SafeExecutionScanResult) -> QueryDepthPreviewResult:
    preview = QueryDepthPreviewResult(safe, (), ())
    if preview.mode is not ScanMode.ACTIVE:
        return preview
    generation = safe.query_generation
    schema_scan = generation.operation_analysis.schema_scan
    review = generation.security_review
    candidates: list[QueryDepthProbePreview] = []
    limitations = []
    for endpoint in schema_scan.schemas:
        witnesses = (
            tuple(
                item
                for item in review.candidates
                if item.endpoint == endpoint.endpoint
                and item.candidate_type is SecurityCandidateType.RECURSIVE_GRAPH_REVIEW
            )
            if review
            else ()
        )
        if not witnesses or endpoint.schema is None:
            limitations.append(
                f"{endpoint.endpoint}: no retained Query-reachable recursive graph candidate."
            )
            continue
        introspection = next(
            (
                item.full_response
                for item in schema_scan.introspection.introspections
                if item.endpoint == endpoint.endpoint and item.full_response
            ),
            None,
        )
        if introspection is None:
            limitations.append(
                f"{endpoint.endpoint}: retained schema validation data is unavailable."
            )
            continue
        try:
            native = load_introspection_schema(introspection.body)
        except SchemaParsingError:
            limitations.append(f"{endpoint.endpoint}: retained schema validation failed.")
            continue
        graph = build_type_graph(endpoint.schema.types, inputs=False)
        # Recover the exact typed Phase 16 witness using its existing algorithm, never
        # interpret a human path string or invent a different recursion detector.
        cycles = [
            (cycle, witness)
            for cycle in cycle_witnesses(graph, require_list=True)
            for witness in witnesses
            if witness.subject == cycle[0].label
            and "Cycle: " + format_path(cycle) in witness.supporting_facts
        ]
        artifacts = [item for item in generation.queries if item.endpoint == endpoint.endpoint]
        attempts = [
            execution
            for artifact in artifacts
            for execution in safe.executions
            if execution.generated_query == artifact
            and execution.attempted
            and execution.status
            in {QueryExecutionStatus.SUCCESS, QueryExecutionStatus.GRAPHQL_ERROR}
        ]
        attempts.sort(key=lambda item: item.status is not QueryExecutionStatus.SUCCESS)
        chosen = None
        reason = (
            "No meaningful attempted safe Query can be associated "
            "with the retained recursive witness."
        )
        for attempt in attempts:
            for cycle, witness in cycles:
                try:
                    query, baseline, depth, path, lists = build_depth_query(
                        endpoint.schema, native, attempt.generated_query, graph, cycle
                    )
                except SafeExecutionValidationError as error:
                    reason = str(error)
                    continue
                references = tuple(
                    dict.fromkeys(
                        (
                            *witness.source_evidence_ids,
                            *(
                                item.evidence_id
                                for item in safe.execution_evidence
                                if item.evidence_type is EvidenceType.QUERY_EXECUTION
                                and item.endpoint == endpoint.endpoint
                                and item.query == attempt.generated_query.query_text
                            ),
                        )
                    )
                )
                chosen = QueryDepthProbePreview(
                    deepcopy(attempt.generated_query),
                    query,
                    attempt.status,
                    baseline,
                    depth,
                    path,
                    lists,
                    references,
                )
                break
            if chosen:
                break
        if chosen:
            candidates.append(chosen)
        else:
            limitations.append(f"{endpoint.endpoint}: {reason}")
    if not schema_scan.schemas:
        limitations.append("No retained schema is available for Query-Depth preparation.")
    return QueryDepthPreviewResult(safe, tuple(candidates), tuple(limitations))


def execute_query_depth(
    preview: QueryDepthPreviewResult,
    *,
    selected_indices: tuple[int, ...] = (),
    confirmed: bool = False,
    client: HttpClient | None = None,
    http_settings: HttpClientSettings | None = None,
) -> QueryDepthValidationResult:
    if any(
        type(index) is not int or not 1 <= index <= len(preview.candidates)
        for index in selected_indices
    ):
        raise GQLSleuthError("Query-Depth selection contains an unknown candidate index.")
    if client is None:
        with HttpClient(http_settings) as owned:
            return execute_query_depth(
                preview, selected_indices=selected_indices, confirmed=confirmed, client=owned
            )
    canonical = prepare_query_depth(preview.safe_execution)
    selected = frozenset(selected_indices)
    attempted = 0
    results = []
    for index, candidate in enumerate(preview.candidates, 1):
        evidence = None
        if preview.mode is not ScanMode.ACTIVE:
            decision, reason = (
                QueryDepthDecision.MODE_DISABLED,
                "Query-Depth checks require ACTIVE mode.",
            )
        elif index > len(canonical.candidates) or not _matches(
            candidate, canonical.candidates[index - 1]
        ):
            decision, reason = (
                QueryDepthDecision.INVALID_ARTIFACT,
                "Candidate does not match the retained source and bounded path.",
            )
        elif index not in selected:
            decision, reason = QueryDepthDecision.NOT_SELECTED, "Depth probe was not selected."
        elif confirmed is not True:
            decision, reason = (
                QueryDepthDecision.DECLINED,
                "Explicit depth-probe confirmation was not given.",
            )
        elif attempted >= MAX_PHASE18_REQUESTS:
            decision, reason = (
                QueryDepthDecision.SKIPPED_LIMIT,
                "One Phase 18 request per scan is allowed.",
            )
        else:
            attempted += 1
            evidence = _execute_one(candidate, preview.safe_execution, client)
            decision, reason = QueryDepthDecision.EXECUTED, evidence.summary
        results.append(
            QueryDepthExecutionResult(candidate, index in selected, decision, reason, evidence)
        )
    return QueryDepthValidationResult(
        preview.candidates,
        tuple(sorted(selected)),
        confirmed is True,
        tuple(results),
        canonical.limitations,
    )


def _matches(candidate: QueryDepthProbePreview, expected: QueryDepthProbePreview) -> bool:
    if (
        type(candidate.baseline_depth) is not int
        or type(candidate.probe_depth) is not int
        or type(candidate.list_edges) is not int
        or not isinstance(candidate.baseline_status, QueryExecutionStatus)
    ):
        return False
    try:
        return candidate == expected and json.dumps(
            candidate.base.variables, sort_keys=True, allow_nan=False
        ) == json.dumps(expected.base.variables, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return False


def _execute_one(
    candidate: QueryDepthProbePreview, safe: SafeExecutionScanResult, client: HttpClient
) -> QueryDepthEvidence:
    timestamp, started = datetime.now(UTC), perf_counter()
    response = None
    error_type = error_message = None
    variables = deepcopy(candidate.base.variables)
    try:
        response = client.send(
            HttpRequest(
                method="POST",
                url=candidate.base.endpoint,
                json_body={"query": candidate.query, "variables": variables},
            )
        )
    except HttpError as error:
        observation, reason = (
            QueryDepthObservation.NETWORK_FAILURE,
            "Depth probe failed with a normalized transport error.",
        )
        error_type, error_message = type(error).__name__, str(error)
    else:
        observation, reason = classify_depth_response(
            response.status_code, response.body, candidate.base.operation_name
        )
    return QueryDepthEvidence(
        target=safe.query_generation.operation_analysis.schema_scan.introspection.detection.discovery.target,
        endpoint=candidate.base.endpoint,
        timestamp=timestamp,
        source="gqlsleuth.application.query_depth",
        summary=reason,
        representative_operation=candidate.base.operation_name,
        baseline_status=candidate.baseline_status,
        baseline_depth=candidate.baseline_depth,
        probe_depth=candidate.probe_depth,
        recursive_path=candidate.recursive_path,
        list_edges=candidate.list_edges,
        source_evidence_ids=candidate.source_evidence_ids,
        query=candidate.query,
        variables=variables,
        request_method="POST",
        observation=observation,
        response_status_code=response.status_code if response else None,
        response_headers=response.headers if response else None,
        response_body=response.body if response else None,
        duration_seconds=response.duration_seconds if response else perf_counter() - started,
        error_type=error_type,
        error_message=error_message,
    )
