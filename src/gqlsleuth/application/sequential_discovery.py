"""Independent, confirmed ACTIVE requests for the seed and its two immediate neighbors."""

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from time import perf_counter
from typing import Literal, cast

from graphql import GraphQLError

from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.object_lookup import retained_object_lookup
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.models import EvidenceType, ScanMode, Target
from gqlsleuth.domain.object_authorization import (
    ObjectAuthorizationCase,
    ObjectAuthorizationMode,
    ObjectOutcome,
)
from gqlsleuth.domain.sequential_discovery import (
    MAX_PHASE22_IDENTIFIER,
    MAX_PHASE22_NEIGHBORS_PER_SEED,
    MAX_PHASE22_REQUESTS,
    PHASE22_OFFSETS,
    SequentialDiscoveryCandidate,
    SequentialDiscoveryEvidence,
    SequentialDiscoveryExecution,
    SequentialDiscoveryProbe,
    SequentialDiscoveryResult,
    SequentialDiscoverySeed,
    parse_discovery_seeds,
)
from gqlsleuth.graphql.object_authorization import build_object_query, classify_object_response
from gqlsleuth.graphql.schema_parser import load_introspection_schema
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest


def _validate_seeds(seeds: tuple[SequentialDiscoverySeed, ...]) -> None:
    if any(
        not isinstance(seed, SequentialDiscoverySeed)
        or type(seed.index) is not int
        or any(type(value) is not str for value in (seed.operation, seed.argument, seed.identifier))
        for seed in seeds
    ):
        raise HttpConfigurationError("idor-seeds must contain validated typed input.")
    canonical = parse_discovery_seeds(
        [f"{seed.operation}:{seed.argument}={seed.identifier}" for seed in seeds]
    )
    if canonical != seeds:
        raise HttpConfigurationError("idor-seeds must retain their validated input identity/order.")


def prepare_sequential_discovery(
    safe: SafeExecutionScanResult,
    *,
    seeds: tuple[SequentialDiscoverySeed, ...],
    enabled: bool = False,
    http_settings: HttpClientSettings | None = None,
) -> SequentialDiscoveryResult:
    """Build exact requests locally. SAFE/disabled callers never derive adjacent identifiers."""
    _validate_seeds(seeds)
    settings = http_settings or HttpClientSettings()
    result = SequentialDiscoveryResult(
        seeds, has_supplied_context_headers=bool(settings.custom_headers)
    )
    schema_scan = safe.query_generation.operation_analysis.schema_scan
    if (
        enabled is not True
        or schema_scan.introspection.detection.discovery.mode is not ScanMode.ACTIVE
    ):
        return replace(
            result,
            limitations=("Sequential discovery requires explicit enablement and ACTIVE mode.",),
        )
    probes = []
    limitations = []
    for seed in seeds:
        try:
            artifact, source = retained_object_lookup(safe, seed.operation)
            schema = next(
                (
                    item.schema
                    for item in schema_scan.schemas
                    if item.endpoint == artifact.endpoint
                    and item.success
                    and item.schema is not None
                ),
                None,
            )
            response = next(
                (
                    item.full_response
                    for item in schema_scan.introspection.introspections
                    if item.endpoint == artifact.endpoint and item.full_response is not None
                ),
                None,
            )
            if schema is None or response is None:
                raise SafeExecutionValidationError("Retained schema is unavailable.")
            native = load_introspection_schema(response.body)
            references = tuple(
                dict.fromkeys(
                    (
                        *source.source_evidence_ids,
                        *(
                            item.evidence_id
                            for item in safe.evidence
                            if item.endpoint == artifact.endpoint
                            and (
                                item.evidence_type is EvidenceType.SCHEMA_ARTIFACT
                                or item.evidence_type is EvidenceType.GENERATED_QUERY
                                and item.query == artifact.query_text
                            )
                        ),
                    )
                )
            )
            # Only adapt the pure Phase 20 helper's input shape; never run that stage
            # or manufacture a Phase 20 scan result/evidence/policy case.
            case = ObjectAuthorizationCase(
                ObjectAuthorizationMode.ANONYMOUS_ONLY,
                None,
                seed.operation,
                seed.argument,
                seed.identifier,
                seed.index,
            )
            query, variables = build_object_query(schema, native, artifact, case)
            baseline = replace(artifact, query_text=query, variables=variables)
            seed_probes = []
            offsets = (0, *PHASE22_OFFSETS[:MAX_PHASE22_NEIGHBORS_PER_SEED])
            for offset in offsets:
                numeric = int(seed.identifier) + offset
                if not 0 <= numeric <= MAX_PHASE22_IDENTIFIER:
                    continue
                identifier = str(numeric)
                query, variables = build_object_query(
                    schema, native, baseline, replace(case, identifier=identifier)
                )
                seed_probes.append(
                    SequentialDiscoveryProbe(
                        seed,
                        artifact.endpoint,
                        identifier,
                        offset,
                        query,
                        variables,
                        (seed.operation, "id"),
                        source,
                        references,
                    )
                )
            probes.extend(seed_probes)
        except (
            SafeExecutionValidationError,
            SchemaParsingError,
            GraphQLError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            limitations.append(
                f"Seed {seed.index}: compatible direct ID object lookup, direct output id "
                "or valid unambiguous retained Query/schema is unavailable."
            )
    return replace(result, probes=tuple(probes), limitations=tuple(limitations))


def _matches(plan: SequentialDiscoveryResult, fresh: SequentialDiscoveryResult) -> bool:
    try:
        return (
            plan == fresh
            and type(plan.has_supplied_context_headers) is bool
            and all(type(item.offset) is int for item in plan.probes)
            and exact_variables(tuple(item.variables for item in plan.probes))
            == exact_variables(tuple(item.variables for item in fresh.probes))
        )
    except (TypeError, ValueError, RecursionError):
        return False


def execute_sequential_discovery(
    safe: SafeExecutionScanResult,
    *,
    seeds: tuple[SequentialDiscoverySeed, ...],
    enabled: bool = False,
    confirmed: bool = False,
    preview: SequentialDiscoveryResult | None = None,
    http_settings: HttpClientSettings | None = None,
) -> SequentialDiscoveryResult:
    """Rebuild and validate before each POST; never use a response as a derivation source."""
    settings = http_settings or HttpClientSettings()
    canonical = prepare_sequential_discovery(
        safe, seeds=seeds, enabled=enabled, http_settings=settings
    )
    planned = preview if preview is not None else canonical
    executions: list[SequentialDiscoveryExecution] = []
    candidates = []
    limitations = list(canonical.limitations)
    baselines: dict[int, SequentialDiscoveryEvidence] = {}
    schema_scan = safe.query_generation.operation_analysis.schema_scan
    discovery = schema_scan.introspection.detection.discovery
    for position, probe in enumerate(canonical.probes):
        # Rechecking the complete canonical plan prevents reordered, duplicated or forged
        # requests, including modifications to unrelated variables or retained schema.
        fresh = prepare_sequential_discovery(
            safe, seeds=seeds, enabled=enabled, http_settings=settings
        )
        reason = None
        if enabled is not True or discovery.mode is not ScanMode.ACTIVE:
            reason = "Sequential discovery requires explicit enablement and ACTIVE mode."
        elif confirmed is not True:
            reason = "Separate sequential-discovery confirmation was not given."
        elif not _matches(planned, fresh) or not _matches(canonical, fresh):
            reason = "Prepared discovery does not match the rebuilt seed plan."
        elif sum(item.attempted for item in executions) >= MAX_PHASE22_REQUESTS:
            reason = "Six-request sequential-discovery budget reached."
        elif probe.offset != 0 and probe.seed.index not in baselines:
            reason = (
                "Adjacent discovery was not performed because the seed object was not confirmed."
            )
        if reason:
            executions.append(SequentialDiscoveryExecution(probe, False, None, None, reason))
            if reason not in limitations:
                limitations.append(reason)
            continue
        # Send only the fresh canonical request, never a caller-mutated preview object.
        evidence = _request(fresh.probes[position], settings, discovery.target)
        executions.append(
            SequentialDiscoveryExecution(
                probe,
                True,
                evidence.outcome,
                evidence.returned_id_matches,
                evidence.summary,
                evidence,
            )
        )
        if evidence.outcome is not ObjectOutcome.TARGET_RETURNED:
            continue
        if probe.offset == 0:
            baselines[probe.seed.index] = evidence
        else:
            candidates.append(
                SequentialDiscoveryCandidate(
                    probe.seed,
                    probe.requested_identifier,
                    probe.offset,
                    canonical.has_supplied_context_headers,
                    (
                        *probe.source_evidence_ids,
                        baselines[probe.seed.index].evidence_id,
                        evidence.evidence_id,
                    ),
                    "Adjacent object access observed. The exact object requested using a generated "
                    "adjacent identifier was returned under the same request context. Review "
                    "whether access to neighboring objects is intended and object-level "
                    "authorization is enforced.",
                )
            )
    return replace(
        canonical,
        confirmed=confirmed is True,
        executions=tuple(executions),
        candidates=tuple(candidates),
        limitations=tuple(limitations),
        attempted_request_count=sum(item.attempted for item in executions),
    )


def _request(
    probe: SequentialDiscoveryProbe,
    settings: HttpClientSettings,
    target: Target,
) -> SequentialDiscoveryEvidence:
    timestamp, started = datetime.now(UTC), perf_counter()
    response = None
    error_type = None
    try:
        # Fresh sessions keep learned cookies from silently changing the request context.
        with HttpClient(settings) as client:
            response = client.send(
                HttpRequest(
                    method="POST",
                    url=probe.endpoint,
                    json_body={"query": probe.query, "variables": deepcopy(probe.variables)},
                )
            )
    except HttpError as error:
        error_type = type(error).__name__
        outcome, matches, reason = ObjectOutcome.NETWORK_FAILURE, None, "Target transport failed."
    else:
        outcome, matches, reason = classify_object_response(
            response.status_code, response.body, probe.seed.operation, probe.requested_identifier
        )
        if outcome is ObjectOutcome.TARGET_RETURNED:
            reason = "The direct returned id exactly matches the requested identifier."
    return SequentialDiscoveryEvidence(
        target=target,
        endpoint=probe.endpoint,
        timestamp=timestamp,
        summary=reason,
        source="gqlsleuth.application.sequential_discovery",
        root_operation=probe.seed.operation,
        identifier_argument=probe.seed.argument,
        operator_seed=probe.seed.identifier,
        requested_identifier=probe.requested_identifier,
        offset=cast(Literal[-1, 0, 1], probe.offset),
        has_supplied_context_headers=bool(settings.custom_headers),
        source_evidence_ids=probe.source_evidence_ids,
        query=probe.query,
        variables=deepcopy(probe.variables),
        request_method="POST",
        outcome=outcome,
        returned_id_matches=matches,
        response_status_code=response.status_code if response else None,
        response_headers=response.headers if response else None,
        response_body=response.body if response else None,
        duration_seconds=response.duration_seconds if response else perf_counter() - started,
        error_type=error_type,
        error_message="Target transport failed." if error_type else None,
    )
