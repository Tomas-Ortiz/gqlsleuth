"""Shared bounded object planning, transport and baseline accounting."""

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from time import perf_counter

from graphql import GraphQLError

from gqlsleuth.application.object_lookup import retained_object_lookup
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.models import EvidenceType
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
    SequentialDiscoveryProbe,
    SequentialDiscoverySeed,
    parse_discovery_seeds,
)
from gqlsleuth.graphql.object_authorization import build_object_query, classify_object_response
from gqlsleuth.graphql.schema_parser import load_introspection_schema
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings, HttpRequest


def validate_seeds(seeds: tuple[SequentialDiscoverySeed, ...]) -> None:
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


def prepare_object_probes(
    safe: SafeExecutionScanResult, seeds: tuple[SequentialDiscoverySeed, ...]
) -> tuple[tuple[SequentialDiscoveryProbe, ...], tuple[str, ...]]:
    """Local shared seed/-1/+1 plan using retained object lookup artifacts."""
    validate_seeds(seeds)
    schema_scan = safe.query_generation.operation_analysis.schema_scan
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
    return tuple(probes), tuple(limitations)


@dataclass(frozen=True)
class ObjectProbeFacts:
    timestamp: datetime
    summary: str
    outcome: ObjectOutcome
    returned_id_matches: bool | None
    response_status_code: int | None
    response_headers: dict[str, str] | None
    response_body: bytes | None
    duration_seconds: float
    error_type: str | None
    error_message: str | None


def request_object_probe(
    probe: SequentialDiscoveryProbe,
    settings: HttpClientSettings,
    client_factory: Callable[[HttpClientSettings], HttpClient],
) -> ObjectProbeFacts:
    """One POST with fresh cookies, normalized failure and shared exact-ID classification."""
    timestamp, started = datetime.now(UTC), perf_counter()
    response = None
    error_type = None
    try:
        # Fresh sessions keep learned cookies from silently changing the request context.
        with client_factory(settings) as client:
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
    return ObjectProbeFacts(
        timestamp,
        reason,
        outcome,
        matches,
        response.status_code if response else None,
        response.headers if response else None,
        response.body if response else None,
        response.duration_seconds if response else perf_counter() - started,
        error_type,
        "Target transport failed." if error_type else None,
    )


@dataclass
class BoundedObjectBudget:
    """Attempt accounting and baseline gate shared by discovery and policy testing."""

    attempted: int = 0
    confirmed_seeds: set[int] = field(default_factory=set)

    def skip_reason(self, probe: SequentialDiscoveryProbe) -> str | None:
        if self.attempted >= MAX_PHASE22_REQUESTS:
            return "Six-request sequential-discovery budget reached."
        if probe.offset != 0 and probe.seed.index not in self.confirmed_seeds:
            return "Adjacent discovery was not performed because the seed object was not confirmed."
        return None

    def record(self, probe: SequentialDiscoveryProbe, outcome: ObjectOutcome) -> None:
        if probe.offset == 0 and outcome is ObjectOutcome.TARGET_RETURNED:
            self.confirmed_seeds.add(probe.seed.index)
