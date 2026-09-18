"""Independent, confirmed ACTIVE requests for the seed and its two immediate neighbors."""

from copy import deepcopy
from dataclasses import asdict, replace
from typing import Literal, cast

from gqlsleuth.application.bounded_object import (
    BoundedObjectBudget,
    prepare_object_probes,
    request_object_probe,
    validate_seeds,
)
from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.domain.object_authorization import (
    ObjectOutcome,
)
from gqlsleuth.domain.sequential_discovery import (
    SequentialDiscoveryCandidate,
    SequentialDiscoveryEvidence,
    SequentialDiscoveryExecution,
    SequentialDiscoveryProbe,
    SequentialDiscoveryResult,
    SequentialDiscoverySeed,
)
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings


def prepare_sequential_discovery(
    safe: SafeExecutionScanResult,
    *,
    seeds: tuple[SequentialDiscoverySeed, ...],
    enabled: bool = False,
    http_settings: HttpClientSettings | None = None,
) -> SequentialDiscoveryResult:
    """Build exact requests locally. SAFE/disabled callers never derive adjacent identifiers."""
    validate_seeds(seeds)
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
    probes, limitations = prepare_object_probes(safe, seeds)
    return replace(result, probes=probes, limitations=limitations)


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
    budget = BoundedObjectBudget()
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
        else:
            reason = budget.skip_reason(probe)
        if reason:
            executions.append(SequentialDiscoveryExecution(probe, False, None, None, reason))
            if reason not in limitations:
                limitations.append(reason)
            continue
        # Send only the fresh canonical request, never a caller-mutated preview object.
        budget.attempted += 1
        evidence = _request(fresh.probes[position], settings, discovery.target)
        budget.record(probe, evidence.outcome)
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
    facts = request_object_probe(probe, settings, HttpClient)
    return SequentialDiscoveryEvidence(
        target=target,
        endpoint=probe.endpoint,
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
        **asdict(facts),
    )
