"""One consented bounded object plan, evaluated against explicit IDOR/BOLA policy."""

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
from gqlsleuth.domain.differential import validate_context_names
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.idor import (
    IdorContextType,
    IdorDetectionResult,
    IdorExecution,
    IdorFinding,
    IdorPolicyResult,
    IdorProbeEvidence,
    evaluate_idor_policy,
    expected_policy,
)
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.object_authorization import ObjectOutcome
from gqlsleuth.domain.sequential_discovery import SequentialDiscoverySeed
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings


def prepare_idor_detection(
    safe: SafeExecutionScanResult,
    *,
    seeds: tuple[SequentialDiscoverySeed, ...],
    enabled: bool = False,
    http_settings: HttpClientSettings | None = None,
    context_label: str | None = None,
) -> IdorDetectionResult:
    """Derive context metadata from supplied settings, never from a caller's policy label."""
    validate_seeds(seeds)
    settings = http_settings or HttpClientSettings()
    if context_label is not None:
        validate_context_names((context_label,), check_count=False)
        if not settings.custom_headers:
            raise HttpConfigurationError(
                "IDOR named context requires supplied headers; omit it for anonymous testing."
            )
    context = (
        IdorContextType.AUTHENTICATED if settings.custom_headers else IdorContextType.ANONYMOUS
    )
    result = IdorDetectionResult(seeds, context, context_label)
    discovery = (
        safe.query_generation.operation_analysis.schema_scan.introspection.detection.discovery
    )
    if enabled is not True or discovery.mode is not ScanMode.ACTIVE:
        return replace(
            result, limitations=("IDOR/BOLA requires explicit enablement and ACTIVE mode.",)
        )
    probes, limitations = prepare_object_probes(safe, seeds)
    return replace(result, probes=probes, limitations=limitations)


def _matches(plan: IdorDetectionResult, fresh: IdorDetectionResult) -> bool:
    try:
        return (
            type(plan) is IdorDetectionResult
            and plan == fresh
            and plan.context_type is fresh.context_type
            and type(plan.confirmed) is bool
            and all(type(probe.offset) is int for probe in plan.probes)
            and exact_variables(tuple(probe.variables for probe in plan.probes))
            == exact_variables(tuple(probe.variables for probe in fresh.probes))
        )
    except (TypeError, ValueError, RecursionError):
        return False


class IdorSession:
    """Own a scan's bounded attempt budget; returned models cannot reset it."""

    def __init__(
        self,
        safe: SafeExecutionScanResult,
        *,
        seeds: tuple[SequentialDiscoverySeed, ...],
        enabled: bool = False,
        http_settings: HttpClientSettings | None = None,
        context_label: str | None = None,
    ) -> None:
        self._safe, self._seeds, self._enabled = safe, seeds, enabled
        self._settings = http_settings or HttpClientSettings()
        self._label = context_label
        self._budget = BoundedObjectBudget()
        self._preview = self._prepare()
        self._result = self._preview

    def _prepare(self) -> IdorDetectionResult:
        return prepare_idor_detection(
            self._safe,
            seeds=self._seeds,
            enabled=self._enabled,
            http_settings=self._settings,
            context_label=self._label,
        )

    @property
    def preview(self) -> IdorDetectionResult:
        return deepcopy(self._preview)

    def execute(
        self, *, preview: IdorDetectionResult, confirmed: bool = False
    ) -> IdorDetectionResult:
        if self._budget.attempted:
            return deepcopy(self._result)
        canonical = self._prepare()
        executions = []
        findings = []
        limitations = list(canonical.limitations)
        baselines: dict[int, IdorProbeEvidence] = {}
        schema_scan = self._safe.query_generation.operation_analysis.schema_scan
        discovery = schema_scan.introspection.detection.discovery
        for position, probe in enumerate(canonical.probes):
            fresh = self._prepare()
            reason = None
            if confirmed is not True:
                reason = "Separate IDOR/BOLA confirmation was not given."
            elif not all(_matches(plan, fresh) for plan in (preview, self._preview, canonical)):
                reason = "Prepared IDOR/BOLA requests do not match the rebuilt canonical plan."
            else:
                reason = self._budget.skip_reason(probe)
            role, expected = expected_policy(canonical.context_type, probe)
            if reason:
                executions.append(
                    IdorExecution(
                        probe,
                        role,
                        expected,
                        IdorPolicyResult.UNRESOLVED,
                        reason,
                    )
                )
                if reason not in limitations:
                    limitations.append(reason)
                continue
            # Only fresh canonical requests are sent. Failures consume the same budget.
            current = fresh.probes[position]
            self._budget.attempted += 1
            facts = request_object_probe(current, self._settings, HttpClient)
            self._budget.record(current, facts.outcome)
            policy = evaluate_idor_policy(expected, facts.outcome)
            evidence = IdorProbeEvidence(
                target=discovery.target,
                endpoint=current.endpoint,
                source="gqlsleuth.application.idor",
                context_type=canonical.context_type,
                context_label=canonical.context_label,
                root_operation=current.seed.operation,
                identifier_argument=current.seed.argument,
                operator_seed=current.seed.identifier,
                requested_identifier=current.requested_identifier,
                offset=cast(Literal[-1, 0, 1], current.offset),
                role=role,
                expected=expected,
                policy_result=policy,
                source_evidence_ids=current.source_evidence_ids,
                query=current.query,
                variables=deepcopy(current.variables),
                request_method="POST",
                **asdict(facts),
            )
            reason = facts.summary
            if policy is IdorPolicyResult.BASELINE_UNUSABLE:
                reason = (
                    "Unusable baseline: exact seed object was not returned; neighbors are skipped."
                )
            executions.append(IdorExecution(current, role, expected, policy, reason, evidence))
            if current.offset == 0 and facts.outcome is ObjectOutcome.TARGET_RETURNED:
                baselines[current.seed.index] = evidence
            if policy is IdorPolicyResult.VIOLATED:
                authenticated = canonical.context_type is IdorContextType.AUTHENTICATED
                baseline_id = baselines[current.seed.index].evidence_id if authenticated else None
                reason = (
                    "The exact alternate object was returned under the current authenticated "
                    "context, contradicting the operator-supplied DENY expectation."
                    if authenticated
                    else "The exact object was returned without supplied authentication, "
                    "contradicting "
                    "the operator-supplied DENY expectation for anonymous access."
                )
                findings.append(
                    IdorFinding(
                        current.endpoint,
                        current.seed.operation,
                        current.seed.argument,
                        current.requested_identifier,
                        canonical.context_type,
                        canonical.context_label,
                        reason,
                        evidence.evidence_id,
                        baseline_id,
                        (
                            *current.source_evidence_ids,
                            *((baseline_id,) if baseline_id else ()),
                            evidence.evidence_id,
                        ),
                    )
                )
        self._result = replace(
            canonical,
            confirmed=confirmed is True,
            executions=tuple(executions),
            findings=tuple(findings),
            limitations=tuple(limitations),
            attempted_request_count=self._budget.attempted,
        )
        return deepcopy(self._result)
