"""Explicit semantic projections of completed capabilities; never classify or serialize Evidence."""

from collections.abc import Iterable

from gqlsleuth.ai.identifiers import identifier as name
from gqlsleuth.ai.identifiers import identifier_path as path
from gqlsleuth.ai.models import (
    AICapability as Capability,
)
from gqlsleuth.ai.models import (
    AICapabilityCoverage,
    AITokenMetadata,
)
from gqlsleuth.ai.models import (
    AIFactCategory as Category,
)
from gqlsleuth.ai.models import (
    AISecurityFact as Fact,
)
from gqlsleuth.application.active_execution import ActiveExecutionScanResult
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.abuse_controls import AbuseControlResult
from gqlsleuth.domain.authentication import AuthenticationSecurityResult
from gqlsleuth.domain.authorization_policy import PolicyProvenance
from gqlsleuth.domain.federation import FederationProbe, FederationSecurityResult
from gqlsleuth.domain.file_upload import FileUploadSecurityResult
from gqlsleuth.domain.idor import IdorDetectionResult
from gqlsleuth.domain.subscriptions import SubscriptionSecurityResult


def category(evaluation: object, outcome: object = None) -> Category:
    """Arrange existing classifications into presentation tiers; no new security decision."""
    if evaluation == "violated":
        return Category.POLICY_VIOLATION
    if evaluation == "satisfied":
        return Category.POLICY_SATISFIED
    if evaluation in ("unresolved", "baseline_unusable") or outcome in (
        "indeterminate",
        "network_failure",
        "no_event_before_timeout",
    ):
        return Category.UNRESOLVED
    return Category.SECURITY_OBSERVATION


def ordered_security_context(
    safe: SafeExecutionScanResult, active: ActiveExecutionScanResult | None
) -> tuple[list[Fact], tuple[AICapabilityCoverage, ...]]:
    facts = list(_local(safe))
    facts.extend(_object_policy(safe))
    coverage = []
    review = safe.query_generation.security_review
    coverage.append(
        AICapabilityCoverage(
            capability=Capability.STRUCTURAL_REVIEW,
            state="local_only" if review and review.analyzed_endpoints else "not_present",
        )
    )
    coverage.append(
        AICapabilityCoverage(
            capability=Capability.SENSITIVE_INPUT_REVIEW,
            state="local_only"
            if safe.query_generation.operation_analysis.endpoints
            else "not_present",
        )
    )
    obj = safe.object_authorization_review
    coverage.append(
        _coverage(
            Capability.OBJECT_AUTHORIZATION,
            obj is not None,
            obj.attempted_request_count if obj else 0,
            len(obj.probes) if obj else 0,
        )
    )
    policy = safe.authorization_policy_validation
    coverage.append(
        AICapabilityCoverage(
            capability=Capability.AUTHORIZATION_POLICY,
            state="local_only" if policy else "not_enabled",
        )
    )
    if active:
        facts.extend(_bounded_queries(active))
        facts.extend(_mutation_policies(active))
        if active.idor_bola_detection:
            facts.extend(_idor(active.idor_bola_detection))
        if active.authentication_token_security:
            facts.extend(_authentication(active.authentication_token_security))
        if active.rate_limiting_abuse_controls:
            facts.extend(_abuse(active.rate_limiting_abuse_controls))
        if active.file_upload_security:
            facts.extend(_upload(active.file_upload_security))
        if active.federation_security:
            facts.extend(_federation(active.federation_security))
        if active.subscription_security:
            facts.extend(_subscriptions(active.subscription_security))
    # Explicit capability/result associations; no reflection over scanner objects.
    multiplicity = active.multiplicity if active else None
    depth = active.query_depth if active else None
    sequential = active.sequential_object_discovery if active else None
    mutation = active.mutation_authorization if active else None
    sensitive = active.sensitive_input_validation if active else None
    idor = active.idor_bola_detection if active else None
    auth = active.authentication_token_security if active else None
    abuse = active.rate_limiting_abuse_controls if active else None
    upload = active.file_upload_security if active else None
    federation = active.federation_security if active else None
    subscription = active.subscription_security if active else None
    for cap, present, attempts, planned in (
        (
            Capability.MULTIPLICITY,
            multiplicity is not None,
            len(multiplicity.evidence) if multiplicity else 0,
            len(multiplicity.selected_indices) if multiplicity else 0,
        ),
        (
            Capability.QUERY_DEPTH,
            depth is not None,
            len(depth.evidence) if depth else 0,
            len(depth.selected_indices) if depth else 0,
        ),
        (
            Capability.SEQUENTIAL_DISCOVERY,
            sequential is not None,
            sequential.attempted_request_count if sequential else 0,
            len(sequential.probes) if sequential else 0,
        ),
        (
            Capability.MUTATION_AUTHORIZATION,
            mutation is not None,
            mutation.attempted_request_count if mutation else 0,
            int(bool(mutation and mutation.probe)),
        ),
        (
            Capability.SENSITIVE_INPUT_VALIDATION,
            sensitive is not None,
            sensitive.attempted_request_count if sensitive else 0,
            int(bool(sensitive and sensitive.probe)),
        ),
        (
            Capability.IDOR_BOLA,
            idor is not None,
            idor.attempted_request_count if idor else 0,
            len(idor.probes) if idor else 0,
        ),
        (
            Capability.AUTHENTICATION,
            auth is not None,
            auth.attempted_request_count if auth else 0,
            1 + len(auth.selected_probes) if auth and auth.selected_query else 0,
        ),
        (
            Capability.ABUSE_CONTROLS,
            abuse is not None,
            abuse.attempted_request_count if abuse else 0,
            abuse.selected.planned_attempts if abuse and abuse.selected else 0,
        ),
        (
            Capability.FILE_UPLOAD,
            upload is not None,
            upload.attempted_request_count if upload else 0,
            upload.planned_request_count if upload else 0,
        ),
        (
            Capability.FEDERATION,
            federation is not None,
            federation.attempted_request_count if federation else 0,
            federation.planned_request_count if federation else 0,
        ),
        (
            Capability.SUBSCRIPTIONS,
            subscription is not None,
            len(subscription.attempts) if subscription else 0,
            int(bool(subscription and subscription.plan)),
        ),
    ):
        coverage.append(_coverage(cap, present, attempts, planned))
    # Stable sorting retains capability/result order inside a tier.
    facts.sort(key=_tier)
    facts = [f.model_copy(update={"security_fact_ref": f"SF{i}"}) for i, f in enumerate(facts, 1)]
    return facts, tuple(coverage)


def _coverage(cap: Capability, present: bool, attempts: int, planned: int) -> AICapabilityCoverage:
    return AICapabilityCoverage(
        capability=cap,
        attempts=attempts,
        state="not_enabled"
        if not present
        else "prepared"
        if not attempts
        else "partial"
        if attempts < planned
        else "executed",
    )


def _tier(fact: Fact) -> int:
    if fact.category is Category.FINDING:
        return 0
    if fact.category is Category.POLICY_VIOLATION:
        return 1
    if fact.category is Category.POLICY_SATISFIED or fact.control_observed:
        return 2
    return 4 if fact.category is Category.REVIEW_CANDIDATE else 3


def _local(safe: SafeExecutionScanResult) -> Iterable[Fact]:
    review = safe.query_generation.security_review
    for item in review.candidates if review else ():
        op = item.related_operation
        yield Fact(
            capability=Capability.STRUCTURAL_REVIEW,
            category=Category.REVIEW_CANDIDATE,
            candidate_type=item.candidate_type,
            name=name(op.name) if op else None,
            kind=op.kind.value if op else None,
            type_name=name(op.return_type.named_type) if op else None,
        )
    for sensitive in safe.query_generation.sensitive_input_review:
        yield Fact(
            capability=Capability.SENSITIVE_INPUT_REVIEW,
            category=Category.REVIEW_CANDIDATE,
            name=name(sensitive.operation),
            kind="mutation",
            argument=name(sensitive.argument),
            path=path((sensitive.argument, sensitive.field)),
            type_name=name(sensitive.input_type),
            candidate_type=sensitive.category,
        )


def _object_policy(safe: SafeExecutionScanResult) -> Iterable[Fact]:
    obj = safe.object_authorization_review
    for item in obj.executions if obj else ():
        evidence = item.evidence
        if evidence:
            yield Fact(
                capability=Capability.OBJECT_AUTHORIZATION,
                category=category(None, item.outcome),
                name=name(evidence.root_operation),
                kind="query",
                argument=name(evidence.identifier_argument),
                outcome=item.outcome,
                control_observed=item.outcome == "explicit_denial",
            )
    policy = safe.authorization_policy_validation
    for evaluation in policy.evaluations if policy else ():
        yield Fact(
            capability=Capability.AUTHORIZATION_POLICY,
            category=category(evaluation.status),
            name=name(evaluation.case.operation),
            argument=name(evaluation.case.argument),
            kind="query",
            outcome=evaluation.observed,
            expected=evaluation.assertion.expected.value,
            evaluation=evaluation.status,
            provenance=evaluation.assertion.provenance,
        )


def _bounded_queries(active: ActiveExecutionScanResult) -> Iterable[Fact]:
    multi = active.multiplicity
    for e in multi.evidence if multi else ():
        yield Fact(
            capability=Capability.MULTIPLICITY,
            category=category(None, e.observation),
            name=name(e.representative_operation),
            kind="query",
            probe=e.probe_type,
            multiplicity=e.multiplicity,
            outcome=e.observation,
            control_observed=e.observation == "rejected",
        )
    depth = active.query_depth
    for d in depth.evidence if depth else ():
        yield Fact(
            capability=Capability.QUERY_DEPTH,
            category=category(None, d.observation),
            name=name(d.representative_operation),
            kind="query",
            baseline_depth=d.baseline_depth,
            probe_depth=d.probe_depth,
            list_edges=d.list_edges,
            outcome=d.observation,
            baseline_status=d.baseline_status,
            control_observed=d.observation == "rejected",
        )
    seq = active.sequential_object_discovery
    if seq:
        yield Fact(
            capability=Capability.SEQUENTIAL_DISCOVERY,
            category=Category.SECURITY_OBSERVATION,
            seed_count=len(seq.seeds),
            attempts=seq.attempted_request_count,
            review_candidate_count=len(seq.candidates),
        )
        for item in seq.executions:
            if item.attempted:
                yield Fact(
                    capability=Capability.SEQUENTIAL_DISCOVERY,
                    category=category(None, item.outcome),
                    name=name(item.probe.seed.operation),
                    kind="query",
                    argument=name(item.probe.seed.argument),
                    outcome=item.outcome,
                    control_observed=item.outcome == "explicit_denial",
                )


def _mutation_policies(active: ActiveExecutionScanResult) -> Iterable[Fact]:
    mutation = active.mutation_authorization
    if mutation and mutation.evaluation:
        case = (
            mutation.probe.case if mutation.probe else mutation.cases[0] if mutation.cases else None
        )
        e = mutation.evaluation
        yield Fact(
            capability=Capability.MUTATION_AUTHORIZATION,
            category=category(e.status),
            name=name(case.operation) if case else None,
            kind="mutation",
            argument=name(case.argument) if case else None,
            outcome=e.observed,
            expected=e.expected.value,
            evaluation=e.status,
            provenance=PolicyProvenance.OPERATOR_SUPPLIED,
        )
    sensitive = active.sensitive_input_validation
    if sensitive and sensitive.evaluation:
        evaluation = sensitive.evaluation
        yield Fact(
            capability=Capability.SENSITIVE_INPUT_VALIDATION,
            category=category(evaluation.status),
            name=name(sensitive.case.operation),
            kind="mutation",
            argument=name(sensitive.case.argument),
            path=path((sensitive.case.argument, sensitive.case.field)),
            outcome=evaluation.observed,
            expected=evaluation.expected.value,
            evaluation=evaluation.status,
            provenance=PolicyProvenance.OPERATOR_SUPPLIED,
        )


def _idor(result: IdorDetectionResult) -> Iterable[Fact]:
    for finding in result.findings:
        yield Fact(
            capability=Capability.IDOR_BOLA,
            category=Category.FINDING,
            name=name(finding.operation),
            kind="query",
            argument=name(finding.identifier_argument),
            finding_type=finding.finding_type,
            expected=finding.expected,
            provenance=finding.provenance,
            context_mode="anonymous" if finding.context_type == "anonymous" else "supplied_context",
        )
    linked = {f.evidence_id for f in result.findings}
    for item in result.executions:
        yield Fact(
            capability=Capability.IDOR_BOLA,
            category=Category.SECURITY_OBSERVATION
            if item.evidence and item.evidence.evidence_id in linked
            else category(item.policy_result),
            kind="query",
            name=name(item.probe.seed.operation),
            argument=name(item.probe.seed.argument),
            expected=item.expected,
            evaluation=item.policy_result,
            provenance=PolicyProvenance.OPERATOR_SUPPLIED,
            context_mode="anonymous" if result.context_type == "anonymous" else "supplied_context",
            outcome=item.evidence.outcome if item.evidence else None,
        )


def _authentication(result: AuthenticationSecurityResult) -> Iterable[Fact]:
    review = result.token_review
    # Project only safe metadata; arbitrary strings fail closed at typed literals.
    token = AITokenMetadata.model_validate(
        {
            "token_type": review.token_type,
            "algorithm": review.algorithm,
            "header_presence": review.header_presence,
            "claim_presence": review.claim_presence,
            "temporal_states": review.temporal_states,
        }
    )
    yield Fact(
        capability=Capability.AUTHENTICATION, category=Category.SECURITY_OBSERVATION, token=token
    )
    linked = {f.probe_evidence_id for f in result.findings}
    for finding in result.findings:
        yield Fact(
            capability=Capability.AUTHENTICATION,
            category=Category.FINDING,
            kind="query",
            name=name(finding.operation),
            finding_type=finding.finding_type,
            provenance=finding.provenance,
            expected="deny",
        )
    for e in result.evidence:
        yield Fact(
            capability=Capability.AUTHENTICATION,
            category=Category.SECURITY_OBSERVATION
            if e.evidence_id in linked
            else category(e.policy_result),
            kind="query",
            name=name(e.operation),
            probe=e.probe_type,
            outcome=e.outcome,
            expected="deny",
            evaluation=e.policy_result,
            provenance=PolicyProvenance.OPERATOR_SUPPLIED,
            control_observed=e.outcome == "explicit_denial",
        )


def _abuse(result: AbuseControlResult) -> Iterable[Fact]:
    for f in result.findings:
        yield Fact(
            capability=Capability.ABUSE_CONTROLS,
            category=Category.FINDING,
            name=name(f.operation.name),
            kind=f.operation.kind.value,
            finding_type=f.finding_type,
            provenance=f.provenance,
            expected="control_required",
        )
    if result.selected and result.attempts:
        first = next((e.signal for e in result.attempts if e.signal), None)
        yield Fact(
            capability=Capability.ABUSE_CONTROLS,
            category=Category.SECURITY_OBSERVATION
            if result.findings
            else category(result.policy_result),
            name=name(result.selected.operation.name),
            kind=result.selected.operation.kind.value,
            baseline_status=result.selected.baseline_status,
            attempts=result.attempted_request_count,
            planned_attempts=result.selected.planned_attempts,
            evaluation=result.policy_result,
            outcome=result.attempts[-1].outcome,
            control_kind=first.kind if first else None,
            control_observed=first is not None,
            expected="control_required",
            provenance=PolicyProvenance.OPERATOR_SUPPLIED,
        )


def _upload(result: FileUploadSecurityResult) -> Iterable[Fact]:
    for f in result.findings:
        yield Fact(
            capability=Capability.FILE_UPLOAD,
            category=Category.FINDING,
            kind="mutation",
            name=name(f.case.operation),
            path=path(f.case.path),
            finding_type=f.finding_type,
            probe=f.probe,
            expected=f.expected.value,
            provenance=f.provenance,
        )
    linked = {f.variant_evidence_id for f in result.findings}
    for e in result.attempts:
        yield Fact(
            capability=Capability.FILE_UPLOAD,
            category=Category.SECURITY_OBSERVATION
            if e.evidence_id in linked
            else category(e.evaluation),
            kind="mutation",
            name=name(e.case.operation),
            path=path(e.case.path),
            probe=e.probe,
            expected=e.expected.value,
            outcome=e.outcome,
            evaluation=e.evaluation,
            baseline_status=result.baseline_status,
            provenance=PolicyProvenance.OPERATOR_SUPPLIED,
            control_observed=e.outcome == "explicit_file_rejection",
        )


def _federation(result: FederationSecurityResult) -> Iterable[Fact]:
    for f in result.findings:
        yield Fact(
            capability=Capability.FEDERATION,
            category=Category.FINDING,
            kind="query",
            finding_type=f.finding_type,
            expected=f.expected.value,
            provenance=f.provenance,
        )
    linked = {f.evidence_id for f in result.findings}
    for e in result.attempts:
        # Only the explicit case's typename/key NAMES; never inspect returned SDL or response data.
        type_name = None
        keys: tuple[str, ...] = ()
        if e.probe is FederationProbe.ENTITY:
            candidate = next((c for c in result.candidates if c.endpoint == e.endpoint), None)
            plan = (
                next((p for p in candidate.plans if p.probe is e.probe), None)
                if candidate
                else None
            )
            if plan:
                representations = plan.variables.get("representations")
                representation = (
                    representations[0]
                    if isinstance(representations, list) and representations
                    else None
                )
                if isinstance(representation, dict):
                    value = representation.get("__typename")
                    type_name = name(value) if isinstance(value, str) else None
                keys = path(tuple(key for key, _ in plan.key_types))
        yield Fact(
            capability=Capability.FEDERATION,
            category=Category.SECURITY_OBSERVATION
            if e.evidence_id in linked
            else category(e.evaluation, e.outcome),
            kind="query",
            probe=e.probe,
            type_name=type_name,
            path=keys,
            outcome=e.outcome,
            expected=e.expected.value,
            evaluation=e.evaluation,
            sdl_returned=e.sdl_returned,
            control_observed=e.outcome == "explicit_denial",
            provenance=PolicyProvenance.OPERATOR_SUPPLIED if e.expected == "deny" else None,
        )


def _subscriptions(result: SubscriptionSecurityResult) -> Iterable[Fact]:
    for f in result.findings:
        yield Fact(
            capability=Capability.SUBSCRIPTIONS,
            category=Category.FINDING,
            kind="subscription",
            name=name(f.subscription),
            finding_type=f.finding_type,
            protocol=f.protocol,
            expected=f.policy.value,
            provenance=f.provenance,
        )
    linked = {f.evidence_id for f in result.findings}
    for e in result.attempts:
        yield Fact(
            capability=Capability.SUBSCRIPTIONS,
            category=Category.SECURITY_OBSERVATION
            if e.evidence_id in linked
            else category(e.evaluation, e.outcome),
            kind="subscription",
            name=name(e.plan.candidate.field.name),
            protocol=e.negotiated_protocol,
            handshake_headers_supplied=e.plan.handshake_headers_supplied,
            init_payload_supplied=e.plan.init_payload_supplied,
            acknowledged=e.acknowledged,
            subscription_sent=e.subscription_sent,
            application_event_count=e.application_event_count,
            expected=e.plan.policy.value,
            evaluation=e.evaluation,
            outcome=e.outcome,
            control_observed=e.outcome == "explicit_denial",
            provenance=PolicyProvenance.OPERATOR_SUPPLIED if e.plan.policy == "deny" else None,
        )
