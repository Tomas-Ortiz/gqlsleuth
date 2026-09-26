"""Pure assessment projection of retained report facts, never a security evaluator."""

from collections import Counter
from dataclasses import dataclass
from typing import Literal

from gqlsleuth.domain.analysis import InterestPriority
from gqlsleuth.domain.models import ConfidenceLevel
from gqlsleuth.presentation.capabilities import capability_wording
from gqlsleuth.presentation.security_review import candidate_label, candidate_summary
from gqlsleuth.reporting.models import ReportContext

DEFAULT_MAX_FINDINGS = 10
DEFAULT_MAX_MANUAL_REVIEW_ITEMS = 8
DEFAULT_MAX_LIMITATIONS = 5
DEFAULT_MAX_AI_INSIGHTS = 3

CAPABILITY_ORDER = (
    "Authentication & Tokens",
    "Object Authorization",
    "IDOR / BOLA",
    "Mutation Authorization",
    "Sensitive Inputs",
    "Rate Limiting & Abuse Controls",
    "File Upload Security",
    "Federation Security",
    "Subscriptions & WebSocket",
    "Query Multiplicity",
    "Query Depth",
    "Sequential Object Discovery",
)
PresentationState = Literal[
    "FINDING", "VIOLATION", "CONTROL", "OBSERVED", "UNRESOLVED", "REVIEW", "NOT_RUN"
]
_STATE_ORDER = ("FINDING", "VIOLATION", "CONTROL", "UNRESOLVED", "OBSERVED", "REVIEW", "NOT_RUN")


@dataclass(frozen=True)
class AssessmentItem:
    capability: str
    operation: str
    state: PresentationState
    label: str
    endpoint: str = ""
    details: tuple[tuple[str, str], ...] = ()
    paragraphs: tuple[str, ...] = ()
    attempted: bool = False


@dataclass(frozen=True)
class AssessmentPresentationSummary:
    target: str
    mode: str
    overview: tuple[tuple[str, str], ...]
    findings: tuple[AssessmentItem, ...]
    additional_policy_violations: int
    scoped_controls_observed: int
    unresolved_checks: int
    review_candidate_count: int
    capabilities: tuple[tuple[str, str], ...]
    manual_review: tuple[AssessmentItem, ...]
    query_outcomes: tuple[tuple[str, int], ...]
    mutations: tuple[tuple[str, str], ...]
    limitations: tuple[str, ...]

    @property
    def validation_rows(self) -> tuple[tuple[str, str], ...]:
        return (
            ("Findings", str(len(self.findings))),
            ("Additional policy violations", str(self.additional_policy_violations)),
            ("Scoped controls observed", str(self.scoped_controls_observed)),
            ("Unresolved checks", str(self.unresolved_checks)),
            ("Manual review candidates", str(self.review_candidate_count)),
        )


def build_assessment(report: ReportContext) -> AssessmentPresentationSummary:
    """Group existing enums/objects, without reading bodies or recomputing any policy."""
    findings = _findings(report)
    events = _validation_items(report)
    represented = {(i.endpoint, i.operation) for i in (*findings, *events)}
    surfaces = []
    review = report.graphql_security_review
    for candidate in review.candidates if review else ():
        op = candidate.related_operation
        operation = f"{op.kind.value} {op.name}" if op else candidate.subject
        surfaces.append(
            AssessmentItem(
                "Attack Surface",
                operation,
                "REVIEW",
                candidate_label(candidate.candidate_type),
                candidate.endpoint,
                paragraphs=(candidate_summary(candidate),),
            )
        )
        represented.add((candidate.endpoint, operation))
    for sensitive in report.sensitive_input_review or ():
        operation = "mutation " + sensitive.operation
        surfaces.append(
            AssessmentItem(
                "Sensitive Inputs",
                operation,
                "REVIEW",
                f"{sensitive.category.value.replace('_', ' ')}: "
                f"{sensitive.argument}.{sensitive.field}",
                sensitive.endpoint,
            )
        )
        represented.add((sensitive.endpoint, operation))
    ordinary = tuple(
        AssessmentItem(
            "Operations",
            f"{op.kind.value} {op.name}",
            "REVIEW",
            op.priority.value.split("_")[0].upper() + " review interest",
            op.endpoint,
        )
        for op in report.review_candidates
        if op.priority in (InterestPriority.CRITICAL_INTEREST, InterestPriority.HIGH_INTEREST)
        and (op.endpoint, f"{op.kind.value} {op.name}") not in represented
    )
    manual = (
        tuple(e for e in events if e.state == "VIOLATION")
        + tuple(e for e in events if e.state == "UNRESOLVED" and e.attempted)
        + tuple(surfaces)
        + ordinary
    )
    capability_rows = []
    for capability in CAPABILITY_ORDER:
        states = {e.state for e in (*findings, *events, *surfaces) if e.capability == capability}
        if states:
            capability_rows.append((capability, "; ".join(s for s in _STATE_ORDER if s in states)))
    meaningful = tuple(
        e
        for e in report.endpoints
        if e.confidence
        in (
            ConfidenceLevel.CONFIRMED,
            ConfidenceLevel.PROBABLE,
        )
    )
    introspection = Counter(e.introspection_status or "not_attempted" for e in meaningful)
    schemas = tuple(e.schema_summary for e in report.endpoints if e.schema_summary)
    overview: tuple[tuple[str, str], ...] = (
        ("GraphQL endpoints", str(len(meaningful)) + " confirmed / probable"),
        (
            "Introspection",
            "; ".join(f"{k.upper()}: {v}" for k, v in introspection.items()) or "Not available",
        ),
        ("Queries", str(sum(s.query_field_count for s in schemas))),
        ("Mutations", str(sum(s.mutation_field_count for s in schemas))),
        ("Subscriptions", str(sum(s.subscription_field_count for s in schemas))),
    )
    for surface, label in (
        ("federation_surface", "Federation"),
        ("file_upload_surface", "Upload surface"),
    ):
        if review and any(c.candidate_type.value == surface for c in review.candidates):
            overview += ((label, "Detected"),)
    queries = Counter(q.execution.status for q in report.queries if q.execution)
    mutations = (
        tuple(
            (m.generated.operation_name, (m.execution.status or "not_recorded").upper())
            for m in report.active.candidates
            if m.execution and m.execution.attempted
        )
        if report.active
        else ()
    )
    limitations = []
    if not meaningful:
        limitations.append("No confirmed or probable GraphQL endpoint was retained.")
    if meaningful and any(e.introspection_status != "enabled" for e in meaningful):
        limitations.append("Introspection was unavailable for at least one GraphQL endpoint.")
    if not schemas:
        limitations.append("No parsed schema was available; operation coverage is limited.")
    transport_messages = {
        "HttpTransportError": (
            "A target connection failed. "
            "Check the URL, network reachability, proxy and TLS settings."
        ),
        "HttpTimeoutError": (
            "A target request timed out. Check network reachability and the target timeout setting."
        ),
        "HttpProxyError": (
            "A target proxy request failed. Check the proxy configuration and reachability."
        ),
        "HttpRedirectError": (
            "A target request exceeded the redirect limit. Check the target URL and redirects."
        ),
    }
    for issue in report.errors_and_limitations:
        # Group normalized codes only. Raw target error prose stays in technical details.
        if issue.code in {"skipped_safety", "not_selected", "blocked_safety"}:
            continue
        if issue.code in transport_messages:
            limitations.append(transport_messages[issue.code])
            continue
        limitations.append(
            f"{capability_wording(issue.stage)}: {issue.code.replace('_', ' ').upper()}."
        )
    if any(e.state == "UNRESOLVED" for e in events):
        limitations.append(
            "Some security checks remain unresolved; see Manual Review and technical details."
        )
    for result in (
        report.multiplicity,
        report.query_depth,
        report.sequential_object_discovery,
        report.mutation_authorization,
        report.sensitive_input_validation,
        report.idor_bola_detection,
        report.authentication_token_security,
        report.rate_limiting_abuse_controls,
        report.file_upload_security,
        report.federation_security,
        report.subscription_security,
    ):
        if result is not None and result.limitations:
            limitations.append(
                "Capability scope/coverage limitations are retained in technical details."
            )
    if report.ai_interpretation and report.ai_interpretation.context_metadata.context_truncated:
        limitations.append("AI context was truncated; interpretation covers only supplied facts.")
    return AssessmentPresentationSummary(
        report.target.original_url,
        report.mode.value.upper(),
        overview,
        findings,
        sum(e.state == "VIOLATION" for e in events),
        sum(e.state == "CONTROL" for e in events),
        sum(e.state == "UNRESOLVED" for e in events),
        len(surfaces) + len(ordinary),
        tuple(capability_rows),
        manual,
        tuple((str(status).upper(), count) for status, count in queries.items()),
        mutations,
        tuple(dict.fromkeys(limitations)),
    )


def _findings(report: ReportContext) -> tuple[AssessmentItem, ...]:
    items = []

    def add(
        cap: str,
        operation: str,
        label: str,
        endpoint: str,
        expected: str,
        observed: str,
        provenance: str,
        reason: str,
        limitation: str,
    ) -> None:
        items.append(
            AssessmentItem(
                cap,
                operation,
                "FINDING",
                label,
                endpoint,
                (
                    ("Endpoint", endpoint),
                    ("Expected", expected.upper()),
                    ("Observed", observed.upper()),
                    ("Policy provenance", provenance),
                ),
                (capability_wording(reason), capability_wording(limitation)),
                True,
            )
        )

    auth = report.authentication_token_security
    for f in auth.findings if auth else ():
        add(
            "Authentication & Tokens",
            "query " + f.operation,
            f.finding_type.value.replace("_", " ").capitalize(),
            f.endpoint,
            "deny",
            f.condition,
            f.provenance.value,
            f.reason,
            f.limitation,
        )
    idor = report.idor_bola_detection
    for i in idor.findings if idor else ():
        add(
            "IDOR / BOLA",
            "query " + i.operation,
            i.classification,
            i.endpoint,
            i.expected,
            i.observed.value,
            i.provenance.value,
            i.reason,
            i.limitation,
        )
    upload = report.file_upload_security
    for u in upload.findings if upload else ():
        add(
            "File Upload Security",
            "mutation " + u.case.operation,
            "File upload validation weakness / " + u.probe.value,
            u.operation.endpoint,
            u.expected.value,
            u.observed.value,
            u.provenance.value,
            u.reason,
            u.limitation,
        )
    abuse = report.rate_limiting_abuse_controls
    for a in abuse.findings if abuse else ():
        add(
            "Rate Limiting & Abuse Controls",
            f"{a.operation.kind.value} {a.operation.name}",
            "Rate limiting / abuse-control weakness",
            a.operation.endpoint,
            a.operator_policy,
            a.policy_result.value,
            a.provenance.value,
            a.reason,
            a.limitation,
        )
    federation = report.federation_security
    for fe in federation.findings if federation else ():
        add(
            "Federation Security",
            "query _service" if "SDL" in fe.finding_type else "query _entities",
            fe.label,
            fe.endpoint,
            fe.expected.value,
            fe.evaluation.value,
            fe.provenance.value,
            fe.reason,
            fe.limitation,
        )
    subscriptions = report.subscription_security
    for su in subscriptions.findings if subscriptions else ():
        add(
            "Subscriptions & WebSocket",
            "subscription " + su.subscription,
            su.label,
            su.endpoint,
            su.policy.value,
            su.outcome.value,
            su.provenance.value,
            su.reason,
            su.limitation,
        )
    return tuple(items)


def _validation_items(report: ReportContext) -> tuple[AssessmentItem, ...]:
    items: list[AssessmentItem] = []
    endpoints = tuple(e.endpoint for e in report.endpoints if e.schema_summary)

    def add(
        cap: str,
        operation: str,
        outcome: str | None,
        policy: str | None = None,
        *,
        linked: bool = False,
        attempted: bool = True,
        endpoint: str = "",
    ) -> None:
        if linked and policy == "violated":
            return  # The existing Finding represents this exact policy event.
        state: PresentationState = "OBSERVED"
        if policy == "violated":
            state = "VIOLATION"
        elif policy in {"unresolved", "baseline_unusable"}:
            state = "UNRESOLVED"
        elif policy == "satisfied" or outcome in {
            "explicit_denial",
            "rejected",
            "explicit_file_rejection",
            "control_signal_observed",
        }:
            state = "CONTROL"
        elif outcome in {
            "indeterminate",
            "network_failure",
            "no_event_before_timeout",
        }:
            state = "UNRESOLVED"
        elif not attempted:
            state = "NOT_RUN"
        label = (
            "Contradicted operator-supplied policy"
            if state == "VIOLATION"
            else (
                "Scoped control for tested case"
                if state == "CONTROL"
                else (outcome or policy or "not executed").replace("_", " ")
            )
        )
        if not endpoint and len(endpoints) == 1:
            endpoint = endpoints[0]
        items.append(AssessmentItem(cap, operation, state, label, endpoint, attempted=attempted))

    policies = report.authorization_policy_validation
    covered = (
        {ref for p in policies.evaluations for ref in p.source_evidence_ids} if policies else set()
    )
    obj = report.object_authorization_review
    for o in obj.executions if obj else ():
        if o.evidence and o.evidence.evidence_id in covered:
            continue
        case = next((c for c in obj.cases if c.index == o.case_index), None) if obj else None
        add(
            "Object Authorization",
            "query " + case.operation if case else "Object case",
            o.outcome,
            attempted=o.attempted,
            endpoint=(o.evidence.endpoint or "") if o.evidence else "",
        )
    for p in policies.evaluations if policies else ():
        add(
            "Object Authorization",
            "query " + p.case.operation,
            p.observed,
            p.status,
            attempted=bool(p.source_evidence_ids),
        )
    mutation = report.mutation_authorization
    if mutation and mutation.evaluation:
        add(
            "Mutation Authorization",
            "mutation " + mutation.cases[0].operation if mutation.cases else "Mutation case",
            mutation.evaluation.observed,
            mutation.evaluation.status,
            attempted=bool(mutation.attempted_request_count),
        )
    sensitive = report.sensitive_input_validation
    if sensitive and sensitive.evaluation:
        add(
            "Sensitive Inputs",
            "mutation " + sensitive.case.operation,
            sensitive.evaluation.observed,
            sensitive.evaluation.status,
            attempted=bool(sensitive.attempted_request_count),
        )
    idor = report.idor_bola_detection
    linked = {f.evidence_id for f in idor.findings} if idor else set()
    for i in idor.executions if idor else ():
        add(
            "IDOR / BOLA",
            "query " + i.probe.seed.operation,
            i.evidence.outcome if i.evidence else None,
            i.policy_result,
            linked=bool(i.evidence and i.evidence.evidence_id in linked),
            attempted=i.attempted,
        )
    auth = report.authentication_token_security
    linked = {f.probe_evidence_id for f in auth.findings} if auth else set()
    for a in auth.executions if auth else ():
        e = a.evidence
        add(
            "Authentication & Tokens",
            "query " + e.operation if e else "Selected Query",
            e.outcome if e else None,
            e.policy_result if e else None,
            linked=bool(e and e.evidence_id in linked),
            attempted=e is not None,
        )
    abuse = report.rate_limiting_abuse_controls
    if abuse and abuse.selected:
        add(
            "Rate Limiting & Abuse Controls",
            f"{abuse.selected.operation.kind.value} {abuse.selected.operation.name}",
            abuse.attempts[-1].outcome if abuse.attempts else None,
            abuse.policy_result if abuse.attempts else None,
            linked=bool(abuse.findings),
            attempted=bool(abuse.attempts),
        )
    upload = report.file_upload_security
    linked = {f.variant_evidence_id for f in upload.findings} if upload else set()
    for u in upload.attempts if upload else ():
        add(
            "File Upload Security",
            "mutation " + u.case.operation,
            u.outcome,
            u.evaluation,
            linked=u.evidence_id in linked,
        )
    federation = report.federation_security
    linked = {f.evidence_id for f in federation.findings} if federation else set()
    for fe in federation.attempts if federation else ():
        add(
            "Federation Security",
            "query _service" if fe.probe.value == "service" else "query _entities",
            fe.outcome,
            fe.evaluation,
            linked=fe.evidence_id in linked,
        )
    subscriptions = report.subscription_security
    linked = {f.evidence_id for f in subscriptions.findings} if subscriptions else set()
    for su in subscriptions.attempts if subscriptions else ():
        add(
            "Subscriptions & WebSocket",
            "subscription " + su.plan.candidate.field.name,
            su.outcome,
            su.evaluation,
            linked=su.evidence_id in linked,
        )
    for result, cap in (
        (report.multiplicity, "Query Multiplicity"),
        (report.query_depth, "Query Depth"),
    ):
        for ex in result.executions if result else ():
            add(
                cap,
                "query " + ex.candidate.base.operation_name,
                ex.evidence.observation if ex.evidence else None,
                attempted=ex.evidence is not None,
            )
    seq = report.sequential_object_discovery
    for se in seq.executions if seq else ():
        add(
            "Sequential Object Discovery",
            "query " + se.probe.seed.operation,
            se.outcome,
            attempted=se.attempted,
        )
    return tuple(items)
