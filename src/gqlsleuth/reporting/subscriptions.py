"""Human Subscription sections: exact requests, state facts, no raw event streams."""

import json

from gqlsleuth.domain.subscriptions import SUBSCRIPTION_NOTICE, SubscriptionSecurityResult
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def subscription_sections(result: SubscriptionSecurityResult) -> tuple[ReportSection, ...]:
    entries = [
        ReportEntry(
            c.field.name,
            details=(("Endpoint", c.endpoint), ("Root", c.root), ("Return", c.field.type.render())),
            paragraphs=(*c.manual_adjustments, *((c.failure,) if c.failure else ())),
            evidence_references=tuple(
                ("Schema source", str(e)) for e in c.source.source_evidence_ids
            ),
        )
        for c in result.candidates
    ]
    if result.plan:
        plan = result.plan
        entries.append(
            ReportEntry(
                "Selected Subscription: " + plan.candidate.field.name,
                details=(
                    ("WebSocket endpoint", plan.ws_url),
                    ("Policy", plan.policy.value.upper()),
                    ("Offered protocols", ", ".join(plan.offered_protocols)),
                    ("Handshake headers supplied", str(plan.handshake_headers_supplied)),
                    ("Init payload supplied", str(plan.init_payload_supplied)),
                    ("Init payload bytes", str(plan.init_payload_bytes)),
                ),
                request_blocks=(
                    ("graphql", plan.candidate.query or ""),
                    ("json", json.dumps(plan.variables, sort_keys=True, indent=2)),
                ),
            )
        )
    for attempt in result.attempts:
        entries.append(
            ReportEntry(
                "WebSocket observation",
                details=(
                    ("Protocol", str(attempt.negotiated_protocol)),
                    ("Connected", str(attempt.connected)),
                    ("ACK", str(attempt.acknowledged)),
                    ("Subscription sent", str(attempt.subscription_sent)),
                    ("Inbound frames", str(attempt.inbound_frame_count)),
                    ("Application events", str(attempt.application_event_count)),
                    ("Outcome", attempt.outcome.value.upper()),
                    ("Close code", str(attempt.close_code)),
                    (
                        "Evaluation",
                        attempt.evaluation.value.upper()
                        if attempt.evaluation
                        else "OBSERVE; no DENY evaluation",
                    ),
                    ("Frame withheld", str(attempt.response_material_withheld)),
                ),
                paragraphs=(attempt.limitation,) if attempt.limitation else (),
                evidence_references=(("Attempt", str(attempt.evidence_id)),),
            )
        )
    sections = [
        ReportSection(
            "Subscriptions & GraphQL over WebSocket",
            paragraphs=(SUBSCRIPTION_NOTICE, *result.limitations),
            rows=(
                ("Candidate count", str(len(result.candidates))),
                ("Confirmed", str(result.confirmed)),
                ("Connection attempts", str(len(result.attempts))),
            ),
            entries=tuple(entries),
        )
    ]
    if result.findings:
        sections.append(
            ReportSection(
                "Subscription Security Findings",
                entries=tuple(
                    ReportEntry(
                        finding.label,
                        details=(
                            ("Subscription", finding.subscription),
                            ("Protocol", finding.protocol),
                            ("Policy", "DENY"),
                            ("Observed", "EVENT_RETURNED"),
                            ("Evaluation", "VIOLATED"),
                            ("Provenance", finding.provenance.value),
                        ),
                        paragraphs=(finding.reason, finding.limitation),
                        evidence_references=(("Attempt", str(finding.evidence_id)),),
                    )
                    for finding in result.findings
                ),
            )
        )
    return tuple(sections)
