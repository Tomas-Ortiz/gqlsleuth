"""Shared human presentation of scoped authentication findings and safe token metadata."""

import json

from gqlsleuth.domain.authentication import AUTHENTICATION_NOTICE, AuthenticationSecurityResult
from gqlsleuth.presentation.authentication import PROBE_LABELS, outcome_label, token_rows
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def authentication_sections(result: AuthenticationSecurityResult) -> tuple[ReportSection, ...]:
    selected = result.selected_query
    entries = []
    if selected:
        entries.append(
            ReportEntry(
                "Selected Query: " + selected.operation,
                details=(("Endpoint", selected.endpoint), ("Existing baseline", "SUCCESS")),
                request_blocks=(
                    ("graphql", selected.query),
                    ("json", json.dumps(selected.variables, indent=2, sort_keys=True)),
                ),
                evidence_references=(("Phase 9 baseline", str(selected.baseline_evidence_id)),),
            )
        )
    for execution in result.executions:
        evidence = execution.evidence
        entries.append(
            ReportEntry(
                PROBE_LABELS[execution.probe_type],
                details=(
                    ("Observed", outcome_label(evidence.outcome) if evidence else "NOT_ATTEMPTED"),
                    (
                        "Policy",
                        evidence.policy_result.value.upper() if evidence else "NOT_EVALUATED",
                    ),
                    ("HTTP", str(evidence.response_status_code) if evidence else "Not observed"),
                ),
                paragraphs=(execution.reason,)
                + (
                    ("Response material withheld at the token privacy boundary.",)
                    if evidence and evidence.response_material_withheld
                    else ()
                ),
                evidence_references=(("Attempt", str(evidence.evidence_id)),) if evidence else (),
            )
        )
    sections = [
        ReportSection(
            "Authentication & Token Security",
            paragraphs=(
                AUTHENTICATION_NOTICE,
                *result.token_review.observations,
                *result.limitations,
            ),
            rows=token_rows(result.token_review)
            + (
                ("Confirmed", str(result.confirmed)),
                ("Attempted requests", str(result.attempted_request_count)),
                (
                    "Selected JWT probes",
                    ", ".join(PROBE_LABELS[p] for p in result.selected_probes) or "none",
                ),
            ),
            entries=tuple(entries),
        )
    ]
    if result.findings:
        sections.append(
            ReportSection(
                "Authentication & Token Findings",
                paragraphs=(AUTHENTICATION_NOTICE,),
                entries=tuple(
                    ReportEntry(
                        item.finding_type.value.upper(),
                        details=(
                            ("Endpoint", item.endpoint),
                            ("Query", item.operation),
                            ("Condition", item.condition),
                            ("Policy provenance", item.provenance.value),
                        ),
                        paragraphs=(item.reason, item.limitation),
                        evidence_references=(
                            ("Baseline", str(item.baseline_evidence_id)),
                            ("Control", str(item.control_evidence_id)),
                            ("Probe", str(item.probe_evidence_id)),
                        ),
                    )
                    for item in result.findings
                ),
            )
        )
    return tuple(sections)
