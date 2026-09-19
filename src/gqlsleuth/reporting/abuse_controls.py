"""Shared Markdown/HTML abuse-control sections built only from retained results."""

import json

from gqlsleuth.domain.abuse_controls import AbuseControlResult
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def abuse_control_sections(result: AbuseControlResult) -> tuple[ReportSection, ...]:
    entries = []
    for candidate in result.candidates:
        selected = result.selected == candidate
        entries.append(
            ReportEntry(
                f"{candidate.operation.kind.value} {candidate.operation.name}",
                details=(
                    ("Endpoint", candidate.endpoint),
                    ("Selected", str(selected)),
                    (
                        "Review priority",
                        candidate.operation.priority.value.replace("_", " ").upper(),
                    ),
                    ("Categories", ", ".join(c.value for c in candidate.operation.categories)),
                    (
                        "Baseline",
                        f"{candidate.baseline_status.value.upper()} / "
                        f"HTTP {candidate.baseline_http_status}",
                    ),
                    ("Planned repeats", str(candidate.planned_attempts)),
                ),
                paragraphs=(candidate.mutation_warning,) if candidate.mutation_warning else (),
                request_blocks=(
                    ("graphql", candidate.query),
                    ("json", json.dumps(candidate.variables, sort_keys=True, indent=2)),
                )
                if selected
                else (),
                evidence_references=(("Baseline", str(candidate.baseline_evidence_id)),),
            )
        )
    for attempt in result.attempts:
        entries.append(
            ReportEntry(
                f"Attempt {attempt.attempt_index}",
                details=(
                    ("Outcome", attempt.outcome.value.upper()),
                    ("Execution status", attempt.repeat_status.value.upper()),
                    (
                        "HTTP",
                        str(attempt.response_status_code)
                        if attempt.response_status_code
                        else "Not observed",
                    ),
                    (
                        "Signal",
                        attempt.signal.kind.value.upper() if attempt.signal else "None observed",
                    ),
                ),
                paragraphs=(
                    (f"{attempt.signal.source}: {attempt.signal.matched_rule}",)
                    if attempt.signal
                    else ()
                )
                + (
                    ("Response material withheld at the request-credential capture boundary.",)
                    if attempt.response_material_withheld
                    else ()
                ),
                evidence_references=(
                    ("Attempt", str(attempt.evidence_id)),
                    ("Policy", str(attempt.policy_id)),
                ),
            )
        )
    sections = [
        ReportSection(
            "Rate Limiting & Abuse Controls",
            paragraphs=(result.operator_policy, result.scope_limitation, *result.limitations),
            rows=(
                ("Confirmed", str(result.confirmed)),
                (
                    "Planned repeats",
                    str(result.selected.planned_attempts if result.selected else 0),
                ),
                ("Attempted requests", str(result.attempted_request_count)),
                ("Policy result", result.policy_result.value.upper()),
                (
                    "First signal attempt",
                    str(result.first_signal_attempt)
                    if result.first_signal_attempt
                    else "None observed",
                ),
            ),
            entries=tuple(entries),
        )
    ]
    if result.findings:
        sections.append(
            ReportSection(
                "Rate Limiting / Abuse-Control Findings",
                entries=tuple(
                    ReportEntry(
                        "Rate limiting / abuse-control weakness",
                        details=(
                            ("Operation", f"{item.operation.kind.value} {item.operation.name}"),
                            (
                                "Planned / completed",
                                f"{item.planned_attempts} / {item.actual_attempts}",
                            ),
                            ("Policy result", item.policy_result.value.upper()),
                            ("Provenance", item.provenance.value),
                        ),
                        paragraphs=(item.reason, item.limitation),
                        evidence_references=(
                            ("Baseline", str(item.baseline_evidence_id)),
                            ("Policy", str(item.policy_id)),
                        )
                        + tuple(("Attempt", str(value)) for value in item.attempt_evidence_ids),
                    )
                    for item in result.findings
                ),
            )
        )
    return tuple(sections)
