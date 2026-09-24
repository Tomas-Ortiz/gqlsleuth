"""Federation metadata and policy results; raw SDL remains only in evidence."""

import json

from gqlsleuth.domain.federation import FEDERATION_LIMITATION, FederationSecurityResult
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def federation_sections(result: FederationSecurityResult) -> tuple[ReportSection, ...]:
    entries = []
    for candidate in result.candidates:
        entries.append(
            ReportEntry(
                candidate.endpoint,
                details=(
                    ("Service available", str(candidate.service_available)),
                    ("Entities available", str(candidate.entities_available)),
                    ("Entity types", ", ".join(candidate.possible_types) or "None"),
                ),
                paragraphs=(*candidate.source.supporting_facts, *candidate.limitations),
                evidence_references=tuple(
                    ("Schema source", str(e)) for e in candidate.source.source_evidence_ids
                ),
            )
        )
        if candidate.endpoint == result.selected_endpoint:
            for plan in candidate.plans:
                if plan.probe in result.selected_probes:
                    entries.append(
                        ReportEntry(
                            "Selected " + plan.probe.value,
                            details=(("Policy", plan.expected.value.upper()),),
                            request_blocks=(
                                ("graphql", plan.query),
                                ("json", json.dumps(plan.variables, sort_keys=True, indent=2)),
                            ),
                        )
                    )
    for attempt in result.attempts:
        details = [
            ("Policy", attempt.expected.value.upper()),
            ("Outcome", attempt.outcome.value.upper()),
            (
                "Evaluation",
                attempt.evaluation.value.upper()
                if attempt.evaluation
                else "Observational; not evaluated",
            ),
            ("HTTP", str(attempt.response_status_code)),
        ]
        if attempt.sdl_returned:
            details.extend(
                (
                    ("SDL UTF-8 bytes", str(attempt.sdl_bytes)),
                    ("SDL SHA-256", str(attempt.sdl_sha256)),
                )
            )
        entries.append(
            ReportEntry(
                attempt.probe.value.title(),
                details=tuple(details),
                paragraphs=("Response material withheld at the request-context privacy boundary.",)
                if attempt.response_material_withheld
                else (),
                evidence_references=(("Attempt", str(attempt.evidence_id)),),
            )
        )
    sections = [
        ReportSection(
            "Federation Security",
            paragraphs=(FEDERATION_LIMITATION, *result.limitations),
            rows=(
                ("Selected endpoint", result.selected_endpoint or "None"),
                ("Selected probes", ", ".join(p.value for p in result.selected_probes) or "None"),
                ("Confirmed", str(result.confirmed)),
                ("Maximum requests", "2"),
                ("Attempted requests", str(len(result.attempts))),
            ),
            entries=tuple(entries),
        )
    ]
    if result.findings:
        sections.append(
            ReportSection(
                "Federation Security Findings",
                entries=tuple(
                    ReportEntry(
                        f.label,
                        details=(
                            ("Endpoint", f.endpoint),
                            ("Type", f.finding_type),
                            ("Expected", "DENY"),
                            ("Evaluation", "VIOLATED"),
                            ("Provenance", f.provenance.value),
                        ),
                        paragraphs=(f.reason, f.limitation),
                        evidence_references=(("Attempt", str(f.evidence_id)),),
                    )
                    for f in result.findings
                ),
            )
        )
    return tuple(sections)
