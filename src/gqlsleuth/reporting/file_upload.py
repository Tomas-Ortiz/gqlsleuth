"""Shared human upload sections with safe metadata and evidence-linked policy decisions."""

import json

from gqlsleuth.domain.file_upload import UPLOAD_LIMITATION, UPLOAD_WARNING, FileUploadSecurityResult
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def file_upload_sections(result: FileUploadSecurityResult) -> tuple[ReportSection, ...]:
    entries = []
    if result.plan:
        plan = result.plan
        entries.append(
            ReportEntry(
                "Selected upload Mutation",
                details=(
                    ("Operation", plan.operation.name),
                    ("Endpoint", plan.operation.endpoint),
                    ("Upload path", ".".join(plan.case.path)),
                    ("Baseline expected", "ALLOW"),
                    ("Filename", plan.baseline.filename),
                    ("MIME", plan.baseline.content_type),
                    ("Bytes", str(plan.baseline.size)),
                    ("SHA-256", plan.baseline.sha256),
                    (
                        "Selected DENY variants",
                        ", ".join(p.value for p in result.selected_variants) or "None",
                    ),
                ),
                paragraphs=(UPLOAD_WARNING, *plan.manual_adjustments),
                request_blocks=(
                    ("graphql", plan.query),
                    ("json", json.dumps(plan.operations, sort_keys=True, indent=2)),
                    ("json", json.dumps(plan.multipart_map, sort_keys=True, indent=2)),
                ),
                evidence_references=tuple(
                    ("Schema source", str(e)) for e in plan.source_evidence_ids
                ),
            )
        )
    for attempt in result.attempts:
        entries.append(
            ReportEntry(
                attempt.probe.value.replace("_", " ").title(),
                details=(
                    ("Expected", attempt.expected.value.upper()),
                    ("Outcome", attempt.outcome.value.upper()),
                    ("Evaluation", attempt.evaluation.value.upper()),
                    ("HTTP", str(attempt.response_status_code)),
                    ("Filename", attempt.file.filename),
                    ("MIME", attempt.file.content_type),
                    ("Bytes", str(attempt.file.size)),
                    ("SHA-256", attempt.file.sha256),
                ),
                paragraphs=("Response material withheld at the upload privacy boundary.",)
                if attempt.response_material_withheld
                else (),
                evidence_references=(("Attempt", str(attempt.evidence_id)),),
            )
        )
    sections = [
        ReportSection(
            "File Upload Security",
            paragraphs=(UPLOAD_LIMITATION, *result.limitations),
            rows=(
                ("Confirmed", str(result.confirmed)),
                ("Baseline", result.baseline_status.value.upper()),
                ("Planned requests", str(result.planned_request_count)),
                ("Attempted requests", str(result.attempted_request_count)),
            ),
            entries=tuple(entries),
        )
    ]
    if result.findings:
        sections.append(
            ReportSection(
                "File Upload Findings",
                entries=tuple(
                    ReportEntry(
                        "File upload validation weakness",
                        paragraphs=(f.reason, f.limitation),
                        details=(
                            ("Operation", f.operation.name),
                            ("Upload path", ".".join(f.case.path)),
                            ("Probe", f.probe.value),
                            ("Expected", "DENY"),
                            ("Observed", "UPLOAD_ACCEPTED"),
                            ("Evaluation", "VIOLATED"),
                            ("Provenance", f.provenance.value),
                        ),
                        evidence_references=(
                            ("Baseline", str(f.baseline_evidence_id)),
                            ("Variant", str(f.variant_evidence_id)),
                        ),
                    )
                    for f in result.findings
                ),
            )
        )
    return tuple(sections)
