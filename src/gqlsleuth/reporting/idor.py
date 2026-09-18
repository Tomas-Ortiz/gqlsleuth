"""Human IDOR reports present retained policy results; they never create Findings."""

import json

from gqlsleuth.domain.idor import IDOR_NOTICE, IdorDetectionResult, expected_policy
from gqlsleuth.presentation.idor import context_description, policy_description
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def idor_sections(result: IdorDetectionResult) -> tuple[ReportSection, ...]:
    entries = []
    for probe in result.probes:
        role, expected = expected_policy(result.context_type, probe)
        execution = next((item for item in result.executions if item.probe == probe), None)
        evidence = execution.evidence if execution else None
        entries.append(
            ReportEntry(
                f"{probe.seed.operation}:{probe.seed.argument}={probe.requested_identifier}",
                details=(
                    ("Endpoint", probe.endpoint),
                    ("Seed", probe.seed.identifier),
                    ("Offset", str(probe.offset)),
                    ("Role", role),
                    ("Expected", expected.upper()),
                    ("Observed", evidence.outcome.value.upper() if evidence else "NOT_ATTEMPTED"),
                    ("Result", execution.policy_result.value.upper() if execution else "PLANNED"),
                    (
                        "HTTP status",
                        str(evidence.response_status_code) if evidence else "Not observed",
                    ),
                ),
                paragraphs=(execution.reason,) if execution else (),
                request_blocks=(
                    ("graphql", probe.query),
                    ("json", json.dumps(probe.variables, indent=2, sort_keys=True)),
                ),
                evidence_references=tuple(
                    ("Source", str(item)) for item in probe.source_evidence_ids
                )
                + ((("Attempt", str(evidence.evidence_id)),) if evidence else ()),
            )
        )
    sections = [
        ReportSection(
            "IDOR / BOLA Detection",
            paragraphs=(policy_description(result), IDOR_NOTICE, *result.limitations),
            rows=(
                ("Context", context_description(result)),
                ("Confirmed", str(result.confirmed)),
                ("Attempted requests", str(result.attempted_request_count)),
                ("Findings", str(len(result.findings))),
            ),
            entries=tuple(entries),
        )
    ]
    if result.findings:
        sections.append(
            ReportSection(
                "IDOR / BOLA Findings",
                paragraphs=(IDOR_NOTICE,),
                entries=tuple(
                    ReportEntry(
                        f"{item.operation}:{item.identifier_argument}={item.identifier}",
                        details=(
                            ("Context", context_description(result)),
                            ("Expected", "DENY"),
                            ("Observed", "TARGET_RETURNED"),
                            ("Result", "VIOLATED"),
                        ),
                        paragraphs=(item.reason,),
                        evidence_references=tuple(
                            ("Source", str(value)) for value in item.source_evidence_ids
                        ),
                    )
                    for item in result.findings
                ),
            )
        )
    return tuple(sections)
