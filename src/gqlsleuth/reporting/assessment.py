"""Human-only assessment hierarchy. Canonical report models/JSON stay untouched."""

from gqlsleuth.presentation.assessment import build_assessment
from gqlsleuth.reporting.models import ReportContext
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection, technical_sections

TECHNICAL_GROUPS = (
    (
        "Discovery & Schema",
        (
            "Scan Overview",
            "Executive Scan Summary",
            "GraphQL Discovery and Confirmation",
            "Introspection",
            "Schema Summary",
        ),
    ),
    (
        "Attack Surface",
        (
            "Security Review Candidates",
            "GraphQL Security Review",
            "Sensitive Input Review",
            "Generated Queries",
        ),
    ),
    ("Operations & Execution", ("Safe Query Execution", "Active Mutation Analysis")),
    (
        "Authentication & Authorization",
        (
            "Controlled Object Authorization Validation",
            "Authorization Policy Validation",
            "Bounded Sequential Object Discovery",
            "Mutation Authorization Validation",
            "Sensitive Input Validation",
            "IDOR / BOLA Detection",
            "IDOR / BOLA Findings",
            "Authentication & Token Security",
            "Authentication & Token Findings",
        ),
    ),
    (
        "GraphQL Runtime Controls",
        (
            "Controlled GraphQL Multiplicity Validation",
            "Controlled Query Depth Validation",
            "Rate Limiting & Abuse Controls",
            "Rate Limiting / Abuse-Control Findings",
        ),
    ),
    (
        "Specialized Surfaces",
        (
            "File Upload Security",
            "File Upload Findings",
            "Federation Security",
            "Federation Security Findings",
            "Subscriptions & GraphQL over WebSocket",
            "Subscription Security Findings",
        ),
    ),
)


def grouped_technical_sections(sections: tuple[ReportSection, ...]) -> tuple[ReportSection, ...]:
    groups = []
    assigned: set[str] = set()
    for name, titles in TECHNICAL_GROUPS:
        children = tuple(s for s in sections if s.title in titles)
        if children:
            groups.append(ReportSection(name, children=children, collapsed=True))
            assigned.update(s.title for s in children)
    remaining = tuple(
        s
        for s in sections
        if s.title not in assigned
        and s.title
        not in {
            "Safety Notice",
            "AI-Assisted Interpretation",
        }
    )
    if remaining:
        groups.append(
            ReportSection("Evidence / Errors / Limitations", children=remaining, collapsed=True)
        )
    return tuple(groups)


def assessment_sections(report: ReportContext) -> tuple[ReportSection, ...]:
    summary = build_assessment(report)
    technical = technical_sections(report)
    sections = [
        ReportSection(
            "Assessment Summary",
            rows=(
                ("Target", summary.target),
                ("Mode", summary.mode),
                *summary.validation_rows,
            ),
        ),
        ReportSection("GraphQL Attack Surface", rows=summary.overview),
    ]
    if summary.findings:
        sections.append(
            ReportSection(
                "Security Findings",
                entries=tuple(
                    ReportEntry(
                        f.label + " / " + f.operation,
                        details=(("Capability", f.capability), *f.details),
                        paragraphs=f.paragraphs,
                    )
                    for f in summary.findings
                ),
            )
        )
    if summary.capabilities:
        sections.append(
            ReportSection(
                "Security Validation Overview",
                paragraphs=(
                    "Controls and policy results apply only to the exact tested cases; "
                    "they are not global security conclusions.",
                ),
                table_headers=("Capability", "Result"),
                table_rows=summary.capabilities,
            )
        )
    if summary.manual_review:
        sections.append(
            ReportSection(
                "Manual Review",
                paragraphs=(
                    "Review interest and structural candidates are not vulnerability "
                    "severity or Findings.",
                ),
                table_headers=("Kind", "Capability", "Operation", "Review"),
                table_rows=tuple(
                    (i.state, i.capability, i.operation, i.label) for i in summary.manual_review
                ),
            )
        )
    sections.extend(s for s in technical if s.title == "AI-Assisted Interpretation")
    sections.append(
        ReportSection("Detailed Technical Results", children=grouped_technical_sections(technical))
    )
    sections.extend(s for s in technical if s.title == "Safety Notice")
    return tuple(sections)
