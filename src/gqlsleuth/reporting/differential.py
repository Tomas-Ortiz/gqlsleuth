"""Deterministic differential reports; HTTP configuration is never report input."""

from copy import deepcopy
from datetime import UTC, datetime

from gqlsleuth import __version__
from gqlsleuth.application.differential_review import DifferentialScanResult
from gqlsleuth.domain.differential import DIFFERENTIAL_NOTICE
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.presentation.differential import present_differential
from gqlsleuth.reporting.builder import SAFETY_NOTICE, build_report
from gqlsleuth.reporting.models import DifferentialReportContext, NamedContextReport
from gqlsleuth.reporting.nested_authorization import nested_authorization_section
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection, security_review_section


def build_differential_report(
    result: DifferentialScanResult, *, generated_at: datetime | None = None
) -> DifferentialReportContext:
    timestamp = generated_at or datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    timestamp = timestamp.astimezone(UTC)
    return DifferentialReportContext(
        1,
        __version__,
        timestamp,
        result.target,
        ScanMode.SAFE,
        tuple(
            NamedContextReport(
                item.name,
                build_report(item.scan, generated_at=timestamp) if item.scan else None,
                item.error_code,
            )
            for item in result.contexts
        ),
        deepcopy(result.pairs),
        SAFETY_NOTICE,
        deepcopy(result.nested_authorization_review),
        deepcopy(result.object_authorization_review),
        deepcopy(result.authorization_policy_validation),
    )


def differential_sections(report: DifferentialReportContext) -> tuple[ReportSection, ...]:
    """Human differential reports use structural facts, not response bodies or raw errors."""
    candidates = present_differential(report.pairs)
    sections = [
        ReportSection(
            "Scan Overview",
            rows=(
                ("Target", report.target.original_url),
                ("Mode", "SAFE"),
                ("Report timestamp (UTC)", report.generated_at.isoformat()),
                ("GQLSleuth version", report.gqlsleuth_version),
            ),
        ),
        ReportSection(
            "Authorization Differential Review",
            paragraphs=(DIFFERENTIAL_NOTICE,),
            rows=(
                (("Target endpoint", candidates.endpoints[0]),)
                if len(candidates.endpoints) == 1
                else ()
            )
            + (
                ("Contexts", ", ".join(item.name for item in report.contexts)),
                ("Pairs compared", str(len(report.pairs))),
                ("Review candidates", str(sum(len(pair.candidates) for pair in report.pairs))),
            ),
            table_headers=candidates.headers,
            table_rows=candidates.rows,
        ),
    ]
    for context in report.contexts:
        scan = context.scan
        entries = []
        if scan:
            for endpoint in scan.endpoints:
                entries.append(
                    ReportEntry(
                        endpoint.endpoint,
                        details=(
                            (
                                "GraphQL confidence",
                                endpoint.confidence.value.upper()
                                if endpoint.confidence
                                else "Not observed",
                            ),
                            (
                                "Introspection",
                                endpoint.introspection_status.upper()
                                if endpoint.introspection_status
                                else "Not observed",
                            ),
                            (
                                "Query fields",
                                str(endpoint.schema_summary.query_field_count)
                                if endpoint.schema_summary
                                else "Not observed",
                            ),
                            (
                                "Mutation fields (schema only)",
                                str(endpoint.schema_summary.mutation_field_count)
                                if endpoint.schema_summary
                                else "Not observed",
                            ),
                        ),
                    )
                )
            for query in scan.queries:
                execution = query.execution
                entries.append(
                    ReportEntry(
                        f"Query {query.generated.operation_name}",
                        details=(
                            ("Endpoint", query.generated.endpoint),
                            ("Review interest", query.generated.operation.priority.value.upper()),
                            (
                                "Execution status",
                                execution.status.upper()
                                if execution and execution.status
                                else "No execution result",
                            ),
                            (
                                "Attempted (execution evidence)",
                                "Yes" if execution and execution.attempted else "No",
                            ),
                            (
                                "HTTP status",
                                str(execution.response.status_code)
                                if execution and execution.response
                                else "No response",
                            ),
                        ),
                    )
                )
        sections.append(
            ReportSection(
                f"Context: {context.name}",
                paragraphs=("SAFE workflow completed; no Mutations executed.",)
                if scan
                else (
                    f"Context scan failed: {context.error_code or 'No result'}. "
                    "Other contexts were retained.",
                ),
                entries=tuple(entries),
                rows=tuple(
                    (f"Evidence: {kind.upper()}", str(count))
                    for kind, count in scan.evidence_counts.items()
                )
                if scan
                else (),
            )
        )
        if scan and scan.graphql_security_review is not None:
            sections.append(
                security_review_section(
                    scan.graphql_security_review,
                    context=context.name,
                    follow_ups=scan.object_lookup_follow_up or (),
                )
            )
        if scan and scan.sensitive_input_review:
            from gqlsleuth.reporting.sensitive_input import sensitive_review_section

            sections.append(sensitive_review_section(scan.sensitive_input_review, context.name))
    for pair in report.pairs:
        entries = []
        for candidate in pair.candidates:
            entries.append(
                ReportEntry(
                    candidate.kind.value.replace("_", " ").title(),
                    details=(
                        ("Endpoint", candidate.endpoint),
                        (
                            "Operation",
                            f"{candidate.operation_kind.value} {candidate.operation_name}"
                            if candidate.operation_kind
                            else "Endpoint",
                        ),
                        (pair.context_a, candidate.left.state.upper()),
                        (pair.context_b, candidate.right.state.upper()),
                        (
                            f"{pair.context_a} HTTP status",
                            str(candidate.left.http_status or "Not recorded"),
                        ),
                        (
                            f"{pair.context_b} HTTP status",
                            str(candidate.right.http_status or "Not recorded"),
                        ),
                    ),
                    evidence_references=(
                        (
                            f"{pair.context_a} source evidence",
                            ", ".join(map(str, candidate.left.evidence_ids)),
                        ),
                        (
                            f"{pair.context_b} source evidence",
                            ", ".join(map(str, candidate.right.evidence_ids)),
                        ),
                    ),
                )
            )
        sections.append(
            ReportSection(
                f"{pair.context_a} ↔ {pair.context_b}",
                entries=tuple(entries),
                paragraphs=()
                if entries
                else (
                    "No differences observed in comparable retained facts. "
                    "This is not proof of equivalent authorization.",
                ),
            )
        )
    sections.extend(
        (
            ReportSection(
                "Errors and Limitations",
                entries=tuple(
                    ReportEntry(
                        f"{pair.context_a} ↔ {pair.context_b}: {item.stage}",
                        details=(("Endpoint", item.endpoint or "Not available"),),
                        paragraphs=(item.reason,),
                    )
                    for pair in report.pairs
                    for item in pair.limitations
                ),
            ),
            ReportSection(
                "Manual Review Recommendations",
                paragraphs=(
                    "Validate observed differences against the application's intended access "
                    "policy and supplied context configuration. Context names do not establish "
                    "privileges.",
                    "Query outcomes may depend on generated placeholders or schema differences. "
                    "No IDs were varied and no ownership or business-data comparison "
                    "was performed.",
                ),
            ),
            ReportSection("Safety Notice", paragraphs=(report.safety_notice,)),
        )
    )
    if report.nested_authorization_review is not None:
        sections.insert(-1, nested_authorization_section(report.nested_authorization_review))
    if report.object_authorization_review is not None:
        from gqlsleuth.reporting.object_authorization import object_authorization_section

        sections.insert(-1, object_authorization_section(report.object_authorization_review))
    if report.authorization_policy_validation is not None:
        from gqlsleuth.reporting.authorization_policy import authorization_policy_section

        sections.insert(-1, authorization_policy_section(report.authorization_policy_validation))
    return tuple(sections)
