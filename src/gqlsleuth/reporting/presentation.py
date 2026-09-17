"""One human-readable section layout shared by Markdown and HTML templates."""

import json
from dataclasses import dataclass, fields

from gqlsleuth.ai.models import AI_NOTICE, AIInterpretationResult, AIStatement
from gqlsleuth.domain.models import Evidence
from gqlsleuth.domain.multiplicity import MULTIPLICITY_NOTICE
from gqlsleuth.domain.query_depth import DEPTH_NOTICE
from gqlsleuth.domain.security_review import SECURITY_REVIEW_NOTICE, GraphQLSecurityReviewResult
from gqlsleuth.presentation.capabilities import capability_wording
from gqlsleuth.presentation.multiplicity import probe_guidance, probe_label, probe_response
from gqlsleuth.presentation.object_lookup import (
    FOLLOW_UP_NOTICE,
    ObjectLookupFollowUpHint,
    follow_up_commands,
)
from gqlsleuth.presentation.query_depth import depth_response
from gqlsleuth.presentation.responses import ResponsePresentation, present_response
from gqlsleuth.presentation.security_review import candidate_facts, candidate_label
from gqlsleuth.reporting.models import OperationReport, ReportContext


@dataclass(frozen=True)
class ReportEntry:
    title: str
    details: tuple[tuple[str, str], ...] = ()
    paragraphs: tuple[str, ...] = ()
    code_blocks: tuple[tuple[str, str], ...] = ()
    request_blocks: tuple[tuple[str, str], ...] = ()
    response: ResponsePresentation | None = None
    evidence_references: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ReportSection:
    title: str
    paragraphs: tuple[str, ...] = ()
    rows: tuple[tuple[str, str], ...] = ()
    entries: tuple[ReportEntry, ...] = ()
    table_headers: tuple[str, ...] = ()
    table_rows: tuple[tuple[str, ...], ...] = ()


def human_sections(report: ReportContext) -> tuple[ReportSection, ...]:
    """Present recorded facts; response parsing is display-only, never classification."""
    sections = [
        ReportSection(
            "Scan Overview",
            rows=(
                ("Target", report.target.original_url),
                ("Mode", report.mode.value.upper()),
                ("Report timestamp (UTC)", report.generated_at.isoformat()),
                ("GQLSleuth version", report.gqlsleuth_version),
                ("Report schema version", str(report.report_schema_version)),
            ),
        ),
        ReportSection(
            "Executive Scan Summary",
            rows=tuple((_human_label(key), str(value)) for key, value in report.summary.items()),
        ),
        ReportSection(
            "GraphQL Discovery and Confirmation",
            entries=tuple(
                ReportEntry(
                    item.endpoint,
                    details=(
                        (
                            "Confidence",
                            item.confidence.value.upper() if item.confidence else "Not recorded",
                        ),
                        ("GET signals", ", ".join(item.get_signals) or "None recorded"),
                        ("POST signals", ", ".join(item.post_signals) or "None recorded"),
                    ),
                    paragraphs=(item.detection_reason or "No detection result retained.",),
                )
                for item in report.endpoints
            ),
        ),
        ReportSection(
            "Introspection",
            entries=tuple(
                ReportEntry(
                    item.endpoint,
                    details=(("Status", item.introspection_status.upper()),),
                    paragraphs=(item.introspection_reason or "",),
                )
                for item in report.endpoints
                if item.introspection_status
            ),
        ),
        ReportSection(
            "Schema Summary",
            entries=tuple(
                ReportEntry(
                    item.endpoint,
                    details=tuple(
                        (
                            _human_label(field.name),
                            str(getattr(item.schema_summary, field.name)),
                        )
                        for field in fields(item.schema_summary)
                    )
                    + (("Analyzed root operations", str(item.analyzed_operation_count)),),
                )
                for item in report.endpoints
                if item.schema_summary
            ),
        ),
        ReportSection(
            "Security Review Candidates",
            paragraphs=(
                "Priority indicates manual-review interest, not vulnerability severity. "
                "The existing operation-analysis order and rule matches are preserved.",
            ),
            entries=tuple(
                ReportEntry(
                    f"{item.kind.value.title()} {item.name}",
                    details=(
                        ("Endpoint", item.endpoint),
                        ("Priority", item.priority.value.replace("_", " ").upper()),
                        ("Interest score", str(item.interest_score)),
                        ("Categories", ", ".join(category.value for category in item.categories)),
                    ),
                    paragraphs=tuple(
                        f"{match.rule_id}: {match.reason} "
                        f"Keywords: {', '.join(match.matched_keywords)}. "
                        f"Locations: {', '.join(match.locations)}. Contribution: {match.weight}."
                        for match in item.matched_rules
                    ),
                )
                for item in report.review_candidates
            ),
        ),
        *(
            [
                security_review_section(
                    report.graphql_security_review, follow_ups=report.object_lookup_follow_up or ()
                )
            ]
            if report.graphql_security_review is not None
            else []
        ),
        ReportSection(
            "Generated Queries", entries=tuple(_artifact_entry(item) for item in report.queries)
        ),
        ReportSection(
            "Safe Query Execution",
            paragraphs=(
                "Attempted requests are established only by QUERY_EXECUTION evidence. "
                "SUCCESS is an execution outcome, not a vulnerability finding.",
            ),
            entries=tuple(
                _execution_entry(item, report.evidence) for item in report.queries if item.execution
            ),
        ),
    ]
    if report.mode.value == "active":
        if report.active is None:
            sections.append(
                ReportSection(
                    "Active Mutation Analysis",
                    paragraphs=(
                        "No active-stage result was retained. No Mutation execution is inferred.",
                    ),
                )
            )
        else:
            active = report.active
            sections.append(
                ReportSection(
                    "Active Mutation Analysis",
                    paragraphs=(
                        "Generation, selection, confirmation, and execution are separate states. "
                        "Only MUTATION_EXECUTION evidence establishes an attempted request. "
                        "SUCCESS does not confirm a vulnerability.",
                        "No Mutation candidates."
                        if not active.candidates
                        else f"{len(active.candidates)} identified; "
                        f"{sum(item.generated.success for item in active.candidates)} generated.",
                    ),
                    rows=(
                        (
                            "Selected candidate indices",
                            ", ".join(map(str, active.selected_indices)) or "None",
                        ),
                        ("Final batch confirmed", "Yes" if active.confirmed else "No"),
                    ),
                    entries=tuple(
                        _mutation_entry(item, report.evidence) for item in active.candidates
                    ),
                )
            )
    sections.extend(
        (
            ReportSection(
                "Evidence Summary",
                paragraphs=(
                    "Counts refer to retained evidence. "
                    "Exact request/response facts are preserved in JSON; "
                    "human execution response bodies are bounded for presentation.",
                ),
                rows=tuple(
                    (key.upper(), str(value)) for key, value in report.evidence_counts.items()
                ),
            ),
            ReportSection(
                "Errors and Limitations",
                entries=tuple(
                    ReportEntry(
                        f"{item.stage}: {item.operation_name or item.endpoint}",
                        details=(("Endpoint", item.endpoint), ("Code", item.code.upper())),
                        paragraphs=(item.message,),
                    )
                    for item in report.errors_and_limitations
                ),
            ),
            ReportSection("Manual Review Recommendations", paragraphs=report.recommendations),
        )
    )
    if report.multiplicity is not None:
        result = report.multiplicity
        sections.append(
            ReportSection(
                "Controlled GraphQL Multiplicity Validation",
                paragraphs=(MULTIPLICITY_NOTICE, *result.limitations),
                rows=(
                    ("Available probes", str(len(result.candidates))),
                    ("Selected indices", ", ".join(map(str, result.selected_indices)) or "None"),
                    ("Confirmed", str(result.confirmed)),
                    ("Attempted requests", str(len(result.evidence))),
                ),
                entries=tuple(
                    ReportEntry(
                        probe_label(item.candidate.probe_type),
                        details=(
                            ("Endpoint", item.candidate.base.endpoint),
                            ("Operation", "query " + item.candidate.base.operation_name),
                            ("Decision", item.decision.value.upper()),
                            (
                                "Observation",
                                item.evidence.observation.value.upper()
                                if item.evidence
                                else "Not executed",
                            ),
                        ),
                        paragraphs=(item.reason, probe_guidance(item.candidate.probe_type)),
                        request_blocks=(
                            ("graphql", item.candidate.query),
                            (
                                "json",
                                json.dumps(item.candidate.base.variables, indent=2, sort_keys=True),
                            ),
                        ),
                        response=probe_response(item.evidence) if item.evidence else None,
                    )
                    for item in result.executions
                ),
            )
        )
    if report.query_depth is not None:
        depth = report.query_depth
        sections.append(
            ReportSection(
                "Controlled Query Depth Validation",
                paragraphs=(DEPTH_NOTICE, *depth.limitations),
                rows=(
                    ("Available probes", str(len(depth.candidates))),
                    ("Selected indices", ", ".join(map(str, depth.selected_indices)) or "None"),
                    ("Confirmed", str(depth.confirmed)),
                    ("Attempted requests", str(len(depth.evidence))),
                ),
                entries=tuple(
                    ReportEntry(
                        "Controlled Query Depth / query " + item.candidate.base.operation_name,
                        details=(
                            ("Endpoint", item.candidate.base.endpoint),
                            ("Baseline depth", str(item.candidate.baseline_depth)),
                            ("Baseline outcome", item.candidate.baseline_status.value.upper()),
                            ("Probe depth", str(item.candidate.probe_depth)),
                            ("Composite list edges", str(item.candidate.list_edges)),
                            ("Recursive path", " -> ".join(item.candidate.recursive_path)),
                            ("Decision", item.decision.value.upper()),
                            (
                                "Observation",
                                item.evidence.observation.value.upper()
                                if item.evidence
                                else "Not executed",
                            ),
                        ),
                        paragraphs=(capability_wording(item.reason),),
                        request_blocks=(
                            ("graphql", item.candidate.query),
                            (
                                "json",
                                json.dumps(item.candidate.base.variables, indent=2, sort_keys=True),
                            ),
                        ),
                        response=depth_response(item.evidence) if item.evidence else None,
                    )
                    for item in depth.executions
                ),
            )
        )
    if report.sequential_object_discovery is not None:
        from gqlsleuth.reporting.sequential_discovery import sequential_discovery_section

        sections.append(sequential_discovery_section(report.sequential_object_discovery))
    if report.object_authorization_review is not None:
        from gqlsleuth.reporting.object_authorization import object_authorization_section

        sections.append(object_authorization_section(report.object_authorization_review))
    if report.authorization_policy_validation is not None:
        from gqlsleuth.reporting.authorization_policy import authorization_policy_section

        sections.append(authorization_policy_section(report.authorization_policy_validation))
    if report.ai_interpretation is not None:
        sections.append(ai_section(report.ai_interpretation))
    sections.append(
        ReportSection(
            "Safety Notice",
            paragraphs=(
                report.safety_notice,
                "Execution sections may contain application response data. "
                "Handle this report as a potentially sensitive pentest artifact.",
            ),
        )
    )
    return tuple(sections)


def security_review_section(
    review: GraphQLSecurityReviewResult,
    *,
    context: str | None = None,
    follow_ups: tuple[ObjectLookupFollowUpHint, ...] = (),
) -> ReportSection:
    entries = tuple(
        ReportEntry(
            candidate_label(item.candidate_type) + ": " + item.subject,
            details=(("Endpoint", item.endpoint),)
            + (
                (
                    (
                        "Review interest",
                        item.related_operation.priority.value.replace("_", " ").upper(),
                    ),
                    (
                        "Categories",
                        ", ".join(value.value for value in item.related_operation.categories),
                    ),
                )
                if item.related_operation
                else ()
            ),
            paragraphs=(
                capability_wording(item.deterministic_reason),
                *candidate_facts(item),
                "Manual review: " + capability_wording(item.review_guidance),
            )
            + (
                (FOLLOW_UP_NOTICE,)
                if any(
                    hint.endpoint == item.endpoint and item.subject == f"query {hint.operation}"
                    for hint in follow_ups
                )
                else ()
            ),
            code_blocks=tuple(
                (
                    "text",
                    "Suggested follow-up:\n\n"
                    + "\n\n".join(
                        f"{label}:\n  {command}" for label, command in follow_up_commands(hint)
                    ),
                )
                for hint in follow_ups
                if hint.endpoint == item.endpoint and item.subject == f"query {hint.operation}"
            ),
            evidence_references=(
                ("Schema evidence", ", ".join(map(str, item.source_evidence_ids))),
            )
            if item.source_evidence_ids
            else (),
        )
        for item in review.candidates
    )
    return ReportSection(
        "GraphQL Security Review" + (f" — Context: {context}" if context else ""),
        paragraphs=(SECURITY_REVIEW_NOTICE,)
        + (
            ()
            if review.candidates
            else (
                "No structural candidates were identified in the inspected metadata. "
                "This is not an absence-of-risk conclusion."
                if review.analyzed_endpoints
                else "Structural review was not performed: no parsed schema.",
            )
        )
        + tuple(
            item.endpoint + ": " + capability_wording(item.reason) for item in review.limitations
        ),
        rows=(("Structural review candidates", str(len(review.candidates))),),
        entries=entries,
    )


def ai_section(result: AIInterpretationResult) -> ReportSection:
    """Present an already-produced interpretation without modifying deterministic sections."""
    entries = []
    interpretation = result.interpretation
    if interpretation is not None:
        entries = [
            ReportEntry(
                "Execution Summary (validated facts)",
                paragraphs=(_ai_statement(interpretation.scan_summary),),
            ),
            ReportEntry(
                "Operation Review",
                paragraphs=tuple(
                    f"{item.operation}: {item.explanation}"
                    for item in interpretation.operation_review
                ),
            ),
            ReportEntry(
                "Limitations",
                paragraphs=tuple(_ai_statement(item) for item in interpretation.limitations),
            ),
        ]
    return ReportSection(
        "AI-Assisted Interpretation",
        paragraphs=(AI_NOTICE,) + ((result.error_message,) if result.error_message else ()),
        rows=(
            ("Model", result.model),
            ("AI status", result.status.value.upper()),
            ("Operations supplied", str(result.context_metadata.operations_included)),
            ("Operations omitted", str(result.context_metadata.operations_omitted)),
            ("Context truncated", "Yes" if result.context_metadata.context_truncated else "No"),
        ),
        entries=tuple(entries),
    )


def _ai_statement(statement: AIStatement) -> str:
    references = f" ({', '.join(statement.operations)})" if statement.operations else ""
    return statement.text + references


def _artifact_entry(item: OperationReport) -> ReportEntry:
    artifact = item.generated
    blocks = (
        ()
        if artifact.query_text is None
        else (
            ("graphql", artifact.query_text),
            (
                "json",
                json.dumps(
                    artifact.variables,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                    allow_nan=False,
                ),
            ),
        )
    )
    return ReportEntry(
        artifact.operation_name,
        details=(("Endpoint", artifact.endpoint),),
        paragraphs=artifact.manual_adjustments
        + ((artifact.failure_reason,) if artifact.failure_reason else ()),
        code_blocks=blocks,
    )


def _execution_entry(item: OperationReport, evidence: tuple[Evidence, ...] = ()) -> ReportEntry:
    execution = item.execution
    if execution is None:
        return ReportEntry(
            item.generated.operation_name, paragraphs=("No execution result retained.",)
        )
    response = None
    if execution.attempted:
        duration = next(
            (
                fact.duration_seconds
                for fact in evidence
                if fact.evidence_id in execution.evidence_ids
            ),
            None,
        )
        response = present_response(
            execution.response, execution.status or "Not recorded", duration_seconds=duration
        )
    return ReportEntry(
        item.generated.operation_name,
        details=(
            ("Endpoint", item.generated.endpoint),
            (
                "Status",
                execution.status.upper() if execution.status else "No response classification",
            ),
            (
                "Decision",
                execution.decision.upper() if execution.decision else execution.status or "None",
            ),
            ("Attempted (execution evidence)", "Yes" if execution.attempted else "No"),
            ("HTTP status", str(execution.response.status_code) if execution.response else "None"),
        ),
        paragraphs=(execution.reason,)
        + ((execution.error_message,) if execution.error_message else ()),
        request_blocks=_artifact_entry(item).code_blocks if execution.attempted else (),
        response=response,
    )


def _mutation_entry(item: OperationReport, evidence: tuple[Evidence, ...] = ()) -> ReportEntry:
    execution = _execution_entry(item, evidence)
    artifact = item.generated
    return ReportEntry(
        f"[{item.candidate_index}] {artifact.operation_name}",
        details=(
            ("Priority", artifact.operation.priority.value.replace("_", " ").upper()),
            ("Categories", ", ".join(category.value for category in artifact.operation.categories)),
            ("Generated", "Yes" if artifact.success else "No"),
            ("Preview decision", (item.preview_decision or "None").upper()),
            ("Selected", "Yes" if item.selected else "No"),
            *execution.details,
        ),
        paragraphs=_unique_text(
            (
                item.preview_reason or "",
                *execution.paragraphs,
                *artifact.manual_adjustments,
                *((artifact.failure_reason,) if artifact.failure_reason else ()),
            )
        ),
        request_blocks=execution.request_blocks,
        response=execution.response,
    )


def _human_label(value: str) -> str:
    label = value.replace("_", " ").capitalize()
    return label.replace("Graphql", "GraphQL").replace("graphql", "GraphQL")


def _unique_text(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))
