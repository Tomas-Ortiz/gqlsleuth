"""One human-readable section layout shared by Markdown and HTML templates."""

import json
from dataclasses import dataclass, replace

from gqlsleuth.ai.models import AI_NOTICE, AIInterpretationResult
from gqlsleuth.ai.sections import quality_warning_description
from gqlsleuth.domain.models import ConfidenceLevel, Evidence
from gqlsleuth.domain.multiplicity import MULTIPLICITY_NOTICE
from gqlsleuth.domain.query_depth import DEPTH_NOTICE
from gqlsleuth.domain.security_review import (
    SECURITY_REVIEW_NOTICE,
    GraphQLSecurityReviewResult,
    SecurityCandidateType,
)
from gqlsleuth.presentation.capabilities import capability_wording
from gqlsleuth.presentation.discovery_scope import discovery_scope_notes
from gqlsleuth.presentation.limits import MAX_HUMAN_DETAIL_ITEMS, showing_notice
from gqlsleuth.presentation.multiplicity import probe_guidance, probe_label, probe_response
from gqlsleuth.presentation.object_lookup import (
    FOLLOW_UP_NOTICE,
    ObjectLookupFollowUpHint,
    follow_up_commands,
)
from gqlsleuth.presentation.query_depth import depth_response
from gqlsleuth.presentation.responses import (
    NULL_DATA_NOTICE,
    SUCCESS_NOTICE,
    ResponsePresentation,
    compact_mutation_body,
    present_response,
    success_with_null_data,
)
from gqlsleuth.presentation.security_review import candidate_facts, candidate_label, review_wording
from gqlsleuth.presentation.terminology import category_label, execution_reason
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
    execution: bool = False
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReportSection:
    title: str
    paragraphs: tuple[str, ...] = ()
    rows: tuple[tuple[str, str], ...] = ()
    entries: tuple[ReportEntry, ...] = ()
    table_headers: tuple[str, ...] = ()
    table_rows: tuple[tuple[str, ...], ...] = ()
    children: tuple["ReportSection", ...] = ()
    collapsed: bool = False
    endpoint: str | None = None


def introspection_section(report: ReportContext) -> ReportSection:
    """Render retained introspection facts, including optional human recovery rows."""
    return ReportSection(
        "Introspection",
        entries=tuple(
            ReportEntry(
                item.endpoint,
                details=(
                    ("Status", (item.observed_introspection_status or "not_attempted").upper()),
                )
                + (
                    (("Schema retrieval", item.schema_retrieval_status.upper()),)
                    if item.schema_retrieval_status
                    else ()
                )
                + (item.recovery.rows if item.recovery else ()),
                paragraphs=(*item.recovery.context, *item.recovery.inventory)
                if item.recovery
                else (item.schema_retrieval_reason or item.introspection_reason or "",),
            )
            for item in report.endpoints
            if item.introspection_status
        ),
    )


def technical_sections(report: ReportContext) -> tuple[ReportSection, ...]:
    """Present recorded facts; response parsing is display-only, never classification."""
    from gqlsleuth.reporting.operation_review import operation_review_section

    scope_notes = discovery_scope_notes(report.target, report.evidence)
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
            "GraphQL Discovery and Confirmation",
            paragraphs=scope_notes,
            rows=(
                ("Supplied target", report.target.original_url),
                (
                    "Retained GraphQL endpoints",
                    ", ".join(
                        item.endpoint
                        for item in report.endpoints
                        if item.confidence in {ConfidenceLevel.CONFIRMED, ConfidenceLevel.PROBABLE}
                    )
                    or "None",
                ),
            )
            if scope_notes
            else (),
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
        introspection_section(report),
        ReportSection(
            "Schema Summary",
            entries=tuple(
                ReportEntry(
                    item.endpoint,
                    paragraphs=(
                        (
                            "Partial retrieval: these counts describe retrieved content only; "
                            "schema and operation coverage may be incomplete.",
                        )
                        if item.schema_retrieval_status == "partial"
                        else ()
                    ),
                    details=tuple(
                        (label, str(value))
                        for label, value in (
                            ("Query root", item.schema_summary.query_root),
                            ("Mutation root", item.schema_summary.mutation_root),
                            ("Subscription root", item.schema_summary.subscription_root),
                            ("Custom scalars", item.schema_summary.custom_scalar_type_count),
                            ("Interfaces", item.schema_summary.interface_type_count),
                            ("Unions", item.schema_summary.union_type_count),
                        )
                        if value
                    ),
                )
                for item in report.endpoints
                if item.schema_summary
            ),
        ),
        operation_review_section(report),
        *(
            [
                security_review_section(
                    report.graphql_security_review, follow_ups=report.object_lookup_follow_up or ()
                )
            ]
            if report.graphql_security_review is not None
            else []
        ),
        ReportSection("Generated Queries"),
        ReportSection(
            "Safe Query Execution",
            paragraphs=(
                "Execution attempts are established from retained QUERY_EXECUTION evidence, "
                "including transport failures. This does not guarantee the server received "
                "the request. " + SUCCESS_NOTICE,
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
                        + SUCCESS_NOTICE,
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
                        f"{item.stage}: {item.operation_name}"
                        if item.operation_name
                        else item.stage,
                        details=(
                            ("Endpoint", item.endpoint),
                            (
                                "Code",
                                item.code if item.code.startswith("Http") else item.code.upper(),
                            ),
                        ),
                        paragraphs=(
                            execution_reason(item.message)
                            if item.stage == "query" and item.code == "skipped_safety"
                            else item.message,
                        ),
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
    if report.authentication_token_security is not None:
        from gqlsleuth.reporting.authentication import authentication_sections

        sections.extend(authentication_sections(report.authentication_token_security))
    if report.idor_bola_detection is not None:
        from gqlsleuth.reporting.idor import idor_sections

        sections.extend(idor_sections(report.idor_bola_detection))
    if report.object_authorization_review is not None:
        from gqlsleuth.reporting.object_authorization import object_authorization_section

        sections.append(object_authorization_section(report.object_authorization_review))
    if report.mutation_authorization is not None:
        from gqlsleuth.reporting.mutation_authorization import mutation_authorization_section

        sections.append(mutation_authorization_section(report.mutation_authorization))
    if report.authorization_policy_validation is not None:
        from gqlsleuth.reporting.authorization_policy import authorization_policy_section

        sections.append(authorization_policy_section(report.authorization_policy_validation))
    if report.sensitive_input_review or report.sensitive_input_validation:
        from gqlsleuth.reporting.sensitive_input import (
            sensitive_review_section,
            sensitive_validation_section,
        )

        if report.sensitive_input_review:
            sections.append(sensitive_review_section(report.sensitive_input_review))
        if report.sensitive_input_validation:
            sections.append(sensitive_validation_section(report.sensitive_input_validation))
    if report.federation_security is not None:
        from gqlsleuth.reporting.federation import federation_sections

        sections.extend(federation_sections(report.federation_security))
    if report.subscription_security is not None:
        from gqlsleuth.reporting.subscriptions import subscription_sections

        sections.extend(subscription_sections(report.subscription_security))
    if report.file_upload_security is not None:
        from gqlsleuth.reporting.file_upload import file_upload_sections

        sections.extend(file_upload_sections(report.file_upload_security))
    if report.rate_limiting_abuse_controls is not None:
        from gqlsleuth.reporting.abuse_controls import abuse_control_sections

        sections.extend(abuse_control_sections(report.rate_limiting_abuse_controls))
    if report.ai_interpretation is not None:
        sections.append(ai_section(report.ai_interpretation, include_operations=False))
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
    from gqlsleuth.reporting.scaling import scale_operations

    return scale_operations(report, tuple(sections))


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
                        ", ".join(
                            category_label(value.value)
                            for value in item.related_operation.categories
                        ),
                    ),
                )
                if item.related_operation
                else ()
            ),
            paragraphs=(
                review_wording(item.deterministic_reason),
                *candidate_facts(item),
                "Manual review: " + review_wording(item.review_guidance),
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
    # Apply the existing global detail cap before grouping, not independently per group.
    visible = entries[:MAX_HUMAN_DETAIL_ITEMS]
    groups: dict[tuple[str, str, str], list[int]] = {}
    for index, candidate in enumerate(review.candidates[:MAX_HUMAN_DETAIL_ITEMS]):
        if candidate.candidate_type is SecurityCandidateType.OBJECT_LOOKUP_REVIEW:
            key = (candidate.endpoint, candidate.deterministic_reason, candidate.review_guidance)
            groups.setdefault(key, []).append(index)
    grouped: set[int] = set()
    children = []
    for (endpoint, reason, guidance), indices in groups.items():
        if len(indices) < 2:
            continue
        grouped.update(indices)
        shared: tuple[str, ...] = (
            review_wording(reason),
            "Manual review: " + review_wording(guidance),
        )
        if any(FOLLOW_UP_NOTICE in visible[i].paragraphs for i in indices):
            shared += (FOLLOW_UP_NOTICE,)
        rows = []
        details = []
        for index in indices:
            candidate = review.candidates[index]
            entry = visible[index]
            hint = next(
                (
                    h
                    for h in follow_ups
                    if h.endpoint == endpoint and candidate.subject == f"query {h.operation}"
                ),
                None,
            )
            rows.append(
                (
                    candidate.subject,
                    f"{hint.identifier_argument}: {hint.identifier_type}"
                    if hint
                    else "See supporting facts",
                    hint.return_type
                    if hint
                    else candidate.related_operation.return_type.render()
                    if candidate.related_operation
                    else "See supporting facts",
                    dict(entry.details).get("Review interest", "Not recorded"),
                )
            )
            details.append(
                replace(
                    entry,
                    title=candidate.subject,
                    details=tuple(
                        p for p in entry.details if p[0] not in {"Endpoint", "Review interest"}
                    ),
                    paragraphs=tuple(p for p in entry.paragraphs if p not in shared),
                )
            )
        children.append(
            ReportSection(
                "Object Lookup Review",
                endpoint=endpoint,
                paragraphs=(f"{len(indices)} operations identified for manual review.", *shared),
                table_headers=("Operation", "Argument", "Return type", "Review interest"),
                table_rows=tuple(rows),
                entries=tuple(details),
            )
        )
    return ReportSection(
        "GraphQL Security Review" + (f" — Context: {context}" if context else ""),
        paragraphs=(review_wording(SECURITY_REVIEW_NOTICE),)
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
        + (
            (showing_notice(MAX_HUMAN_DETAIL_ITEMS, len(entries), "structural review details"),)
            if len(entries) > MAX_HUMAN_DETAIL_ITEMS
            else ()
        ),
        rows=(("Structural review candidates", str(len(review.candidates))),),
        children=tuple(children),
        entries=tuple(entry for index, entry in enumerate(visible) if index not in grouped)
        + tuple(
            ReportEntry(
                "Limitation",
                details=(("Endpoint", item.endpoint),),
                paragraphs=(capability_wording(item.reason),),
            )
            for item in review.limitations
        ),
    )


def ai_section(result: AIInterpretationResult, *, include_operations: bool = True) -> ReportSection:
    """Present an already-produced interpretation without modifying deterministic sections."""
    from gqlsleuth.ai.sections import interpretation_sections, quality_summary_lines, usage_rows

    entries: list[ReportEntry] = []
    children: list[ReportSection] = []
    interpretation = result.interpretation
    if interpretation is not None:
        entries = [
            ReportEntry(
                "Execution Summary (deterministic facts)",
                paragraphs=(result.execution_summary or "Not recorded.",),
            ),
        ]
        children.extend(
            ReportSection(
                title,
                entries=tuple(
                    ReportEntry(
                        block.title,
                        details=block.details,
                        paragraphs=block.paragraphs,
                        references=block.references,
                    )
                    for block in blocks
                ),
            )
            for title, blocks in interpretation_sections(result)
            if blocks and (include_operations or title != "Operation Analysis")
        )
        controls = tuple(
            f
            for f in result.references.security_facts
            if f.control_observed or f.evaluation == "satisfied"
        )
        if controls:
            children.append(
                ReportSection(
                    "Scoped Controls (deterministic facts)",
                    rows=tuple(
                        (
                            fact.security_fact_ref + " / " + fact.capability.value,
                            str(
                                fact.control_kind
                                or fact.evaluation
                                or fact.outcome
                                or "control_observed"
                            ),
                        )
                        for fact in controls
                    ),
                )
            )
    if result.quality_warnings:
        entries.insert(
            0,
            ReportEntry(
                "AI quality warnings",
                paragraphs=(
                    "Heuristic quality flags, not deterministic Findings. "
                    "Absence of flags does not establish that AI prose is correct.",
                ),
                details=tuple(
                    ("Quality warning", quality_warning_description(code))
                    for code in result.quality_warnings
                ),
            ),
        )
    if quality_lines := quality_summary_lines(result):
        entries.insert(0, ReportEntry("AI Quality Summary", paragraphs=quality_lines))
    children.append(
        ReportSection(
            "AI Generation Metadata",
            rows=usage_rows(result)
            + (
                ("Security facts supplied", str(result.context_metadata.security_facts_included)),
                ("Security facts omitted", str(result.context_metadata.security_facts_omitted)),
                ("Deterministic Findings", str(result.context_metadata.deterministic_findings)),
                ("Policy violations", str(result.context_metadata.policy_violations)),
                ("Satisfied policies", str(result.context_metadata.policy_satisfied)),
                ("Unresolved policies", str(result.context_metadata.policy_unresolved)),
                ("Context bytes", str(result.context_metadata.serialized_bytes)),
            ),
            collapsed=True,
        )
    )
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
        children=tuple(children),
    )


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
    null_data = bool(
        execution.attempted
        and execution.response
        and success_with_null_data(execution.status, execution.response.body)
    )
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
            ("Execution attempted", "Yes" if execution.attempted else "No"),
            ("HTTP status", str(execution.response.status_code) if execution.response else "None"),
        )
        + ((("Response data", "Null"),) if null_data else ()),
        paragraphs=(execution_reason(execution.reason),)
        + ((NULL_DATA_NOTICE,) if null_data else ())
        + ((execution.error_message,) if execution.error_message else ()),
        request_blocks=_artifact_entry(item).code_blocks if execution.attempted else (),
        response=response,
        execution=True,
    )


def _mutation_entry(item: OperationReport, evidence: tuple[Evidence, ...] = ()) -> ReportEntry:
    execution = _execution_entry(item, evidence)
    if execution.response and item.execution and item.execution.response:
        execution = replace(
            execution,
            response=replace(
                execution.response, body=compact_mutation_body(item.execution.response.body)
            ),
        )
    artifact = item.generated
    return ReportEntry(
        f"[{item.candidate_index}] {artifact.operation_name}",
        details=(
            ("Priority", artifact.operation.priority.value.replace("_", " ").upper()),
            (
                "Categories",
                ", ".join(
                    category_label(category.value) for category in artifact.operation.categories
                ),
            ),
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
        execution=True,
    )


def _human_label(value: str) -> str:
    if value == "security_review_candidate_count":
        return "Operation review candidate count"
    label = value.replace("_", " ").capitalize()
    return label.replace("Graphql", "GraphQL").replace("graphql", "GraphQL")


def _unique_text(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def human_sections(report: ReportContext) -> tuple[ReportSection, ...]:
    """Shared assessment-first Markdown/HTML presentation."""
    from gqlsleuth.reporting.assessment import assessment_sections

    return assessment_sections(report)
