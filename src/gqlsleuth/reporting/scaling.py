"""Bounded human inventories and exception details; canonical records stay exhaustive."""

from collections import Counter
from dataclasses import replace

from gqlsleuth.domain.analysis import InterestPriority
from gqlsleuth.presentation.assessment import build_assessment
from gqlsleuth.presentation.limits import (
    JSON_DETAIL_NOTICE,
    MAX_HUMAN_DETAIL_ITEMS,
    MAX_HUMAN_INVENTORY_ITEMS,
    is_safe_budget_reason,
    showing_notice,
)
from gqlsleuth.presentation.responses import success_with_null_data
from gqlsleuth.reporting.models import OperationReport, ReportContext
from gqlsleuth.reporting.presentation import (
    ReportEntry,
    ReportSection,
    _artifact_entry,
    _execution_entry,
    _mutation_entry,
)


def bound_section(section: ReportSection) -> ReportSection:
    """Cap collections before endpoint grouping, with explicit retained-data notices."""
    if section.title in {"AI-Assisted Interpretation", "Safety Notice"}:
        return section
    notices = []
    if len(section.entries) > MAX_HUMAN_DETAIL_ITEMS:
        notices.append(
            showing_notice(
                MAX_HUMAN_DETAIL_ITEMS, len(section.entries), "available detail sections"
            )
        )
    if len(section.table_rows) > MAX_HUMAN_INVENTORY_ITEMS:
        notices.append(
            showing_notice(MAX_HUMAN_INVENTORY_ITEMS, len(section.table_rows), "inventory rows")
        )
    return replace(
        section,
        paragraphs=section.paragraphs + tuple(notices),
        entries=section.entries[:MAX_HUMAN_DETAIL_ITEMS],
        table_rows=section.table_rows[:MAX_HUMAN_INVENTORY_ITEMS],
        children=tuple(bound_section(child) for child in section.children),
    )


def _state(item: OperationReport) -> str:
    execution = item.execution
    return (
        (execution.status or execution.decision or "unresolved") if execution else "not_run"
    ).upper()


def _exception(item: OperationReport) -> bool:
    return _state(item) not in {"SUCCESS", "NOT_SELECTED", "NOT_RUN"}


def _budget_skip(item: OperationReport) -> bool:
    execution = item.execution
    return bool(
        execution
        and _state(item) == "SKIPPED_LIMIT"
        and not execution.attempted
        and not execution.recorded_attempted
        and not execution.evidence_ids
        and execution.response is None
        and is_safe_budget_reason(execution.reason)
    )


def _group_limitations(report: ReportContext, section: ReportSection) -> ReportSection:
    groups: dict[tuple[str, str, str, str], list[ReportEntry]] = {}
    for issue, entry in zip(report.errors_and_limitations, section.entries, strict=True):
        key = (issue.endpoint, issue.stage, issue.code, " ".join(issue.message.split()))
        groups.setdefault(key, []).append(entry)
    # Administrative groups follow material limitations; ordering within each class is stable.
    keys = sorted(
        groups,
        key=lambda key: (
            key[1] == "query" and key[2] == "skipped_limit" and is_safe_budget_reason(key[3])
        ),
    )
    entries = []
    for key in keys:
        group = groups[key]
        entry = group[0]
        if len(group) > 1:
            entry = replace(
                entry,
                title=key[1],
                details=entry.details + (("Records", str(len(group))),),
                paragraphs=(
                    entry.paragraphs[0],
                    "Complete operation-level records remain in canonical JSON.",
                ),
            )
        entries.append(entry)
    return replace(section, entries=tuple(entries))


def _execution_detail(item: OperationReport, report: ReportContext) -> ReportEntry:
    entry = _execution_entry(item, report.evidence)
    # Response already supplies HTTP status/classification; don't repeat them in the same block.
    return replace(
        entry,
        paragraphs=tuple(dict.fromkeys((*entry.paragraphs, *item.generated.manual_adjustments))),
        details=tuple(
            pair
            for pair in entry.details
            if not (entry.response and pair[0] in {"Status", "HTTP status"})
            and not (pair[0] == "Decision" and pair[1].upper() == _state(item))
        ),
    )


def _mutation_detail(item: OperationReport, report: ReportContext) -> ReportEntry:
    entry = _mutation_entry(item, report.evidence)
    return replace(
        entry,
        details=tuple(
            pair
            for pair in entry.details
            if not (entry.response and pair[0] in {"Status", "HTTP status"})
            and not (pair[0] == "Decision" and pair[1].upper() == _state(item))
        ),
        request_blocks=_artifact_entry(item).code_blocks if item.selected else entry.request_blocks,
    )


def _duration(item: OperationReport, report: ReportContext) -> str:
    execution = item.execution
    if not execution or not execution.attempted:
        return "-"
    duration = (
        execution.response.duration_seconds
        if execution.response
        else next(
            (
                fact.duration_seconds
                for fact in report.evidence
                if fact.evidence_id in execution.evidence_ids
            ),
            None,
        )
    )
    return f"{duration * 1000:.3f} ms" if duration is not None else "-"


def _http(item: OperationReport) -> str:
    return (
        str(item.execution.response.status_code)
        if item.execution and item.execution.response
        else "-"
    )


def _inventory(
    section: ReportSection,
    headers: tuple[str, ...],
    rows: tuple[tuple[str, ...], ...],
    details: tuple[ReportEntry, ...],
    collection: str,
    protected_titles: frozenset[str] = frozenset(),
) -> ReportSection:
    notices: tuple[str, ...] = (JSON_DETAIL_NOTICE,)
    if len(rows) > MAX_HUMAN_INVENTORY_ITEMS:
        notices += (showing_notice(MAX_HUMAN_INVENTORY_ITEMS, len(rows), collection),)
    if len(details) > MAX_HUMAN_DETAIL_ITEMS:
        notices += (
            showing_notice(
                MAX_HUMAN_DETAIL_ITEMS, len(details), "available exception/review detail sections"
            ),
        )
    # Reserve space for selected/attempted support before ordinary exceptions, then retain order.
    selected = [index for index, entry in enumerate(details) if entry.title in protected_titles]
    selected += [
        index for index, entry in enumerate(details) if entry.title not in protected_titles
    ]
    visible = set(selected[:MAX_HUMAN_DETAIL_ITEMS])
    return replace(
        section,
        paragraphs=section.paragraphs + notices,
        table_headers=headers,
        table_rows=rows[:MAX_HUMAN_INVENTORY_ITEMS],
        entries=tuple(entry for index, entry in enumerate(details) if index in visible),
    )


def scale_operations(
    report: ReportContext, sections: tuple[ReportSection, ...]
) -> tuple[ReportSection, ...]:
    """Choose display detail from retained states/references, never reinterpret outcomes."""
    support_refs = {
        ref
        for section in sections
        if section.title
        not in {"Generated Queries", "Safe Query Execution", "Active Mutation Analysis"}
        for entry in section.entries
        if dict(entry.details).get("Selected") != "False"
        for _, value in entry.evidence_references
        for ref in value.split(", ")
    }
    supported = {
        (item.endpoint, item.operation.removeprefix("query "))
        for item in build_assessment(report).findings
    }
    for result in (report.multiplicity, report.query_depth):
        if result:
            supported.update(
                (item.candidate.base.endpoint, item.candidate.base.operation_name)
                for item in result.executions
                if item.evidence
            )

    def execution_detail(item: OperationReport) -> bool:
        if _budget_skip(item):
            return False
        return _exception(item) or (
            bool(item.execution and item.execution.attempted)
            and (
                (item.generated.endpoint, item.generated.operation_name) in supported
                or bool(
                    item.execution
                    and support_refs.intersection(map(str, item.execution.evidence_ids))
                )
            )
        )

    def null_data_detail(item: OperationReport) -> bool:
        return bool(
            item.execution
            and item.execution.attempted
            and item.execution.response
            and success_with_null_data(item.execution.status, item.execution.response.body)
        )

    replacements = []
    for section in sections:
        if section.title == "Generated Queries":
            detailed = tuple(
                item
                for item in report.queries
                if not (item.execution and (execution_detail(item) or null_data_detail(item)))
                and (
                    not item.generated.success
                    or item.generated.manual_adjustments
                    or item.generated.operation.priority
                    in {InterestPriority.CRITICAL_INTEREST, InterestPriority.HIGH_INTEREST}
                )
            )
            section = replace(
                section,
                rows=(
                    ("Generated", str(sum(i.generated.success for i in report.queries))),
                    (
                        "Generation failed",
                        str(sum(not i.generated.success for i in report.queries)),
                    ),
                ),
            )
            section = _inventory(
                section,
                ("Operation", "Priority", "Generation", "Endpoint"),
                tuple(
                    (
                        i.generated.operation_name,
                        i.generated.operation.priority.value.replace("_", " ").upper(),
                        "GENERATED" if i.generated.success else "GENERATION_FAILED",
                        i.generated.endpoint,
                    )
                    for i in report.queries
                ),
                tuple(_artifact_entry(i) for i in detailed),
                "generated Queries",
            )
        elif section.title == "Safe Query Execution":
            items = tuple(i for i in report.queries if i.execution)
            budgets = Counter(
                (i.generated.endpoint, " ".join(i.execution.reason.split()))
                for i in items
                if i.execution and _budget_skip(i)
            )
            multiple_endpoints = len({i.generated.endpoint for i in items}) > 1
            section = replace(
                section,
                paragraphs=section.paragraphs
                + tuple(
                    (f"{endpoint}: " if multiple_endpoints else "")
                    + f"{count} Queries were not executed. {reason}"
                    for (endpoint, reason), count in budgets.items()
                ),
                rows=tuple(
                    (state, str(count))
                    for state, count in Counter(_state(i) for i in items).items()
                ),
            )
            section = _inventory(
                section,
                ("Operation", "Status", "HTTP", "Duration", "Endpoint"),
                tuple(
                    (
                        i.generated.operation_name,
                        _state(i),
                        _http(i),
                        _duration(i, report),
                        i.generated.endpoint,
                    )
                    for i in items
                ),
                tuple(
                    _execution_detail(i, report)
                    for i in items
                    if execution_detail(i) or null_data_detail(i)
                ),
                "Query execution results",
                frozenset(
                    i.generated.operation_name
                    for i in items
                    if i.execution
                    and i.execution.attempted
                    and not _exception(i)
                    and execution_detail(i)
                ),
            )
        elif section.title == "Errors and Limitations":
            section = _group_limitations(report, section)
        elif section.title == "Active Mutation Analysis" and report.active:
            items = report.active.candidates
            section = _inventory(
                section,
                ("Operation", "Selected", "Status", "HTTP", "Endpoint"),
                tuple(
                    (
                        f"[{i.candidate_index}] {i.generated.operation_name}",
                        "Yes" if i.selected else "No",
                        _state(i),
                        _http(i),
                        i.generated.endpoint,
                    )
                    for i in items
                ),
                tuple(
                    _mutation_detail(i, report)
                    for i in items
                    if i.selected
                    or (i.execution and i.execution.attempted)
                    or _exception(i)
                    or not i.generated.success
                    or i.preview_decision == "blocked_safety"
                ),
                "Mutation candidates",
                frozenset(
                    f"[{i.candidate_index}] {i.generated.operation_name}"
                    for i in items
                    if i.selected or (i.execution and i.execution.attempted)
                ),
            )
        elif section.title in {
            "Controlled GraphQL Multiplicity Validation",
            "Controlled Query Depth Validation",
        }:
            depth_columns = (
                ("Baseline depth", "Probe depth")
                if section.title == "Controlled Query Depth Validation"
                else ()
            )
            probe_rows: list[tuple[str, ...]] = []
            probe_details: list[ReportEntry] = []
            protected_titles: set[str] = set()
            for entry in section.entries:
                metadata = dict(entry.details)
                if "Operation" in metadata:
                    entry = replace(entry, title=entry.title + " / " + metadata["Operation"])
                probe_rows.append(
                    (
                        entry.title,
                        *(metadata.get(column, "-") for column in depth_columns),
                        metadata.get("Decision", "NOT_RUN"),
                        metadata.get("Observation", "Not executed"),
                        metadata.get("Endpoint", ""),
                    )
                )
                if entry.response is not None or metadata.get("Decision") != "NOT_SELECTED":
                    probe_details.append(entry)
                if entry.response is not None:
                    protected_titles.add(entry.title)
            section = _inventory(
                section,
                ("Operation / probe", *depth_columns, "Decision", "Observation", "Endpoint"),
                tuple(probe_rows),
                tuple(probe_details),
                "capability results",
                frozenset(protected_titles),
            )
        replacements.append(section)
    return tuple(replacements)
