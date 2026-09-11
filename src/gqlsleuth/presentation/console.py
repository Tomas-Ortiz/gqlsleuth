"""Compact and detailed Rich views of existing results; never initiate scanner work."""

from collections import Counter
from json import dumps
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from gqlsleuth.ai.models import AI_NOTICE, AIAnalysisStatus, AIInterpretationResult
from gqlsleuth.application.active_execution import ActiveExecutionScanResult
from gqlsleuth.application.operation_analysis import EndpointOperationAnalysisResult
from gqlsleuth.application.safe_execution import QueryExecutionResult, SafeExecutionScanResult
from gqlsleuth.application.schema_parsing import EndpointSchemaResult
from gqlsleuth.domain.active import MutationDecision, MutationPreview
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.infrastructure.http import HttpResponse
from gqlsleuth.presentation.priorities import priority_label, style_priority_terms
from gqlsleuth.presentation.responses import present_response, present_response_body

CONSOLE_THEME = Theme(
    {
        "gql.heading": "bold",
        "gql.section": "bold bright_white",
        "gql.response": "dim bold",
        "gql.positive": "green",
        "gql.warning": "yellow",
        "gql.error": "bold red",
        "gql.metadata": "cyan",
        "gql.secondary": "dim",
    }
)
ROOT_HELP_EPILOG = "\n\n".join(
    (
        "[bold]Quick Start[/bold]",
        "gqlsleuth scan https://example.com",
        "gqlsleuth scan https://example.com --mode active",
        "gqlsleuth scan https://example.com --ai",
        "gqlsleuth scan https://example.com -f html -o ./reports",
        "",
        "[bold]Common scan options[/bold]",
        "--mode  safe|active (default: safe)",
        "--format, -f  json|markdown|html; comma-separated or repeated",
        "--output, -o  report output directory",
        "--ai  optional local Ollama/qwen3:8b interpretation",
        "--verbose, -v  detailed console output",
        "--help, -h  help; use gqlsleuth scan -h for complete scan options",
    )
)


def _status(value: str) -> Text:
    if value in {"success", "enabled", "parsed", "confirmed", "probable"}:
        style = "gql.positive"
    elif value in {"http_error", "network_failure", "failed", "invalid_response", "endpoint_error"}:
        style = "gql.error"
    else:
        style = "gql.warning"
    return Text(value.upper(), style=style)


def _table(*columns: str) -> Table:
    # Structural spacing belongs to the renderer, not invisible top/bottom table edges.
    return Table(
        *columns, box=box.SIMPLE, show_edge=False, header_style="gql.heading", padding=(0, 1)
    )


def _section(console: Console, title: str) -> None:
    console.print()
    console.print(title, style="gql.section")


def _render_table(console: Console, table: Table) -> None:
    console.print()
    console.print(table)


def render_error(console: Console, message: str, *, label: str = "Error") -> None:
    console.print(Text.assemble((f"{label}: ", "gql.error"), message))


def render_active_gate(console: Console) -> None:
    console.print(
        "ACTIVE mode: use only against systems you are authorized to test.", style="gql.warning"
    )


def render_state_warning(console: Console) -> None:
    console.print()
    console.print(
        Panel(
            "WARNING: These operations may modify application state.",
            border_style="gql.warning",
            padding=(0, 1),
        )
    )


def render_scan(
    console: Console, result: SafeExecutionScanResult, *, verbose: bool = False
) -> None:
    generation = result.query_generation
    analysis = generation.operation_analysis
    schema_scan = analysis.schema_scan
    introspection = schema_scan.introspection
    discovery = introspection.detection.discovery
    overview = Table.grid(padding=(0, 2))
    overview.add_row("Target", Text(discovery.target.original_url, style="gql.metadata"))
    overview.add_row("Mode", Text(discovery.mode.value.upper(), style="gql.heading"))
    console.print(Panel(overview, title="GQLSleuth", border_style="gql.metadata"))
    introspections = {item.endpoint: item for item in introspection.introspections}
    schemas = {item.endpoint: item for item in schema_scan.schemas}
    analyses = {item.endpoint: item for item in analysis.endpoints}
    if not introspection.detection.detections:
        console.print("No GraphQL detection results retained.", style="gql.warning")
    for detected in introspection.detection.detections:
        console.print(
            Text.assemble(("Endpoint: ", "gql.heading"), (detected.candidate_url, "gql.metadata"))
        )
        console.print(Text.assemble("GraphQL: ", _status(detected.confidence.value)))
        if verbose:
            console.print(detected.reason, markup=False)
        probe = next(
            (item for item in discovery.probes if item.candidate_url == detected.candidate_url),
            None,
        )
        if probe and probe.error_type:
            render_error(console, probe.error_message or probe.error_type, label="Discovery")
        if detected.post_error_type:
            render_error(
                console, detected.post_error_message or detected.post_error_type, label="Detection"
            )
        tested = introspections.get(detected.candidate_url)
        if tested:
            console.print(Text.assemble("Introspection: ", _status(tested.status.value)))
            if verbose or tested.status.value != "enabled":
                console.print(tested.reason, markup=False)
        else:
            console.print("Introspection: not attempted", style="gql.secondary")
        schema = schemas.get(detected.candidate_url)
        if schema:
            _render_schema(console, schema, verbose=verbose)
        else:
            console.print("Schema: not parsed", style="gql.secondary")
        endpoint_analysis = analyses.get(detected.candidate_url)
        if endpoint_analysis:
            _render_analysis(console, endpoint_analysis, verbose=verbose)
        queries = tuple(
            item for item in generation.queries if item.endpoint == detected.candidate_url
        )
        if queries:
            _render_queries(console, queries, verbose=verbose)
        executions = tuple(
            item for item in result.executions if item.endpoint == detected.candidate_url
        )
        if executions:
            _render_executions(console, executions, verbose=verbose)
    console.print(
        "Review priorities are not vulnerability severities or vulnerability confirmation. "
        "Execution success is not proof of a vulnerability.",
        style="gql.secondary",
    )


def _render_schema(console: Console, result: EndpointSchemaResult, *, verbose: bool) -> None:
    if not result.success or result.summary is None:
        render_error(
            console, result.error_message or "Unknown parsing error.", label="Schema FAILED"
        )
        return
    summary = result.summary
    console.print(Text.assemble("Schema: ", _status("parsed")))
    table = _table("Types", "Queries", "Mutations", "Subscriptions")
    table.add_row(
        str(summary.total_type_count),
        str(summary.query_field_count),
        str(summary.mutation_field_count),
        str(summary.subscription_field_count),
    )
    _render_table(console, table)
    if verbose:
        for label, root in (
            ("Query", summary.query_root),
            ("Mutation", summary.mutation_root),
            ("Subscription", summary.subscription_root),
        ):
            if root is not None:
                console.print(f"{label} root: {root}", markup=False)


def _render_analysis(
    console: Console, result: EndpointOperationAnalysisResult, *, verbose: bool
) -> None:
    _section(console, "Security Review")
    if not result.success:
        render_error(
            console, result.error_message or "Unknown analysis error.", label="Analysis FAILED"
        )
        return
    candidates = result.review_candidates
    console.print(
        f"{len(result.operations)} root operation(s); {len(candidates)} review candidate(s)."
    )
    if not candidates:
        console.print(
            "No operations matched the bundled security-interest rules.", style="gql.secondary"
        )
        return
    visible = candidates if verbose else candidates[:10]
    table = _table("Interest", "Kind", "Operation", "Score")
    for item in visible:
        table.add_row(
            priority_label(item.priority, compact=True),
            Text(item.kind.value.title()),
            Text(item.name),
            str(item.interest_score),
        )
    _render_table(console, table)
    if len(visible) < len(candidates):
        console.print(
            f"... {len(candidates) - len(visible)} additional review candidate(s); "
            "use --verbose or a report for details.",
            style="gql.secondary",
        )
    if verbose:
        for item in visible:
            console.print()
            console.print(
                Text.assemble(
                    priority_label(item.priority),
                    f" [{item.kind.value}] {item.name} - interest score {item.interest_score}",
                )
            )
            console.print(
                "Categories: " + ", ".join(c.value for c in item.categories), markup=False
            )
            for match in item.matched_rules:
                console.print(
                    f"  {match.rule_id}: {', '.join(match.matched_keywords)} "
                    f"at {', '.join(match.locations)}",
                    markup=False,
                )
                console.print("    Why: " + match.reason, markup=False)


def _render_queries(
    console: Console, results: tuple[QueryGenerationResult, ...], *, verbose: bool
) -> None:
    _section(console, "Generated Queries")
    generated = sum(item.success for item in results)
    console.print(
        f"{generated}/{len(results)} generated; {len(results) - generated} generation failures."
    )
    if not verbose:
        return
    for item in results:
        console.print()
        console.print(Text(item.operation_name, style="gql.heading"))
        if not item.success:
            render_error(
                console,
                item.failure_reason or "Unknown generation error.",
                label="Generation FAILED",
            )
            continue
        _document(console, item.query_text or "")
        if item.variables:
            console.print("Variables: " + dumps(item.variables, sort_keys=True), markup=False)
        for note in item.manual_adjustments:
            console.print("Note: " + note, markup=False, style="gql.warning")


def _render_executions(
    console: Console, results: tuple[QueryExecutionResult, ...], *, verbose: bool
) -> None:
    _section(console, "Query Execution")
    counts = Counter(item.status for item in results)
    console.print(
        f"Attempted {sum(item.attempted for item in results)}; "
        f"Success {counts[QueryExecutionStatus.SUCCESS]}; "
        f"GraphQL errors {counts[QueryExecutionStatus.GRAPHQL_ERROR]}"
    )
    console.print(
        f"Safety skips {counts[QueryExecutionStatus.SKIPPED_SAFETY]}; "
        f"Limit skips {counts[QueryExecutionStatus.SKIPPED_LIMIT]}"
    )
    for status in (
        QueryExecutionStatus.HTTP_ERROR,
        QueryExecutionStatus.INVALID_RESPONSE,
        QueryExecutionStatus.NETWORK_FAILURE,
    ):
        if counts[status]:
            console.print(Text.assemble(_status(status.value), f": {counts[status]}"))
    noteworthy = tuple(item for item in results if item.status is not QueryExecutionStatus.SUCCESS)
    visible = results if verbose else noteworthy[:5]
    if visible:
        table = _table("Operation", "Outcome", "HTTP")
        for item in visible:
            table.add_row(
                Text(item.operation_name),
                _status(item.status.value),
                str(item.response.status_code) if item.response else "-",
            )
        _render_table(console, table)
    if verbose:
        for item in results:
            if item.attempted:
                _render_execution_response(
                    console,
                    item.operation_name,
                    item.status.value,
                    item.response,
                    error_message=item.error_message,
                )
            else:
                console.print(f"{item.operation_name}: {item.reason}", markup=False)
    elif len(noteworthy) > len(visible):
        console.print(
            f"... {len(noteworthy) - len(visible)} additional outcomes; use --verbose or a report.",
            style="gql.secondary",
        )


def _document(console: Console, document: str) -> None:
    console.print(
        Syntax(document, "graphql", theme="ansi_dark", background_color="default", word_wrap=True)
    )


def render_mutations(
    console: Console,
    candidates: tuple[tuple[int, MutationPreview], ...],
    *,
    title: str,
) -> None:
    """Group endpoints in first-seen order without changing any candidate index."""
    _section(console, title)
    groups: dict[str, list[tuple[int, MutationPreview]]] = {}
    for index, candidate in candidates:
        groups.setdefault(candidate.generated_mutation.endpoint, []).append((index, candidate))
    for group_index, (endpoint, entries) in enumerate(groups.items()):
        if group_index:
            console.print()
        console.print(Text.assemble("Endpoint: ", (endpoint, "gql.metadata")))
        for position, (index, candidate) in enumerate(entries):
            if position:
                console.print()
            render_mutation(console, index, candidate)


def render_mutation(console: Console, index: int, candidate: MutationPreview) -> None:
    """Always show complete authorization-relevant artifacts, independent of verbosity."""
    artifact = candidate.generated_mutation
    priority = priority_label(artifact.operation.priority)
    label = (
        priority if candidate.selectable else _status(candidate.decision.value.replace("_", " "))
    )
    console.print(
        Text.assemble(f"[{index}] ", label, (f" {artifact.operation_name}", "gql.heading"))
    )
    if not candidate.selectable:
        console.print(Text.assemble("Priority: ", priority))
    console.print(
        "Categories: " + ", ".join(item.value for item in artifact.operation.categories),
        markup=False,
    )
    if not candidate.selectable:
        console.print(candidate.reason, markup=False, style="gql.warning")
        return
    _document(console, artifact.query_text or "")
    console.print("Variables: " + dumps(artifact.variables, sort_keys=True), markup=False)
    console.print("Placeholder values may require manual adjustment.", style="gql.warning")
    for note in artifact.manual_adjustments:
        console.print("Warning: " + note, markup=False, style="gql.warning")


def render_active_execution(console: Console, result: ActiveExecutionScanResult) -> None:
    attempted = tuple(item for item in result.executions if item.attempted)
    statuses = Counter(item.status for item in attempted)
    _section(console, "Mutation Execution")
    summary = Text(f"{len(attempted)} executed")
    for status in QueryExecutionStatus:
        if statuses[status]:
            summary.append(f"; {statuses[status]} ")
            summary.append(_status(status.value))
    summary.append(".")
    console.print(summary)
    if any(item.decision is MutationDecision.DECLINED for item in result.executions):
        console.print(
            "Batch confirmation declined; no Mutations were executed.", style="gql.warning"
        )
    for item in result.executions:
        artifact = item.preview.generated_mutation
        if item.attempted:
            duration = next(
                (
                    fact.duration_seconds
                    for fact in result.execution_evidence
                    if fact.endpoint == artifact.endpoint
                    and fact.query == artifact.query_text
                    and fact.variables == artifact.variables
                ),
                None,
            )
            _render_execution_response(
                console,
                artifact.operation_name,
                item.status.value if item.status else "Not recorded",
                item.response,
                duration_seconds=duration,
                error_message=item.error_message,
            )
        elif item.selected and item.decision is not MutationDecision.DECLINED:
            outcome = item.status.value if item.status is not None else item.decision.value
            console.print(
                Text.assemble(
                    item.preview.generated_mutation.operation_name + ": ", _status(outcome)
                )
            )
    console.print(
        "Mutation execution results are evidence, not vulnerability confirmation.",
        style="gql.secondary",
    )


def _render_execution_response(
    console: Console,
    operation: str,
    status: str,
    response: HttpResponse | None,
    *,
    duration_seconds: float | None = None,
    error_message: str | None = None,
) -> None:
    console.print()
    console.print(Text.assemble((operation + " - ", "gql.heading"), _status(status)))
    view = present_response(response, status, duration_seconds=duration_seconds)
    console.print("Response", style="gql.response")
    console.print(Text("; ".join(f"{key}: {value}" for key, value in view.details)))
    if view.body is None:
        console.print("No HTTP response was received; no server response body is available.")
        if error_message:
            error = present_response_body(error_message.encode("utf-8"))
            console.print(Text(error.text or error.notice or ""))
    else:
        if view.body.notice:
            console.print(view.body.notice, style="gql.warning")
        if view.body.text:
            console.print(
                Syntax(
                    view.body.text,
                    view.body.language,
                    theme="ansi_dark",
                    background_color="default",
                    word_wrap=True,
                )
            )


def render_ai(console: Console, result: AIInterpretationResult, *, verbose: bool = False) -> None:
    _section(console, "AI-Assisted Interpretation")
    console.print(AI_NOTICE, markup=False, style="gql.secondary")
    console.print(f"Model: {result.model}", markup=False)
    if result.status is not AIAnalysisStatus.SUCCESS:
        console.print(
            f"AI assistance {result.status.value}: {result.error_message}",
            markup=False,
            style="gql.warning",
        )
        console.print("Deterministic scan completed normally.")
        return
    console.print(Text.assemble("AI status: ", _status(result.status.value)))
    interpretation = result.interpretation
    if interpretation is None:
        return
    _section(console, "Execution Summary (validated facts)")
    facts = _table("Scope", "Validated facts")
    facts.expand = True
    facts.columns[0].ratio = 1
    facts.columns[1].ratio = 3
    # Keep the canonical, validated summary clauses intact; do not ask AI to count or recount.
    for clause in interpretation.scan_summary.text.split(". "):
        scope, separator, values = clause.partition(": ")
        facts.add_row(
            Text(scope if separator else "Summary"), Text(values if separator else clause)
        )
    _render_table(console, facts)
    collections = (
        (
            "Review Focus",
            tuple(((item.operation,), item.explanation) for item in interpretation.review_focus),
        ),
        (
            "Operation Explanations",
            tuple(
                ((item.operation,), item.explanation)
                for item in interpretation.operation_explanations
            ),
        ),
        (
            "Manual Review Suggestions",
            tuple(
                (item.operations, item.text) for item in interpretation.manual_review_suggestions
            ),
        ),
        ("Limitations", tuple((item.operations, item.text) for item in interpretation.limitations)),
    )
    for title, entries in collections:
        _section(console, title)
        if not entries:
            console.print("  None supplied.", style="gql.secondary")
            continue
        table = _table("Operation", "Interpretation")
        for references, prose in entries if verbose else entries[:5]:
            table.add_row(
                Text("\n".join(references) or "-", style="gql.metadata"),
                style_priority_terms(prose),
            )
        _render_table(console, table)
        if not verbose and len(entries) > 5:
            console.print(
                "  Additional entries available with --verbose or in reports.",
                style="gql.secondary",
            )


def render_reports(console: Console, paths: tuple[Path, ...]) -> None:
    _section(console, "Reports")
    table = Table.grid(padding=(0, 2))
    for path in paths:
        label = "Markdown" if path.suffix == ".md" else path.suffix[1:].upper()
        table.add_row(Text(label, style="gql.heading"), Text(str(path), overflow="fold"))
    console.print(table)
