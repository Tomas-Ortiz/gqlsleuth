"""Command-line interface for safe GraphQL discovery and Query execution."""

import re
import sys
from json import dumps
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from gqlsleuth import __version__
from gqlsleuth.application.active_execution import (
    ActiveExecutionScanResult,
    ActiveMutationPreviewResult,
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.operation_analysis import EndpointOperationAnalysisResult
from gqlsleuth.application.reporting import generate_reports
from gqlsleuth.application.safe_execution import (
    QueryExecutionResult,
    SafeExecutionScanResult,
    run_safe_execution_scan,
)
from gqlsleuth.application.schema_parsing import EndpointSchemaResult
from gqlsleuth.domain.active import MAX_MUTATION_EXECUTIONS, MutationDecision, MutationPreview
from gqlsleuth.domain.analysis import OperationAnalysis
from gqlsleuth.domain.exceptions import GQLSleuthError, ReportingError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.reporting.models import ReportFormat

app = typer.Typer(
    name="gqlsleuth",
    help=(
        "Authorized GraphQL security discovery and analysis. "
        "Use only against systems you are explicitly authorized to test."
    ),
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
error_console = Console(stderr=True)


@app.command()
def version() -> None:
    """Show the installed GQLSleuth version."""
    console.print(f"GQLSleuth {__version__}")


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(
            metavar="TARGET",
            help=(
                "HTTP(S) target for safe GraphQL discovery, introspection, schema parsing, "
                "operation prioritization, and local query generation."
            ),
        ),
    ],
    mode: Annotated[
        ScanMode,
        typer.Option(
            "--mode",
            help=(
                "SAFE is default. ACTIVE acknowledges active capabilities for an authorized "
                "target; Mutations require explicit selection and one final batch confirmation."
            ),
            case_sensitive=False,
        ),
    ] = ScanMode.SAFE,
    formats: Annotated[
        list[ReportFormat] | None,
        typer.Option(
            "--format", help="Write a report after scanning; repeat for multiple formats."
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Report output directory (default: ./gqlsleuth-reports)."),
    ] = None,
) -> None:
    """Discover GraphQL and safely execute validated generated Query operations."""
    if output is not None and not formats:
        error_console.print("[bold red]Error:[/bold red] --output requires at least one --format.")
        raise typer.Exit(code=2)
    if mode is ScanMode.ACTIVE:
        console.print("ACTIVE mode: use only against systems you are authorized to test.")
    try:
        result = run_safe_execution_scan(
            target,
            mode=mode,
        )
    except GQLSleuthError as error:
        error_console.print(f"[bold red]Error:[/bold red] {escape(str(error))}")
        raise typer.Exit(code=2) from None

    console.print(
        "GraphQL discovery, introspection, schema parsing, operation analysis, query generation, "
        "and safe execution completed for "
        f"[cyan]{escape(result.query_generation.operation_analysis.schema_scan.introspection.detection.discovery.target.original_url)}"
        "[/cyan]."
    )
    generation = result.query_generation
    analysis_scan = generation.operation_analysis
    introspection_scan = analysis_scan.schema_scan.introspection
    introspections = {item.endpoint: item for item in introspection_scan.introspections}
    schemas = {item.endpoint: item for item in analysis_scan.schema_scan.schemas}
    analyses = {item.endpoint: item for item in analysis_scan.endpoints}
    generated_by_endpoint: dict[str, list[QueryGenerationResult]] = {}
    for query_result in generation.queries:
        generated_by_endpoint.setdefault(query_result.endpoint, []).append(query_result)
    executions_by_endpoint: dict[str, list[QueryExecutionResult]] = {}
    for execution in result.executions:
        executions_by_endpoint.setdefault(execution.endpoint, []).append(execution)
    for detection in introspection_scan.detection.detections:
        confidence = detection.confidence.value.upper()
        console.print(
            f"[cyan]{escape(detection.candidate_url)}[/cyan] -> "
            f"GraphQL: [bold]{confidence}[/bold] — {escape(detection.reason)}"
        )
        introspection = introspections.get(detection.candidate_url)
        if introspection is not None:
            status = introspection.status.value.upper()
            console.print(
                f"  Introspection: [bold]{status}[/bold] — {escape(introspection.reason)}"
            )
        schema_result = schemas.get(detection.candidate_url)
        if schema_result is not None:
            _render_schema(schema_result)
        analysis = analyses.get(detection.candidate_url)
        if analysis is not None:
            _render_operation_analysis(analysis)
        query_results = generated_by_endpoint.get(detection.candidate_url)
        if query_results is not None:
            _render_query_generation(query_results)
        execution_results = executions_by_endpoint.get(detection.candidate_url)
        if execution_results is not None:
            _render_safe_execution(execution_results)

    successful_queries = sum(query.success for query in generation.queries)
    attempted = sum(execution.attempted for execution in result.executions)
    succeeded = sum(
        execution.status is QueryExecutionStatus.SUCCESS for execution in result.executions
    )
    graphql_errors = sum(
        execution.status is QueryExecutionStatus.GRAPHQL_ERROR for execution in result.executions
    )
    skipped = len(result.executions) - attempted
    console.print(
        f"Analyzed {len(introspection_scan.detection.detections)} candidate(s), tested "
        f"introspection on {len(introspection_scan.introspections)} endpoint(s), processed "
        f"{len(analysis_scan.schema_scan.schemas)} schema result(s), analyzed "
        f"{sum(len(item.operations) for item in analysis_scan.endpoints)} root operation(s), "
        f"generated {successful_queries}/{len(generation.queries)} read-only query artifact(s), "
        f"executed {attempted}, succeeded {succeeded}, received {graphql_errors} GraphQL error "
        f"response(s), and skipped {skipped}. Execution results are evidence, not vulnerability "
        "confirmation; review priorities are not vulnerability severities or vulnerability "
        "confirmation."
    )
    mode = introspection_scan.detection.discovery.mode
    console.print(f"Effective mode: [cyan]{mode.value}[/cyan].")
    report_result: SafeExecutionScanResult | ActiveExecutionScanResult = result
    if mode is ScanMode.ACTIVE:
        report_result = _run_active_stage(result)
    if formats:
        try:
            paths = generate_reports(report_result, formats=tuple(formats), output_directory=output)
        except ReportingError as error:
            error_console.print(f"[bold red]Reporting error:[/bold red] {escape(str(error))}")
            raise typer.Exit(code=1) from None
        for path in paths:
            console.print(f"Report written: {path}", markup=False)


def _interactive_stdin() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def _run_active_stage(safe_result: SafeExecutionScanResult) -> ActiveExecutionScanResult:
    preview = prepare_active_mutations(safe_result)
    console.print("Active Mutation candidates:")
    for index, candidate in enumerate(preview.candidates, start=1):
        _render_mutation(index, candidate)
    selected: tuple[int, ...] = ()
    confirmed = False
    if not preview.candidates:
        console.print("No Mutation candidates.")
    elif not _interactive_stdin():
        console.print(
            "Interactive selection and confirmation are required; zero Mutations will execute."
        )
    elif not any(candidate.selectable for candidate in preview.candidates):
        console.print("No executable Mutation candidates.")
    else:
        try:
            selected = _select_mutations(preview)
            if selected:
                console.print("Selected Mutations:")
                for index in selected:
                    _render_mutation(index, preview.candidates[index - 1])
                console.print("WARNING: These operations may modify application state.")
                confirmed = typer.confirm(
                    f"Execute these {len(selected)} selected Mutations?", default=False
                )
        except (typer.Abort, EOFError, KeyboardInterrupt):
            console.print("Mutation selection/confirmation cancelled; zero Mutations will execute.")
    result = execute_selected_mutations(preview, selected_indices=selected, confirmed=confirmed)
    _render_active_execution(result)
    return result


def _select_mutations(preview: ActiveMutationPreviewResult) -> tuple[int, ...]:
    while True:
        value = typer.prompt(
            "Select Mutations to execute (max 5, Enter for none)", default="", show_default=False
        ).strip()
        if not value:
            return ()
        if re.fullmatch(r"[0-9]+(?:\s*,\s*[0-9]+)*", value) is None:
            console.print("Enter individual comma-separated indices only (for example, 1,3).")
            continue
        # Compare normalized decimal strings first to avoid unbounded integer conversion.
        indices = {str(index): index for index in range(1, len(preview.candidates) + 1)}
        tokens = tuple(token.strip().lstrip("0") or "0" for token in value.split(","))
        if any(token not in indices for token in tokens):
            console.print("Unknown Mutation index; choose only executable candidate indices.")
            continue
        selected = tuple(sorted({indices[token] for token in tokens}))
        if len(selected) > MAX_MUTATION_EXECUTIONS:
            console.print("Select at most 5 Mutations.")
            continue
        if any(not preview.candidates[index - 1].selectable for index in selected):
            console.print("Blocked or failed Mutation candidates cannot be selected.")
            continue
        return selected


def _render_mutation(index: int, candidate: MutationPreview) -> None:
    artifact = candidate.generated_mutation
    priority = artifact.operation.priority.value.replace("_", " ").upper()
    label = priority if candidate.selectable else candidate.decision.value.replace("_", " ").upper()
    console.print(
        f"[{index}] {label} {artifact.operation_name} — {artifact.endpoint}", markup=False
    )
    if not candidate.selectable:
        console.print(candidate.reason, markup=False)
        return
    console.print(
        "Categories: " + ", ".join(item.value for item in artifact.operation.categories),
        markup=False,
    )
    console.print(artifact.query_text or "", markup=False)
    console.print("Variables: " + dumps(artifact.variables, sort_keys=True), markup=False)
    console.print("Placeholder values may require manual adjustment.")
    for note in artifact.manual_adjustments:
        console.print("Warning: " + note, markup=False)


def _render_active_execution(result: ActiveExecutionScanResult) -> None:
    candidates = result.preview.candidates
    executed = sum(item.attempted for item in result.executions)
    selected = sum(item.selected for item in result.executions)
    succeeded = sum(item.status is QueryExecutionStatus.SUCCESS for item in result.executions)
    graphql_errors = sum(
        item.status is QueryExecutionStatus.GRAPHQL_ERROR for item in result.executions
    )
    blocked = sum(item.decision is MutationDecision.BLOCKED_SAFETY for item in candidates)
    console.print(
        f"Active Mutation execution: {len(candidates)} identified; "
        f"{sum(item.generated_mutation.success for item in candidates)} generated; "
        f"{blocked} blocked for safety; "
        f"{selected} selected; {selected if result.confirmed else 0} confirmed; "
        f"{executed} executed; {succeeded} succeeded; {graphql_errors} GraphQL error(s)."
    )
    for item in result.executions:
        if not item.selected:
            continue
        status = item.status.value if item.status is not None else item.decision.value
        console.print(
            f"  {item.preview.generated_mutation.operation_name}: {status.upper()}", markup=False
        )
    console.print("Mutation execution results are evidence, not vulnerability confirmation.")


def _render_schema(schema_result: EndpointSchemaResult) -> None:
    if not schema_result.success or schema_result.summary is None:
        message = schema_result.error_message or "Unknown schema parsing error."
        console.print(f"  Schema: [bold]FAILED[/bold] — {escape(message)}")
        return
    summary = schema_result.summary
    console.print("  Schema: [bold]PARSED[/bold]")
    console.print(f"    Query root: {escape(summary.query_root)}")
    if summary.mutation_root is not None:
        console.print(f"    Mutation root: {escape(summary.mutation_root)}")
    if summary.subscription_root is not None:
        console.print(f"    Subscription root: {escape(summary.subscription_root)}")
    console.print(
        f"    Types: {summary.total_type_count}; Queries: {summary.query_field_count}; "
        f"Mutations: {summary.mutation_field_count}; "
        f"Subscriptions: {summary.subscription_field_count}"
    )


def _render_operation_analysis(result: EndpointOperationAnalysisResult) -> None:
    if not result.success:
        message = result.error_message or "Unknown operation-analysis error."
        console.print(f"  Operation analysis: [bold]FAILED[/bold] — {escape(message)}")
        return
    candidates = result.review_candidates
    console.print(
        f"  Operation analysis: {len(result.operations)} root operation(s); "
        f"{len(candidates)} security-review candidate(s)."
    )
    if not candidates:
        console.print("    No operations matched the bundled security-interest rules.")
        return
    visible_candidates = candidates[:10]
    for operation in visible_candidates:
        _render_review_candidate(operation)
    omitted = len(candidates) - len(visible_candidates)
    if omitted:
        console.print(f"    … {omitted} additional review candidate(s) omitted from display.")


def _render_review_candidate(operation: OperationAnalysis) -> None:
    priority = operation.priority.value.replace("_", " ").upper()
    kind = escape(f"[{operation.kind.value}]")
    categories = "; ".join(
        category.value.replace("_", " ").title() for category in operation.categories
    )
    console.print(
        f"    [bold]{priority}[/bold] {kind} {escape(operation.name)} "
        f"— interest score {operation.interest_score}"
    )
    console.print(f"      {escape(categories)}")
    for match in operation.matched_rules:
        keywords = ", ".join(match.matched_keywords)
        locations = ", ".join(match.locations)
        console.print(f"      {escape(match.rule_id)}: {escape(keywords)} at {escape(locations)}")
        console.print(f"        Why: {escape(match.reason)}")


def _render_query_generation(results: list[QueryGenerationResult]) -> None:
    successful = [result for result in results if result.success]
    console.print(f"  Generated read-only queries: {len(successful)}/{len(results)}")
    for result in successful[:5]:
        if result.query_text is None:
            continue
        priority = result.operation.priority.value.replace("_", " ").upper()
        kind = escape("[query]")
        console.print(f"    [bold]{priority}[/bold] {kind} {escape(result.operation_name)}")
        console.print(escape(result.query_text))
        if result.variables:
            console.print(f"    Variables: {escape(dumps(result.variables, sort_keys=True))}")
        for adjustment in result.manual_adjustments:
            console.print(f"    Note: {escape(adjustment)}")
    omitted = len(successful) - min(len(successful), 5)
    if omitted:
        console.print(f"    … {omitted} additional generated query artifact(s) omitted.")
    failures = [result for result in results if not result.success]
    for result in failures[:5]:
        reason = result.failure_reason or "Unknown query-generation error."
        kind = escape("[query]")
        console.print(f"    FAILED {kind} {escape(result.operation_name)} — {escape(reason)}")


def _render_safe_execution(results: list[QueryExecutionResult]) -> None:
    attempted = sum(result.attempted for result in results)
    succeeded = sum(result.status is QueryExecutionStatus.SUCCESS for result in results)
    graphql_errors = sum(result.status is QueryExecutionStatus.GRAPHQL_ERROR for result in results)
    skipped_safety = sum(result.status is QueryExecutionStatus.SKIPPED_SAFETY for result in results)
    skipped_limit = sum(result.status is QueryExecutionStatus.SKIPPED_LIMIT for result in results)
    console.print(
        f"  Safe query execution: {attempted} executed; {succeeded} succeeded; "
        f"{graphql_errors} GraphQL error(s); {skipped_safety} skipped for safety; "
        f"{skipped_limit} skipped by limit."
    )
    for result in results[:8]:
        status = result.status.value.replace("_", " ").upper()
        http_status = (
            f" — HTTP {result.response.status_code}" if result.response is not None else ""
        )
        kind = escape("[query]")
        console.print(
            f"    {kind} {escape(result.operation_name)} — [bold]{status}[/bold]{http_status}"
        )
        if result.status is not QueryExecutionStatus.SUCCESS:
            console.print(f"      {escape(result.reason)}")
    omitted = len(results) - min(len(results), 8)
    if omitted:
        console.print(f"    … {omitted} additional execution result(s) omitted.")


def main() -> None:
    """Run the command-line application."""
    app()
