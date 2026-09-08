"""Command-line interface for safe GraphQL discovery and Query execution."""

from json import dumps
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from gqlsleuth import __version__
from gqlsleuth.application.operation_analysis import EndpointOperationAnalysisResult
from gqlsleuth.application.safe_execution import (
    QueryExecutionResult,
    run_safe_execution_scan,
)
from gqlsleuth.application.schema_parsing import EndpointSchemaResult
from gqlsleuth.domain.analysis import OperationAnalysis
from gqlsleuth.domain.exceptions import GQLSleuthError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.query_generation import QueryGenerationResult

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
            help="Scan mode. ACTIVE performs the same safe behavior in Phase 9.",
            case_sensitive=False,
        ),
    ] = ScanMode.SAFE,
) -> None:
    """Discover GraphQL and safely execute validated generated Query operations."""
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
    if mode is ScanMode.ACTIVE:
        console.print("ACTIVE mode uses the same safe Query-only execution behavior in Phase 9.")


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
