"""Command-line interface for safe GraphQL discovery and operation analysis."""

from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from gqlsleuth import __version__
from gqlsleuth.application.operation_analysis import (
    EndpointOperationAnalysisResult,
    run_operation_analysis_scan,
)
from gqlsleuth.application.schema_parsing import EndpointSchemaResult
from gqlsleuth.domain.analysis import OperationAnalysis
from gqlsleuth.domain.exceptions import GQLSleuthError
from gqlsleuth.domain.models import ScanMode

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
                "and operation prioritization."
            ),
        ),
    ],
    mode: Annotated[
        ScanMode,
        typer.Option(
            "--mode",
            help="Scan mode. ACTIVE performs the same safe behavior in Phase 7.",
            case_sensitive=False,
        ),
    ] = ScanMode.SAFE,
) -> None:
    """Discover and prioritize GraphQL operations for authorized manual review."""
    try:
        result = run_operation_analysis_scan(
            target,
            mode=mode,
        )
    except GQLSleuthError as error:
        error_console.print(f"[bold red]Error:[/bold red] {escape(str(error))}")
        raise typer.Exit(code=2) from None

    console.print(
        "GraphQL discovery, introspection, schema parsing, and operation analysis completed for "
        f"[cyan]{escape(result.schema_scan.introspection.detection.discovery.target.original_url)}"
        "[/cyan]."
    )
    introspection_scan = result.schema_scan.introspection
    introspections = {item.endpoint: item for item in introspection_scan.introspections}
    schemas = {item.endpoint: item for item in result.schema_scan.schemas}
    analyses = {item.endpoint: item for item in result.endpoints}
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

    console.print(
        f"Analyzed {len(introspection_scan.detection.detections)} candidate(s), tested "
        f"introspection on {len(introspection_scan.introspections)} endpoint(s), processed "
        f"{len(result.schema_scan.schemas)} schema result(s), and analyzed "
        f"{sum(len(item.operations) for item in result.endpoints)} root operation(s). "
        "Review priorities are not vulnerability severities or vulnerability confirmation."
    )
    mode = introspection_scan.detection.discovery.mode
    console.print(f"Effective mode: [cyan]{mode.value}[/cyan].")
    if mode is ScanMode.ACTIVE:
        console.print("ACTIVE mode uses the same safe operation-analysis behavior in Phase 7.")


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
    keywords = sorted(
        {keyword for match in operation.matched_rules for keyword in match.matched_keywords}
    )
    rules = ", ".join(match.rule_id for match in operation.matched_rules)
    console.print(
        f"    [bold]{priority}[/bold] {kind} {escape(operation.name)} "
        f"— interest score {operation.interest_score}"
    )
    console.print(f"      {escape(categories)}")
    console.print(f"      Matched: {escape(', '.join(keywords))} (rules: {escape(rules)})")
    console.print(f"      Why: {escape('; '.join(operation.reasons))}")


def main() -> None:
    """Run the command-line application."""
    app()
