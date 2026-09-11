"""CLI options, workflow orchestration, and explicit ACTIVE user interaction."""

import re
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from gqlsleuth import __version__
from gqlsleuth.application.active_execution import (
    ActiveExecutionScanResult,
    ActiveMutationPreviewResult,
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.application.reporting import generate_reports
from gqlsleuth.application.safe_execution import SafeExecutionScanResult, run_safe_execution_scan
from gqlsleuth.domain.active import MAX_MUTATION_EXECUTIONS
from gqlsleuth.domain.exceptions import GQLSleuthError, ReportingError
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.presentation.console import (
    CONSOLE_THEME,
    ROOT_HELP_EPILOG,
    render_active_execution,
    render_active_gate,
    render_ai,
    render_error,
    render_mutations,
    render_reports,
    render_scan,
    render_state_warning,
)
from gqlsleuth.reporting.models import ReportFormat

app = typer.Typer(
    name="gqlsleuth",
    help=(
        "Authorized GraphQL security discovery and analysis. "
        "Use only against systems you are explicitly authorized to test."
    ),
    epilog=ROOT_HELP_EPILOG,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["--help", "-h"]},
    no_args_is_help=True,
    add_completion=False,
)
console = Console(theme=CONSOLE_THEME)
error_console = Console(stderr=True, theme=CONSOLE_THEME)


@app.command()
def version() -> None:
    """Show the installed GQLSleuth version."""
    console.print(f"GQLSleuth {__version__}")


def _parse_formats(values: list[str] | None) -> tuple[ReportFormat, ...]:
    """Normalize CLI syntax only; serialization remains owned by reporting."""
    formats: list[ReportFormat] = []
    for value in values or ():
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                raise typer.BadParameter(
                    "Empty report format; choose json, markdown, or html.",
                    param_hint="--format / -f",
                )
            try:
                format = ReportFormat(entry)
            except ValueError:
                raise typer.BadParameter(
                    f"Unsupported report format '{entry}'; choose json, markdown, or html.",
                    param_hint="--format / -f",
                ) from None
            if format not in formats:
                formats.append(format)
    return tuple(formats)


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(
            metavar="TARGET", help="HTTP(S) application URL or direct GraphQL endpoint."
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
        list[str] | None,
        typer.Option(
            "--format",
            "-f",
            metavar="json|markdown|html",
            help=(
                "Write reports after scanning. Accepts comma-separated values and may be repeated."
            ),
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Report output directory (default: ./gqlsleuth-reports)."
        ),
    ] = None,
    ai: Annotated[
        bool,
        typer.Option(
            "--ai",
            help=(
                "Interpret the completed scan using local Ollama/qwen3:8b. "
                "Optional; disabled by default."
            ),
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed analysis, generated Queries, and execution outcomes.",
        ),
    ] = False,
) -> None:
    """Discover and analyze GraphQL; safely execute validated Query operations."""
    report_formats = _parse_formats(formats)
    if output is not None and not report_formats:
        render_error(error_console, "--output / -o requires at least one --format / -f.")
        raise typer.Exit(code=2)
    if mode is ScanMode.ACTIVE:
        render_active_gate(console)
    try:
        result = run_safe_execution_scan(target, mode=mode)
    except GQLSleuthError as error:
        render_error(error_console, str(error))
        raise typer.Exit(code=2) from None

    render_scan(console, result, verbose=verbose)
    schema_scan = result.query_generation.operation_analysis.schema_scan
    mode = schema_scan.introspection.detection.discovery.mode
    report_result: SafeExecutionScanResult | ActiveExecutionScanResult = result
    if mode is ScanMode.ACTIVE:
        report_result = _run_active_stage(result)
    ai_result = None
    if ai:
        console.print("AI assistance: interpreting the completed scan with local qwen3:8b...")
        ai_result = interpret_completed_scan(report_result)
        render_ai(console, ai_result, verbose=verbose)
    if report_formats:
        try:
            paths = generate_reports(
                report_result,
                formats=report_formats,
                output_directory=output,
                ai_interpretation=ai_result,
            )
        except ReportingError as error:
            render_error(error_console, str(error), label="Reporting error")
            raise typer.Exit(code=1) from None
        render_reports(console, paths)


def _interactive_stdin() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def _run_active_stage(safe_result: SafeExecutionScanResult) -> ActiveExecutionScanResult:
    preview = prepare_active_mutations(safe_result)
    render_mutations(
        console, tuple(enumerate(preview.candidates, start=1)), title="Active Mutation candidates:"
    )
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
                render_mutations(
                    console,
                    tuple((index, preview.candidates[index - 1]) for index in selected),
                    title="Selected Mutations:",
                )
                render_state_warning(console)
                confirmed = typer.confirm(
                    f"Execute these {len(selected)} selected Mutations?", default=False
                )
        except (typer.Abort, EOFError, KeyboardInterrupt):
            console.print("Mutation selection/confirmation cancelled; zero Mutations will execute.")
    result = execute_selected_mutations(preview, selected_indices=selected, confirmed=confirmed)
    render_active_execution(console, result)
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


def main() -> None:
    """Run the command-line application."""
    app()
