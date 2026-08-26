"""Command-line interface for safe GraphQL discovery and introspection."""

from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from gqlsleuth import __version__
from gqlsleuth.application.introspection import run_introspection_scan
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
            help="HTTP(S) target for safe GraphQL discovery and introspection.",
        ),
    ],
    mode: Annotated[
        ScanMode,
        typer.Option(
            "--mode",
            help="Scan mode. ACTIVE performs the same safe behavior in Phase 5.",
            case_sensitive=False,
        ),
    ] = ScanMode.SAFE,
) -> None:
    """Discover GraphQL endpoints and test introspection availability."""
    try:
        result = run_introspection_scan(
            target,
            mode=mode,
        )
    except GQLSleuthError as error:
        error_console.print(f"[bold red]Error:[/bold red] {escape(str(error))}")
        raise typer.Exit(code=2) from None

    console.print(
        "GraphQL discovery and introspection completed for "
        f"[cyan]{escape(result.detection.discovery.target.original_url)}[/cyan]."
    )
    introspections = {item.endpoint: item for item in result.introspections}
    for detection in result.detection.detections:
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

    console.print(
        f"Analyzed {len(result.detection.detections)} candidate(s) and tested introspection "
        f"on {len(result.introspections)} endpoint(s). Results are not vulnerability confirmation."
    )
    mode = result.detection.discovery.mode
    console.print(f"Effective mode: [cyan]{mode.value}[/cyan].")
    if mode is ScanMode.ACTIVE:
        console.print("ACTIVE mode uses the same safe introspection behavior in Phase 5.")


def main() -> None:
    """Run the command-line application."""
    app()
