"""Command-line interface for safe endpoint candidate discovery."""

from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from gqlsleuth import __version__
from gqlsleuth.application.endpoint_discovery import run_endpoint_discovery
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
            help="HTTP(S) target for safe endpoint candidate discovery.",
        ),
    ],
    mode: Annotated[
        ScanMode,
        typer.Option(
            "--mode",
            help="Discovery mode. ACTIVE performs the same safe GET probes in Phase 3.",
            case_sensitive=False,
        ),
    ] = ScanMode.SAFE,
) -> None:
    """Discover possible GraphQL endpoint locations using safe GET requests."""
    try:
        result = run_endpoint_discovery(
            target,
            mode=mode,
        )
    except GQLSleuthError as error:
        error_console.print(f"[bold red]Error:[/bold red] {escape(str(error))}")
        raise typer.Exit(code=2) from None

    console.print(
        "Endpoint candidate discovery completed for "
        f"[cyan]{escape(result.target.original_url)}[/cyan]."
    )
    for probe in result.probes:
        if probe.response is not None:
            console.print(
                f"[cyan]{escape(probe.candidate_url)}[/cyan] -> "
                f"HTTP [bold]{probe.response.status_code}[/bold]"
            )
        else:
            error_type = escape(probe.error_type or "HttpError")
            console.print(
                f"[cyan]{escape(probe.candidate_url)}[/cyan] -> "
                f"[yellow]transport failure ({error_type})[/yellow]"
            )

    console.print(
        f"Probed {len(result.probes)} endpoint candidate(s). No GraphQL confirmation was performed."
    )
    console.print(f"Effective mode: [cyan]{result.mode.value}[/cyan].")
    if result.mode is ScanMode.ACTIVE:
        console.print("ACTIVE mode uses the same safe discovery behavior in Phase 3.")


def main() -> None:
    """Run the command-line application."""
    app()
