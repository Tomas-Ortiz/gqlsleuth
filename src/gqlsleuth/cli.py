"""Command-line interface preserved through the Phase 2 HTTP layer."""

from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from gqlsleuth import __version__
from gqlsleuth.application.scan_configuration import map_scan_inputs
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
            help="Target URL reserved for a future scanning phase.",
        ),
    ],
    mode: Annotated[
        ScanMode,
        typer.Option(
            "--mode",
            help="Configuration mode. ACTIVE performs no active behavior in Phase 2.",
            case_sensitive=False,
        ),
    ] = ScanMode.SAFE,
) -> None:
    """Validate inputs without performing scanning or network activity."""
    try:
        validated_target, settings = map_scan_inputs(
            target,
            mode=mode,
        )
    except GQLSleuthError as error:
        error_console.print(f"[bold red]Error:[/bold red] {escape(str(error))}")
        raise typer.Exit(code=2) from None

    console.print("[bold yellow]Phase 0 placeholder:[/bold yellow] retained through Phase 2.")
    console.print(
        "no scan or network request was performed for "
        f"[cyan]{escape(validated_target.original_url)}[/cyan]."
    )
    console.print(f"Effective mode: [cyan]{settings.mode.value}[/cyan].")
    if settings.mode is ScanMode.ACTIVE:
        console.print("ACTIVE mode is configuration-only; no active behavior was performed.")


def main() -> None:
    """Run the command-line application."""
    app()
