"""Command-line interface for the Phase 0 project scaffold."""

from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from gqlsleuth import __version__

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
) -> None:
    """A Phase 0 placeholder that performs no scanning or network activity."""
    console.print(
        "[bold yellow]Phase 0 placeholder:[/bold yellow] "
        f"no scan or network request was performed for [cyan]{escape(target)}[/cyan]."
    )


def main() -> None:
    """Run the command-line application."""
    app()
