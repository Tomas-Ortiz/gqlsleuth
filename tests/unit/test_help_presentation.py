"""Root help layout stays separate from generated scan help and command behavior."""

from io import StringIO

import pytest
from rich.console import Console
from rich.style import Style
from typer.main import get_command
from typer.testing import CliRunner

import gqlsleuth.cli as cli
from gqlsleuth.presentation.console import CONSOLE_THEME, render_root_help

COMMANDS = (
    "gqlsleuth scan https://example.com",
    "gqlsleuth scan https://example.com --mode active",
    "gqlsleuth scan https://example.com --ai",
    "gqlsleuth scan https://example.com -f html -o ./reports",
)
OPTIONS = (
    "--mode",
    "-f, --format",
    "-o, --output",
    "--ai",
    "-v, --verbose",
    "-H, --header",
    "--timeout",
    "--proxy",
    "--verify-tls",
    "--no-verify-tls",
)
HELP_COMMANDS = (
    ("version", "Show the installed GQLSleuth version."),
    ("scan", "Discover and analyze GraphQL; safely execute validated Query operations."),
)


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_root_help_keeps_structure_commands_and_one_scan_help_hint(flag):
    result = CliRunner().invoke(cli.app, [flag])
    assert result.exit_code == 0
    output = result.stdout
    labels = (
        "Usage:",
        "Authorized GraphQL",
        "Options",
        "Commands",
        "Common options",
        "Quick Start",
    )
    assert [output.index(label) for label in labels] == sorted(
        output.index(label) for label in labels
    )
    examples, hint = output.split("Quick Start\n", 1)[1].split("\n\nRun ", 1)
    assert examples.strip().splitlines() == list(COMMANDS)
    command_panel = output.split("Commands", 1)[1].split("Quick Start", 1)[0]
    assert command_panel.index("version") < command_panel.index("scan")
    assert command_panel.index("scan") < command_panel.index("Common options")
    options = command_panel.split("Common options", 1)[1]
    for option in OPTIONS:
        assert option in options
    assert "--help" not in options.split() and "-h" not in options.split()
    assert hint.strip() == "gqlsleuth scan --help for all scan options."
    assert "Common scan options" not in output
    assert "Target HTTP options do not affect local Ollama." not in output


@pytest.mark.parametrize("width", [45, 60, 80])
def test_root_guidance_wraps_without_blank_rows_or_trailing_padding(width):
    stream = StringIO()
    console = Console(file=stream, width=width, color_system=None, theme=CONSOLE_THEME)
    render_root_help(console, HELP_COMMANDS)
    output = stream.getvalue()
    assert max(map(len, output.splitlines())) <= width
    assert all(line == line.rstrip() for line in output.splitlines())
    assert "\n\n\n" not in output
    command_panel = output.split("Quick Start", 1)[0]
    table = command_panel.split("Common options", 1)[1]
    # Ignore panel right padding and its closing border, not option-row spacing.
    table = "\n".join(line.strip(" \u2502|") for line in table.splitlines()[1:-2])
    assert all(line.strip() for line in table.splitlines())
    for option in OPTIONS:
        assert option in table
    rows = table.splitlines()
    # Wrapped descriptions stay within their option row, before the next option starts.
    for option, word in (("--mode", "safe"), ("--proxy", "Explicit"), ("--timeout", "Target")):
        assert any(option in row and word in row for row in rows)
    scan_line = next(line for line in command_panel.splitlines() if "scan" in line)
    options_line = next(line for line in command_panel.splitlines() if "--mode" in line)
    assert options_line.index("--mode") > scan_line.index("scan")


def test_help_headings_are_neutral_and_references_cyan(monkeypatch):
    console = Console(file=StringIO(), width=100, theme=CONSOLE_THEME)
    segments = []
    original_print = console.print

    def collect(*objects, **kwargs):
        with console.capture() as captured:
            original_print(*objects, **kwargs)
        # Also render the actual Text/table rows to inspect styles without ANSI snapshots.
        for value in objects:
            if isinstance(value, str):
                if value == "Quick Start":
                    assert console.get_style(kwargs["style"]) == Style.parse("bold bright_white")
            else:
                segments.extend(console.render(value))
        assert captured.get() is not None

    monkeypatch.setattr(console, "print", collect)
    render_root_help(console, HELP_COMMANDS)
    references = [
        segment for segment in segments if "gqlsleuth" in segment.text or "--proxy" in segment.text
    ]
    assert len(references) >= 6
    assert all(segment.style.color.name == "cyan" for segment in references)
    headings = [segment for segment in segments if "Common options" in segment.text]
    assert headings and all(
        segment.style == Style.parse("bold bright_white") for segment in headings
    )
    commands = [segment for segment in segments if segment.text.strip() in {"version", "scan"}]
    assert len(commands) == 2
    assert all(segment.style.color.name == "cyan" for segment in commands)


def test_custom_guidance_is_root_only():
    result = CliRunner().invoke(cli.app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Quick Start" not in result.stdout and "Common options" not in result.stdout
    assert "Target HTTP" in result.stdout
    for option in (
        "--mode",
        "--ai",
        "--format",
        "--output",
        "--verbose",
        "--header",
        "--timeout",
        "--proxy",
        "--verify-tls",
        "--no-verify-tls",
    ):
        assert option in result.stdout


def test_root_help_preserves_command_registry_and_uses_command_descriptions():
    root = get_command(cli.app)
    commands = root.commands.copy()
    with (
        root.make_context("gqlsleuth", [], resilient_parsing=True) as context,
        cli.console.capture() as captured,
    ):
        root.format_help(context, context.make_formatter())
    assert root.commands == commands
    assert all(root.commands[name] is command for name, command in commands.items())
    assert "Show the installed GQLSleuth version." in captured.get()
    assert "Common options" in captured.get()


@pytest.mark.parametrize("width", [45, 60])
def test_complete_root_help_on_narrow_terminal(monkeypatch, width):
    from typer import rich_utils

    original_console = rich_utils._get_rich_console

    def narrow_console(*args, **kwargs):
        console = original_console(*args, **kwargs)
        console.width = width
        return console

    monkeypatch.setattr(rich_utils, "_get_rich_console", narrow_console)
    monkeypatch.setattr(cli, "console", Console(width=width, theme=CONSOLE_THEME))
    result = CliRunner().invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert max(map(len, result.stdout.splitlines())) <= width
    for title in ("Options", "Commands", "Quick Start", "Common options"):
        assert title in result.stdout
    assert "gqlsleuth scan --help" in result.stdout


def test_scan_help_documents_defaults_without_duplicate_metadata():
    result = CliRunner().invoke(cli.app, ["scan", "--help"])
    assert result.exit_code == 0
    output = " ".join(result.stdout.replace("│", " ").replace("|", " ").split())
    assert output.lower().count("default:") == 10
    assert "[default:" not in output.lower()
    for text in (
        "Default: safe.",
        "Default: discovery 8s, other target requests 10s.",
        "An explicit value applies to all target stages.",
        "Default: enabled.",
        "Default: ./gqlsleuth-reports when reports are requested.",
        "Environment proxies are ignored.",
    ):
        assert text in output


@pytest.mark.parametrize(
    "name,default,description",
    [
        ("mode", "safe", "Default: safe."),
        ("timeout", None, "Default: discovery 8s, other target requests 10s."),
        ("verify_tls", True, "Default: enabled."),
        ("proxy", None, "Default: none."),
        ("headers", None, "Default: none."),
        ("ai", False, "Default: disabled."),
        ("verbose", False, "Default: disabled."),
        ("formats", None, "Default: none."),
        ("output", None, "Default: ./gqlsleuth-reports when reports are requested."),
        ("auth_context", None, "Default: disabled."),
    ],
)
def test_default_descriptions_belong_to_the_right_options_without_changing_values(
    name, default, description
):
    scan = get_command(cli.app).commands["scan"]
    parameter = next(item for item in scan.params if item.name == name)
    assert parameter.default == default
    assert description in parameter.help
