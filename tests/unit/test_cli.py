"""Tests for the Phase 0 command-line scaffold."""

from typer.testing import CliRunner

from gqlsleuth import __version__
from gqlsleuth.cli import app

runner = CliRunner()


def test_root_help_describes_authorized_use() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Authorized GraphQL security discovery and analysis" in result.stdout
    assert "explicitly authorized" in result.stdout
    assert "scan" in result.stdout
    assert "version" in result.stdout


def test_version_command_reports_package_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"GQLSleuth {__version__}"


def test_scan_command_is_a_successful_non_networking_placeholder() -> None:
    target = "https://example.com"

    result = runner.invoke(app, ["scan", target])

    assert result.exit_code == 0
    assert "Phase 0 placeholder" in result.stdout
    assert "no scan or network request was performed" in result.stdout
    assert target in result.stdout


def test_scan_command_requires_a_target() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "Missing argument 'TARGET'" in result.stderr
