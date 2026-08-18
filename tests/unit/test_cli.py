"""Tests for the Phase 0 CLI behavior and Phase 1 input mapping."""

from typing import Never

import httpx
import pytest
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
    assert "Effective mode: safe" in result.stdout


def test_scan_command_requires_a_target() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "Missing argument 'TARGET'" in result.stderr


def test_scan_help_exposes_phase_one_configuration_options() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "--mode" in result.stdout
    assert "safe" in result.stdout
    assert "active" in result.stdout
    assert "--config" not in result.stdout


def test_scan_accepts_explicit_safe_mode() -> None:
    result = runner.invoke(app, ["scan", "https://example.com", "--mode", "safe"])

    assert result.exit_code == 0
    assert "Effective mode: safe" in result.stdout
    assert "no scan or network request was performed" in result.stdout


def test_scan_accepts_active_as_configuration_only() -> None:
    result = runner.invoke(app, ["scan", "https://example.com", "--mode", "active"])

    assert result.exit_code == 0
    assert "Effective mode: active" in result.stdout
    assert "configuration-only" in result.stdout
    assert "no scan or network request was performed" in result.stdout


def test_scan_reports_invalid_target_without_a_traceback() -> None:
    result = runner.invoke(app, ["scan", "ftp://example.com"])

    assert result.exit_code == 2
    assert "Unsupported target scheme" in result.stderr
    assert "Traceback" not in result.stderr


def test_scan_command_does_not_construct_an_http_client(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_http_client(*args: object, **kwargs: object) -> Never:
        raise AssertionError("scan must remain non-networking during Phase 2")

    monkeypatch.setattr(httpx, "Client", unexpected_http_client)

    result = runner.invoke(app, ["scan", "https://example.com"])

    assert result.exit_code == 0
    assert "no scan or network request was performed" in result.stdout
