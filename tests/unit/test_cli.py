"""Tests for stable CLI behavior and Phase 3 discovery delegation."""

import pytest
from typer.testing import CliRunner

import gqlsleuth.cli as cli_module
from gqlsleuth import __version__
from gqlsleuth.application.endpoint_discovery import (
    EndpointDiscoveryResult,
    EndpointProbeResult,
)
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.infrastructure.http import HttpResponse

runner = CliRunner()
app = cli_module.app


@pytest.fixture(autouse=True)
def discovery_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ScanMode]]:
    """Keep CLI tests offline while recording application-service delegation."""
    calls: list[tuple[str, ScanMode]] = []

    def fake_discovery(
        target_url: str,
        *,
        mode: ScanMode = ScanMode.SAFE,
    ) -> EndpointDiscoveryResult:
        target = Target.parse(target_url)
        calls.append((target_url, mode))
        candidate_url = f"{target.scheme}://{target.host}/graphql"
        response = HttpResponse(
            request_url=candidate_url,
            final_url=candidate_url,
            status_code=404,
            headers={},
            body=b"",
            duration_seconds=0,
            redirect_count=0,
        )
        return EndpointDiscoveryResult(
            target=target,
            mode=mode,
            probes=(EndpointProbeResult(candidate_url=candidate_url, response=response),),
            evidence=(),
        )

    monkeypatch.setattr(cli_module, "run_endpoint_discovery", fake_discovery)
    return calls


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


def test_scan_command_runs_safe_endpoint_discovery() -> None:
    target = "https://example.com"

    result = runner.invoke(app, ["scan", target])

    assert result.exit_code == 0
    assert "Endpoint candidate discovery completed" in result.stdout
    assert "HTTP 404" in result.stdout
    assert "Probed 1 endpoint candidate(s)" in result.stdout
    assert "No GraphQL confirmation was performed" in result.stdout
    assert target in result.stdout
    assert "Effective mode: safe" in result.stdout


def test_scan_command_requires_a_target() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "Missing argument 'TARGET'" in result.stderr


def test_scan_help_exposes_current_discovery_options() -> None:
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
    assert "No GraphQL confirmation was performed" in result.stdout


def test_scan_accepts_active_with_the_same_safe_discovery_behavior() -> None:
    result = runner.invoke(app, ["scan", "https://example.com", "--mode", "active"])

    assert result.exit_code == 0
    assert "Effective mode: active" in result.stdout
    assert "same safe discovery behavior" in result.stdout
    assert "No GraphQL confirmation was performed" in result.stdout


def test_scan_reports_invalid_target_without_a_traceback() -> None:
    result = runner.invoke(app, ["scan", "ftp://example.com"])

    assert result.exit_code == 2
    assert "Unsupported target scheme" in result.stderr
    assert "Traceback" not in result.stderr


def test_scan_delegates_target_and_mode_to_discovery(
    discovery_calls: list[tuple[str, ScanMode]],
) -> None:
    result = runner.invoke(app, ["scan", "https://example.com"])

    assert result.exit_code == 0
    assert discovery_calls == [("https://example.com", ScanMode.SAFE)]
