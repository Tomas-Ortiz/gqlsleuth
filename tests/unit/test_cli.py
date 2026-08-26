"""Tests for stable CLI behavior and Phase 5 workflow delegation."""

import pytest
from typer.testing import CliRunner

import gqlsleuth.cli as cli_module
from gqlsleuth import __version__
from gqlsleuth.application.endpoint_discovery import (
    EndpointDiscoveryResult,
    EndpointProbeResult,
)
from gqlsleuth.application.graphql_detection import (
    CandidateDetectionResult,
    GraphQLDetectionResult,
)
from gqlsleuth.application.introspection import (
    EndpointIntrospectionResult,
    IntrospectionScanResult,
)
from gqlsleuth.domain.models import ConfidenceLevel, ScanMode, Target
from gqlsleuth.graphql.introspection import IntrospectionStatus
from gqlsleuth.infrastructure.http import HttpResponse

runner = CliRunner()
app = cli_module.app


@pytest.fixture(autouse=True)
def scan_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ScanMode]]:
    """Keep CLI tests offline while recording application-service delegation."""
    calls: list[tuple[str, ScanMode]] = []

    def fake_scan(
        target_url: str,
        *,
        mode: ScanMode = ScanMode.SAFE,
    ) -> IntrospectionScanResult:
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
        discovery = EndpointDiscoveryResult(
            target=target,
            mode=mode,
            probes=(EndpointProbeResult(candidate_url=candidate_url, response=response),),
            evidence=(),
        )
        detection = CandidateDetectionResult(
            candidate_url=candidate_url,
            get_signals=(),
            post_probe_required=True,
            post_response=response,
            post_signals=(),
            post_error_type=None,
            post_error_message=None,
            confidence=ConfidenceLevel.CONFIRMED,
            reason="Valid data.__typename string.",
        )
        detection_result = GraphQLDetectionResult(
            discovery=discovery,
            detections=(detection,),
            confirmation_evidence=(),
        )
        introspection = EndpointIntrospectionResult(
            endpoint=candidate_url,
            status=IntrospectionStatus.ENABLED,
            minimal_response=response,
            minimal_error_type=None,
            minimal_error_message=None,
            full_retrieval_attempted=True,
            full_response=response,
            full_error_type=None,
            full_error_message=None,
            reason="Full introspection response was retrieved.",
        )
        return IntrospectionScanResult(
            detection=detection_result,
            introspections=(introspection,),
            introspection_evidence=(),
        )

    monkeypatch.setattr(cli_module, "run_introspection_scan", fake_scan)
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


def test_scan_command_runs_safe_introspection_workflow() -> None:
    target = "https://example.com"

    result = runner.invoke(app, ["scan", target])
    output = " ".join(result.stdout.split())

    assert result.exit_code == 0
    assert "GraphQL discovery and introspection completed" in output
    assert "GraphQL: CONFIRMED" in output
    assert "Introspection: ENABLED" in output
    assert "tested introspection on 1 endpoint(s)" in output
    assert "not vulnerability confirmation" in output.lower()
    assert target in output
    assert "Effective mode: safe" in output


def test_scan_command_requires_a_target() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "Missing argument 'TARGET'" in result.stderr


def test_scan_help_exposes_current_scan_options() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "--mode" in result.stdout
    assert "safe" in result.stdout
    assert "active" in result.stdout
    assert "--config" not in result.stdout


def test_scan_accepts_explicit_safe_mode() -> None:
    result = runner.invoke(app, ["scan", "https://example.com", "--mode", "safe"])
    output = " ".join(result.stdout.split())

    assert result.exit_code == 0
    assert "Effective mode: safe" in output
    assert "not vulnerability confirmation" in output


def test_scan_accepts_active_with_the_same_safe_introspection_behavior() -> None:
    result = runner.invoke(app, ["scan", "https://example.com", "--mode", "active"])
    output = " ".join(result.stdout.split())

    assert result.exit_code == 0
    assert "Effective mode: active" in output
    assert "same safe introspection behavior" in output
    assert "not vulnerability confirmation" in output


def test_scan_reports_invalid_target_without_a_traceback() -> None:
    result = runner.invoke(app, ["scan", "ftp://example.com"])

    assert result.exit_code == 2
    assert "Unsupported target scheme" in result.stderr
    assert "Traceback" not in result.stderr


def test_scan_delegates_target_and_mode_to_phase_five_workflow(
    scan_calls: list[tuple[str, ScanMode]],
) -> None:
    result = runner.invoke(app, ["scan", "https://example.com"])

    assert result.exit_code == 0
    assert scan_calls == [("https://example.com", ScanMode.SAFE)]
