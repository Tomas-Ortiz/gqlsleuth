"""Reporting is opt-in and runs only after the unchanged SAFE/ACTIVE CLI workflow."""

import json

import httpx
import pytest
from typer.testing import CliRunner

import gqlsleuth.cli as cli
from gqlsleuth.application.active_execution import execute_selected_mutations
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient


@pytest.fixture
def report_cli(phase_ten_scan, monkeypatch, tmp_path):
    safe, _ = phase_ten_scan(mode=ScanMode.SAFE)
    active, _ = phase_ten_scan(mode=ScanMode.ACTIVE)
    calls = []
    mutations = []

    def scan(target, *, mode=ScanMode.SAFE):
        calls.append(mode)
        return active if mode is ScanMode.ACTIVE else safe

    def handler(request):
        mutations.append(json.loads(request.content))
        return httpx.Response(200, json={"data": None})

    def execute(preview, *, selected_indices=(), confirmed=False):
        with HttpClient(transport=httpx.MockTransport(handler)) as client:
            return execute_selected_mutations(
                preview, selected_indices=selected_indices, confirmed=confirmed, client=client
            )

    monkeypatch.setattr(cli, "run_safe_execution_scan", scan)
    monkeypatch.setattr(cli, "execute_selected_mutations", execute)
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    monkeypatch.chdir(tmp_path)
    return calls, mutations


def invoke(*options, input=""):
    return CliRunner().invoke(cli.app, ["scan", "https://example.com", *options], input=input)


def test_no_format_creates_nothing_and_preserves_safe_console_output(report_cli, tmp_path):
    baseline = invoke()
    assert baseline.exit_code == 0
    assert list(tmp_path.iterdir()) == []
    reported = invoke("--format", "json")
    assert reported.exit_code == 0
    assert reported.stdout.split("Report written:")[0] == baseline.stdout
    paths = list((tmp_path / "gqlsleuth-reports").iterdir())
    assert len(paths) == 1
    assert paths[0].suffix == ".json"
    assert json.loads(paths[0].read_text(encoding="utf-8"))["mode"] == "safe"
    assert report_cli == ([ScanMode.SAFE, ScanMode.SAFE], [])


def test_multiple_formats_and_explicit_directory_write_one_file_per_format(report_cli, tmp_path):
    result = invoke(
        "--format",
        "json",
        "--format",
        "markdown",
        "--format",
        "html",
        "--format",
        "json",
        "--output",
        "custom/nested",
    )
    assert result.exit_code == 0
    assert {path.suffix for path in (tmp_path / "custom/nested").iterdir()} == {
        ".json",
        ".md",
        ".html",
    }
    assert result.stdout.count("Report written:") == 3
    assert not (tmp_path / "gqlsleuth-reports").exists()


@pytest.mark.parametrize("options", [("--output", "reports"), ("--format", "pdf")])
def test_invalid_reporting_options_fail_before_scanning(report_cli, tmp_path, options):
    result = invoke(*options)
    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert report_cli == ([], [])
    assert list(tmp_path.iterdir()) == []


def test_active_empty_selection_reports_previews_without_mutation_requests(report_cli, tmp_path):
    baseline = invoke("--mode", "active", input="\n")
    result = invoke("--mode", "active", "--format", "json", "--format", "html", input="\n")
    assert baseline.exit_code == result.exit_code == 0
    assert result.stdout.split("Report written:")[0] == baseline.stdout
    assert result.stdout.count("Select Mutations to execute") == 1
    assert "Execute these" not in result.stdout
    report = json.loads(
        next((tmp_path / "gqlsleuth-reports").glob("*.json")).read_text(encoding="utf-8")
    )
    assert report["mode"] == "active"
    assert report["active"]["candidates"]
    assert report["active"]["selected_indices"] == []
    assert not report["active"]["confirmed"]
    assert report["summary"]["mutation_execution_count"] == 0
    assert any(
        item["preview_decision"] == "blocked_safety" for item in report["active"]["candidates"]
    )
    assert report_cli[1] == []


def test_active_selected_confirmation_and_http_behavior_are_unchanged(report_cli, tmp_path):
    baseline = invoke("--mode", "active", input="1\ny\n")
    before = list(report_cli[1])
    result = invoke("--mode", "active", "--format", "json", input="1\ny\n")
    assert baseline.exit_code == result.exit_code == 0
    assert result.stdout.split("Report written:")[0] == baseline.stdout
    assert result.stdout.count("Execute these 1 selected Mutations?") == 1
    assert report_cli[1] == before + before
    report = json.loads(
        next((tmp_path / "gqlsleuth-reports").glob("*.json")).read_text(encoding="utf-8")
    )
    assert report["active"]["confirmed"]
    assert report["summary"]["mutation_execution_count"] == 1
    assert sum(item["evidence_type"] == "mutation_execution" for item in report["evidence"]) == 1


def test_report_write_failure_occurs_after_scan_with_concise_error(report_cli, tmp_path):
    path = tmp_path / "occupied"
    path.write_text("existing file", encoding="utf-8")
    result = invoke("--format", "json", "--output", str(path))
    assert result.exit_code == 1
    assert "safe execution completed" in result.stdout
    assert "Reporting error:" in result.stderr
    assert "Traceback" not in result.output
    assert path.read_text(encoding="utf-8") == "existing file"
    assert report_cli == ([ScanMode.SAFE], [])


def test_noninteractive_active_reporting_never_reads_selection_or_confirms(
    report_cli, tmp_path, monkeypatch
):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    result = invoke("--mode", "active", "--format", "json", input="1\ny\n")
    assert result.exit_code == 0
    assert "Select Mutations to execute" not in result.stdout
    assert "Execute these" not in result.stdout
    report = json.loads(
        next((tmp_path / "gqlsleuth-reports").glob("*.json")).read_text(encoding="utf-8")
    )
    assert report["active"]["selected_indices"] == []
    assert report["active"]["confirmed"] is False
    assert report["summary"]["mutation_execution_count"] == 0
    assert report_cli[1] == []
