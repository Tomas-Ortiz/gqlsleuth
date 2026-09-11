"""Offline Phase 13 ergonomics and console-only behavior boundaries."""

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO

import pytest
from rich.console import Console
from typer.testing import CliRunner

import gqlsleuth.application.reporting as reporting
import gqlsleuth.cli as cli
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_scan
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.mark.parametrize("command", [[], ["scan"]])
@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_aliases_describe_main_workflow(command, flag):
    result = CliRunner().invoke(cli.app, [*command, flag])
    assert result.exit_code == 0
    output = " ".join(result.stdout.split())
    for option in (
        "--mode",
        "--format",
        "-f",
        "--output",
        "-o",
        "--ai",
        "--verbose",
        "-v",
        "--help",
        "-h",
    ):
        assert option in output
    assert "comma-separated" in output
    if not command:
        assert "scan" in output and "version" in output
        assert "Quick Start" in output and "Common scan options" in output
        assert "gqlsleuth scan https://example.com" in output
    else:
        assert "TARGET" in output
        assert "disabled by default" in output


@pytest.fixture
def completed_cli(phase_ten_scan, monkeypatch, tmp_path):
    fields = " ".join(f"account{chr(65 + i)}: String" for i in range(12))
    safe, requests = phase_ten_scan(
        f"type Query {{ {fields} readAndBurn: String }}", mode=ScanMode.SAFE
    )
    before = deepcopy(safe)
    target_requests = deepcopy(requests)
    calls = []

    def scan(target, *, mode=ScanMode.SAFE):
        calls.append((target, mode))
        return safe

    monkeypatch.setattr(cli, "run_safe_execution_scan", scan)
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Presentation sent HTTP"))
    monkeypatch.setattr(
        cli, "interpret_completed_scan", lambda *args: pytest.fail("AI was not requested")
    )
    monkeypatch.setattr(
        reporting,
        "build_report",
        lambda result, **kwargs: build_report(
            result, generated_at=datetime(2026, 9, 11, tzinfo=UTC), **kwargs
        ),
    )
    monkeypatch.chdir(tmp_path)
    yield safe, calls
    assert safe == before
    assert requests == target_requests


def invoke(*options):
    return CliRunner().invoke(cli.app, ["scan", "https://example.com", *options])


@pytest.mark.parametrize(
    "options,extensions",
    [
        (("--format", "json"), [".json"]),
        (("-f", "json"), [".json"]),
        (("--format", "json,html"), [".json", ".html"]),
        (("-f", "json,html"), [".json", ".html"]),
        (("-f", "json", "-f", "html"), [".json", ".html"]),
        (("-f", "json,html", "--format", "markdown", "-f", "json"), [".json", ".html", ".md"]),
        (("-f", " json , html , json "), [".json", ".html"]),
    ],
)
def test_format_syntax_writes_once_in_first_occurrence_order(
    completed_cli, tmp_path, monkeypatch, options, extensions
):
    written = []
    generate = cli.generate_reports

    def reports(result, **kwargs):
        written.extend(generate(result, **kwargs))
        return tuple(written)

    monkeypatch.setattr(cli, "generate_reports", reports)
    result = invoke(*options, "-o", "custom")
    assert result.exit_code == 0
    assert [path.suffix for path in written] == extensions
    assert len(list((tmp_path / "custom").iterdir())) == len(extensions)
    assert all(path.parent == tmp_path / "custom" for path in written)
    assert len(completed_cli[1]) == 1


@pytest.mark.parametrize(
    "entry", ["", " ", ",json", "json,", "json,,html", "json, ,html", "json,pdf"]
)
def test_invalid_format_fails_before_scanning(completed_cli, tmp_path, entry):
    result = invoke("-f", entry)
    assert result.exit_code == 2
    output = " ".join(result.stderr.replace("│", " ").split())
    assert "choose json," in output
    assert "markdown, or html" in output
    assert ("pdf" if "pdf" in entry else "Empty report format") in output
    assert "Traceback" not in result.output
    assert completed_cli[1] == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("flag", ["--output", "-o"])
def test_output_requires_formats_without_changing_verbosity(completed_cli, tmp_path, flag):
    invalid = invoke(flag, "reports")
    assert invalid.exit_code == 2
    assert "requires at least one" in invalid.stderr
    assert completed_cli[1] == []
    baseline = invoke()
    reported = invoke(flag, "reports", "-f", "json")
    assert baseline.stdout == reported.stdout.split("\nReports\n")[0]


def test_compact_and_verbose_leave_results_requests_and_all_report_formats_identical(
    completed_cli, tmp_path
):
    compact = invoke("-f", "json,markdown,html", "-o", "compact")
    verbose = invoke("-v", "-f", "json,markdown,html", "-o", "verbose")
    long_verbose = invoke("--verbose")
    assert compact.exit_code == verbose.exit_code == long_verbose.exit_code == 0
    assert "Why:" not in compact.stdout
    assert "query {" not in compact.stdout
    assert "2 additional review candidate(s)" in compact.stdout
    assert "use --verbose or a report" in compact.stdout
    assert "Why:" in verbose.stdout and "query {" in verbose.stdout
    assert "Query name contains explicit state-changing" in verbose.stdout
    assert len(compact.stdout) < len(verbose.stdout)
    assert verbose.stdout.split("\nReports\n")[0] == long_verbose.stdout
    for path in (tmp_path / "compact").iterdir():
        assert path.read_bytes() == (tmp_path / "verbose" / path.name).read_bytes()
    assert len(completed_cli[1]) == 3


@pytest.mark.parametrize("width", [45, 80])
def test_plain_narrow_console_wraps_without_mutating_or_interpreting_target_markup(
    completed_cli, width
):
    safe = completed_cli[0]
    stream = StringIO()
    console = Console(file=stream, width=width, color_system=None, theme=CONSOLE_THEME)
    stamp = datetime(2026, 9, 11, tzinfo=UTC)
    before = render_report(build_report(safe, generated_at=stamp), ReportFormat.JSON)
    render_scan(console, safe)
    text = stream.getvalue()
    assert "GraphQL: CONFIRMED" in text
    assert "Query Execution" in text
    assert "\x1b[" not in text
    assert "Success 12;" in text
    assert "... 2 additional" in text
    assert max(map(len, text.splitlines())) <= width
    assert render_report(build_report(safe, generated_at=stamp), ReportFormat.JSON) == before


def test_partial_schema_failure_is_not_rendered_as_parsed(completed_cli):
    safe = completed_cli[0]
    analysis = safe.query_generation.operation_analysis
    schema_scan = analysis.schema_scan
    failure = replace(
        schema_scan.schemas[0],
        success=False,
        schema=None,
        error_message="[bold]Fake parsing error[/bold]",
    )
    safe = replace(
        safe,
        query_generation=replace(
            safe.query_generation,
            queries=(),
            operation_analysis=replace(
                analysis, endpoints=(), schema_scan=replace(schema_scan, schemas=(failure,))
            ),
        ),
        executions=(),
        execution_evidence=(),
    )
    stream = StringIO()
    render_scan(Console(file=stream, theme=CONSOLE_THEME), safe)
    assert "Schema FAILED" in stream.getvalue()
    assert "Schema: PARSED" not in stream.getvalue()
    assert "[bold]Fake parsing error[/bold]" in stream.getvalue()
