"""Coordinate reporting after scanning; never start or repeat any scan stage."""

from pathlib import Path

from gqlsleuth.application.active_execution import ActiveExecutionScanResult
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.exceptions import ReportingError
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.output import write_reports

DEFAULT_REPORT_DIRECTORY = Path("gqlsleuth-reports")


def generate_reports(
    result: SafeExecutionScanResult | ActiveExecutionScanResult,
    *,
    formats: tuple[ReportFormat, ...],
    output_directory: Path | None = None,
) -> tuple[Path, ...]:
    """Build one context for all requested formats, leaving the scan result untouched."""
    if not formats:
        return ()
    try:
        context = build_report(result)
    except (TypeError, ValueError, RecursionError) as error:
        raise ReportingError(f"Could not build report context: {type(error).__name__}.") from error
    return write_reports(context, formats, output_directory or DEFAULT_REPORT_DIRECTORY)
