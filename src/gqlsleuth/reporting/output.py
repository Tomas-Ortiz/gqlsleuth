"""UTF-8 report files with normalized filenames and exclusive, non-overwriting creation."""

import re
from itertools import count
from pathlib import Path

from gqlsleuth.domain.exceptions import ReportingError
from gqlsleuth.reporting.models import ReportContext, ReportFormat
from gqlsleuth.reporting.renderers import render_report


def write_reports(
    context: ReportContext,
    formats: tuple[ReportFormat, ...],
    output_directory: Path,
) -> tuple[Path, ...]:
    """Render before writing; repeated formats are deduplicated in request order."""
    rendered = [(format, render_report(context, format)) for format in dict.fromkeys(formats)]
    if not rendered:
        return ()
    written: list[Path] = []
    try:
        directory = output_directory.resolve()
        directory.mkdir(parents=True, exist_ok=True)
        host = re.sub(r"[^a-z0-9.-]+", "-", context.target.host.casefold())
        host = re.sub(r"\.{2,}", "-", host).strip(".-")[:80] or "target"
        stem = f"gqlsleuth-{host}-{context.generated_at:%Y%m%d-%H%M%S}"
        for format, contents in rendered:
            extension = "md" if format is ReportFormat.MARKDOWN else format.value
            for number in count(1):
                suffix = "" if number == 1 else f"-{number}"
                path = directory / f"{stem}{suffix}.{extension}"
                try:
                    stream = path.open("x", encoding="utf-8", newline="\n")
                except FileExistsError:
                    continue
                with stream:
                    stream.write(contents)
                written.append(path)
                break
    except (OSError, ValueError, UnicodeError) as error:
        completed = ", ".join(str(path) for path in written) or "none"
        raise ReportingError(
            f"Could not write reports to '{output_directory}': {type(error).__name__}. "
            f"Completed reports: {completed}."
        ) from error
    return tuple(written)
