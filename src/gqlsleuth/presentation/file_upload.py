"""Explicit upload metadata and logical request preview, never local bytes or parent paths."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gqlsleuth.domain.file_upload import UPLOAD_LIMITATION, UPLOAD_WARNING, FileUploadSecurityResult
from gqlsleuth.presentation.console import _document, _section


def render_file_upload(
    console: Console, result: FileUploadSecurityResult, *, preview: bool = False
) -> None:
    _section(console, "File Upload Security")
    plan = result.plan
    if plan:
        console.print(
            Text(f"Mutation: {plan.case.operation} — {plan.operation.endpoint}", style="cyan")
        )
        console.print(Text("Upload path: " + ".".join(plan.case.path)))
        console.print(
            Text(
                f"Baseline ALLOW: {plan.baseline.filename}; {plan.baseline.content_type}; "
                f"{plan.baseline.size} bytes"
            )
        )
        console.print(Text("SHA-256: " + plan.baseline.sha256))
        console.print(
            Text(
                "Selected DENY probes: "
                + (
                    ", ".join(p.value.replace("_", " ") for p in result.selected_variants)
                    or "none (baseline only)"
                )
            )
        )
        console.print(f"Planned requests: {result.planned_request_count} maximum.")
        if preview:
            _document(console, plan.query)
            console.print(
                Text("Operations: " + json.dumps(plan.operations, sort_keys=True, indent=2))
            )
            console.print(Text("Map: " + json.dumps(plan.multipart_map, sort_keys=True)))
            console.print(Text(UPLOAD_WARNING, style="gql.warning"))
            for note in plan.manual_adjustments:
                console.print(Text(note))
    if not preview:
        console.print(
            f"Confirmed: {result.confirmed}; attempted: {result.attempted_request_count}; "
            f"{result.baseline_status.value.upper()}."
        )
        table = Table(box=None)
        for title in ("Probe", "Expected", "Outcome", "Evaluation", "HTTP"):
            table.add_column(title)
        for attempt in result.attempts:
            table.add_row(
                attempt.probe.value.replace("_", " "),
                attempt.expected.value.upper(),
                attempt.outcome.value.upper(),
                attempt.evaluation.value.upper(),
                str(attempt.response_status_code or "—"),
            )
        if result.attempts:
            console.print(table)
        for finding in result.findings:
            console.print(Text("File upload validation weakness: " + finding.reason))
    for reason in result.limitations:
        console.print(Text(reason))
    console.print(Text(UPLOAD_LIMITATION))
