"""Compact bounded replay previews and outcomes without response or header dumps."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gqlsleuth.domain.abuse_controls import AbuseControlResult
from gqlsleuth.presentation.console import _document, _section
from gqlsleuth.presentation.priorities import priority_label


def render_abuse_controls(
    console: Console, result: AbuseControlResult, *, preview: bool = False, verbose: bool = False
) -> None:
    _section(console, "Rate Limiting & Abuse Controls")
    console.print(Text(result.operator_policy))
    candidates = (result.selected,) if result.selected else result.candidates
    for position, candidate in enumerate(candidates):
        if position:
            console.print()
        console.print(
            Text(
                f"[{candidate.index}] {candidate.operation.kind.value.title()} "
                f"{candidate.operation.name} — {candidate.endpoint}",
                style="cyan",
            )
        )
        console.print(priority_label(candidate.operation.priority))
        console.print(
            Text(
                "Categories: "
                + ", ".join(c.value.replace("_", " ") for c in candidate.operation.categories)
            )
        )
        console.print(
            Text(
                f"Existing baseline: {candidate.baseline_status.value.upper()} / "
                f"HTTP {candidate.baseline_http_status}. "
                f"Planned repeats: {candidate.planned_attempts}."
            )
        )
        if candidate.mutation_warning:
            console.print(Text(candidate.mutation_warning, style="gql.warning"))
        if result.selected and (preview or verbose):
            _document(console, candidate.query)
            console.print(
                Text("Variables: " + json.dumps(candidate.variables, sort_keys=True, indent=2))
            )
    if preview:
        console.print("Sequential exact repeats only; no concurrency, retries or threshold search.")
    else:
        console.print(
            Text(
                f"Confirmed: {result.confirmed}; {result.attempted_request_count} requests; "
                f"result: {result.policy_result.value.upper()}."
            )
        )
        table = Table(box=None, padding=(0, 1))
        for title in ("Attempt", "Outcome", "Signal", "Execution", "HTTP"):
            table.add_column(title)
        for item in result.attempts:
            table.add_row(
                str(item.attempt_index),
                item.outcome.value.upper(),
                item.signal.kind.value.upper() if item.signal else "—",
                item.repeat_status.value.upper(),
                str(item.response_status_code or "—"),
            )
        if result.attempts:
            console.print(table)
        if result.first_signal_attempt:
            console.print(f"First explicit control signal: attempt {result.first_signal_attempt}.")
        for finding in result.findings:
            console.print(
                Text("Finding: Rate limiting / abuse-control weakness. " + finding.reason)
            )
        if verbose:
            for item in result.attempts:
                if item.signal:
                    console.print(
                        Text(
                            f"Attempt {item.attempt_index}: {item.signal.source}: "
                            + item.signal.matched_rule
                        )
                    )
    for limitation in result.limitations:
        console.print(Text(limitation))
    console.print(Text(result.scope_limitation))
