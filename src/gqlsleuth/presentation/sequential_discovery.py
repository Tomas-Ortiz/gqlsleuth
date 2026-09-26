"""Explicit adjacent-ID preview and concise outcomes, without business response bodies."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gqlsleuth.domain.sequential_discovery import SEQUENTIAL_NOTICE, SequentialDiscoveryResult
from gqlsleuth.presentation.capabilities import capability_wording
from gqlsleuth.presentation.console import _document, _section


def render_sequential_discovery(
    console: Console,
    result: SequentialDiscoveryResult,
    *,
    preview: bool = False,
    verbose: bool = False,
) -> None:
    _section(console, "Bounded Sequential Object Discovery")
    console.print(
        Text(
            "Current supplied HTTP context."
            if result.has_supplied_context_headers
            else "Without user-supplied target headers."
        )
    )
    if preview:
        console.print(f"Maximum planned requests: {len(result.probes)} (hard limit: 6).")
    else:
        console.print(
            f"Confirmed: {result.confirmed}; {result.attempted_request_count} requests; "
            f"{len(result.candidates)} review candidate(s)."
        )
    for seed in result.seeds:
        console.print(Text(f"Seed {seed.index}: query {seed.operation}", style="gql.metadata"))
        console.print(Text(f"Operator-supplied seed: {seed.argument}={seed.identifier}"))
        table = Table(box=None, padding=(0, 1))
        for column in ("ID", "Source", "Planned" if preview else "Outcome"):
            table.add_column(column)
        for probe in result.probes:
            if probe.seed != seed:
                continue
            execution = next((item for item in result.executions if item.probe == probe), None)
            table.add_row(
                probe.requested_identifier,
                "baseline" if probe.offset == 0 else f"generated offset {probe.offset:+d}",
                "baseline"
                if preview and probe.offset == 0
                else "only if baseline returns exact object"
                if preview
                else execution.outcome.value.upper()
                if execution and execution.outcome
                else "NOT_ATTEMPTED",
            )
            if preview or verbose:
                _document(console, probe.query)
                console.print(Text("Variables: " + json.dumps(probe.variables, sort_keys=True)))
                if execution:
                    console.print(Text(execution.reason))
                    if execution.evidence:
                        console.print(
                            Text(
                                f"HTTP: {execution.evidence.response_status_code}; "
                                f"Evidence: {execution.evidence.evidence_id}"
                            )
                        )
        console.print(table)
        for item in result.candidates:
            if item.seed == seed:
                console.print(
                    Text(f"ADJACENT_OBJECT_ACCESS: {item.generated_identifier}. {item.reason}")
                )
    for limitation in result.limitations:
        console.print(Text(limitation))
    console.print(Text(capability_wording(SEQUENTIAL_NOTICE)))
