"""Compact exact-object outcomes, without unrelated returned business data."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gqlsleuth.domain.object_authorization import OBJECT_NOTICE, ObjectAuthorizationResult
from gqlsleuth.presentation.console import _document, _section


def render_object_authorization(
    console: Console, result: ObjectAuthorizationResult, *, verbose: bool = False
) -> None:
    _section(console, "Controlled Object Authorization Validation")
    console.print(
        f"{len(result.cases)} case(s); "
        f"{result.attempted_request_count} additional read-only requests."
    )
    for case in result.cases:
        console.print(Text(f"Case {case.index}: query {case.operation}", style="gql.metadata"))
        console.print(
            Text(f"Identifier: {case.argument}={json.dumps(case.identifier, ensure_ascii=False)}")
        )
        if case.declared_authorized_context:
            console.print(
                Text("Operator-declared authorized context: " + case.declared_authorized_context)
            )
        table = Table(box=None, padding=(0, 1))
        for column in ("Context", "Supplied request context", "Outcome"):
            table.add_column(column)
        for item in result.executions:
            if item.case_index == case.index:
                table.add_row(
                    Text(item.context.name),
                    "supplied" if item.context.has_supplied_context_headers else "none",
                    item.outcome.value.upper() if item.outcome else "NOT_ATTEMPTED",
                )
                if verbose:
                    http_status = (
                        item.evidence.response_status_code if item.evidence else "not observed"
                    )
                    console.print(
                        Text(
                            f"{item.context.name}: {item.reason}; "
                            f"id match: {item.returned_id_matches}; "
                            f"HTTP: {http_status}"
                        )
                    )
                    if item.evidence:
                        console.print(Text(f"Evidence: {item.evidence.evidence_id}"))
        console.print(table)
        for candidate in result.candidates:
            if candidate.case.index == case.index:
                console.print(
                    Text(
                        f"{candidate.kind.value.upper()} ({candidate.observed_context}): "
                        f"{candidate.reason}"
                    )
                )
        if verbose:
            for probe in result.probes:
                if probe.case == case:
                    console.print(Text(probe.endpoint, style="gql.metadata"))
                    console.print("Structural source: OBJECT_LOOKUP_REVIEW")
                    _document(console, probe.query)
                    console.print(Text("Variables: " + json.dumps(probe.variables, sort_keys=True)))
    for limitation in result.limitations:
        console.print(Text(limitation))
    console.print(Text(OBJECT_NOTICE))
