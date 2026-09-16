"""Compact nested review outcomes without raw business responses or HTTP configuration."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gqlsleuth.domain.nested_authorization import NESTED_NOTICE, NestedAuthorizationResult
from gqlsleuth.presentation.console import _document, _section


def render_nested_authorization(
    console: Console, result: NestedAuthorizationResult, *, verbose: bool = False
) -> None:
    _section(console, "Nested Authorization Review")
    console.print(
        f"{len(result.candidates)} candidate path(s); "
        f"{result.request_count} additional read-only requests."
    )
    for index, candidate in enumerate(result.candidates, 1):
        console.print(
            Text(
                f"{candidate.base.endpoint} / query {candidate.base.operation_name}",
                style="gql.metadata",
            )
        )
        console.print(Text("Path: " + ".".join(candidate.path)))
        table = Table(box=None, padding=(0, 1))
        table.add_column("Context")
        table.add_column("Outcome")
        table.add_column("HTTP")
        for item in result.executions:
            if item.candidate_index == index:
                table.add_row(
                    Text(item.context),
                    item.outcome.value.upper() if item.outcome else "NOT_ATTEMPTED",
                    str(item.evidence.response_status_code) if item.evidence else "—",
                )
                if verbose:
                    console.print(Text(item.reason))
        console.print(table)
        for pair in result.pairs:
            if pair.candidate_index == index:
                console.print(
                    Text(
                        f"{pair.context_a} ↔ {pair.context_b}: "
                        f"{pair.kind.value.upper()}. {pair.reason}"
                    )
                )
        if verbose:
            console.print(
                Text("Rules: " + ", ".join(item.rule_id for item in candidate.matched_rules))
            )
            if candidate.query:
                _document(console, candidate.query)
                console.print(
                    Text("Variables: " + json.dumps(candidate.base.variables, sort_keys=True))
                )
    for limitation in result.limitations:
        console.print(Text(limitation))
    console.print(Text(NESTED_NOTICE))
