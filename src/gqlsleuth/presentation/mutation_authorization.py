"""Full state-changing request preview and concise exact-policy outcomes."""

import json

from rich.console import Console
from rich.text import Text

from gqlsleuth.domain.mutation_authorization import (
    MUTATION_AUTHORIZATION_NOTICE,
    MutationAuthorizationResult,
)
from gqlsleuth.presentation.console import _document, _section


def render_mutation_authorization(
    console: Console,
    result: MutationAuthorizationResult,
    *,
    preview: bool = False,
) -> None:
    _section(console, "Mutation Authorization Validation")
    console.print(
        Text(
            "Current request context: supplied HTTP context"
            if result.has_supplied_context_headers
            else "Current request context: without user-supplied target headers"
        )
    )
    for case in result.cases:
        console.print(Text(f"Mutation: {case.operation}", style="gql.metadata"))
        console.print(Text(f"Identifier argument: {case.argument}"))
        console.print(Text(f"Target identifier: {json.dumps(case.identifier, ensure_ascii=False)}"))
    console.print("Operator-supplied expected authorization policy: DENY")
    if preview:
        console.print("Maximum requests: 1")
        if result.probe:
            console.print(Text(result.probe.endpoint, style="gql.metadata"))
            _document(console, result.probe.query)
            console.print(
                Text(
                    "Variables:\n"
                    + json.dumps(
                        result.probe.variables, indent=2, ensure_ascii=False, sort_keys=True
                    )
                )
            )
            for note in result.probe.manual_adjustments:
                console.print(Text(note))
            console.print("This request may modify server-side state.", style="gql.warning")
    else:
        console.print(
            f"Confirmed: {result.confirmed}; attempted requests: {result.attempted_request_count}"
        )
        console.print(
            "Observed: "
            + (result.execution.outcome.value.upper() if result.execution else "NOT_ATTEMPTED")
        )
        if result.evaluation:
            console.print("Result: " + result.evaluation.status.value.upper())
            console.print(Text(result.evaluation.reason))
        if result.violation:
            console.print("MUTATION_AUTHORIZATION_POLICY_VIOLATION")
    for limitation in result.limitations:
        console.print(Text(limitation))
    console.print(Text(MUTATION_AUTHORIZATION_NOTICE))
