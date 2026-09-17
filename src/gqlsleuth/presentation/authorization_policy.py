"""Policy outcomes clearly attributed to operator assertions, without response bodies."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gqlsleuth.domain.authorization_policy import (
    POLICY_NOTICE,
    AuthorizationPolicyResult,
    PolicyStatus,
)
from gqlsleuth.presentation.capabilities import capability_wording
from gqlsleuth.presentation.console import _section


def render_authorization_policy(
    console: Console, result: AuthorizationPolicyResult, *, verbose: bool = False
) -> None:
    _section(console, "Authorization Policy Validation")
    console.print(
        f"{len(result.assertions)} operator-supplied DENY assertion(s); "
        f"{len(result.violations)} policy violation(s); zero additional target requests."
    )
    table = Table(box=None, padding=(0, 1))
    for name in ("Case / Query", "Context", "Expected", "Observed", "Result"):
        table.add_column(name)
    for item in result.evaluations:
        table.add_row(
            Text(f"{item.case.index} / {item.case.operation}", style="gql.metadata"),
            Text(item.assertion.context),
            "DENY",
            item.observed.value.upper() if item.observed else "NOT_OBSERVED",
            Text(
                item.status.value.upper(),
                style="bold red" if item.status is PolicyStatus.VIOLATED else "",
            ),
        )
    console.print(table)
    for item in result.evaluations:
        if verbose or item.status is PolicyStatus.VIOLATED:
            prefix = (
                "AUTHORIZATION_POLICY_VIOLATION: " if item.status is PolicyStatus.VIOLATED else ""
            )
            console.print(
                Text(
                    f"Case {item.case.index}, context {item.assertion.context}: "
                    f"{prefix}{capability_wording(item.reason)}"
                )
            )
        if verbose:
            console.print(
                Text(
                    f"Identifier: {item.case.argument}="
                    f"{json.dumps(item.case.identifier, ensure_ascii=False)}"
                )
            )
            for identifier in item.source_evidence_ids:
                console.print(Text(f"Object authorization evidence: {identifier}"))
    for limitation in result.limitations:
        console.print(Text(capability_wording(limitation)))
    console.print(Text(capability_wording(POLICY_NOTICE)))
