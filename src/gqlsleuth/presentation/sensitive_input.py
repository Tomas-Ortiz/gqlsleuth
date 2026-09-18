"""Concise local review and complete consent-time state-changing request presentation."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gqlsleuth.domain.sensitive_input import (
    SENSITIVE_REVIEW_NOTICE,
    SENSITIVE_VALIDATION_NOTICE,
    SensitiveInputCandidate,
    SensitiveInputValidationResult,
)
from gqlsleuth.presentation.console import _document, _section


def render_sensitive_review(
    console: Console,
    candidates: tuple[SensitiveInputCandidate, ...],
    *,
    verbose: bool = False,
    context: str | None = None,
) -> None:
    if not candidates:
        return
    _section(console, "Sensitive Input Review")
    if context:
        console.print(Text(f"Context: {context}"))
    console.print(
        f"{len(candidates)} schema-derived review candidate(s); zero additional requests."
    )
    table = Table(box=None, padding=(0, 1))
    for title in ("Mutation", "Input field", "Type", "Review category"):
        table.add_column(title)
    for item in candidates if verbose else candidates[:10]:
        table.add_row(
            item.operation,
            f"{item.argument}.{item.field}",
            item.input_type,
            item.category.value.replace("_", " "),
        )
    console.print(table)
    if verbose:
        for item in candidates:
            console.print()
            console.print(
                Text(
                    f"{item.endpoint} / mutation {item.operation} / {item.argument}.{item.field}",
                    style="gql.metadata",
                )
            )
            console.print(Text(item.reason))
            for fact in item.supporting_facts:
                console.print(Text(fact))
            if item.case_template:
                console.print("Suggested follow-up: --mode active --sensitive-input-review")
                console.print(
                    Text(f'  --sensitive-input-case "{item.case_template}"', style="gql.metadata")
                )
                if item.target_template:
                    console.print(
                        Text(
                            f'  --sensitive-input-target "{item.target_template}"',
                            style="gql.metadata",
                        )
                    )
                console.print(
                    "Supply the exact value and target; schema hints do not establish "
                    "valid runtime values."
                )
    console.print(Text(SENSITIVE_REVIEW_NOTICE))


def render_sensitive_validation(
    console: Console, result: SensitiveInputValidationResult, *, preview: bool = False
) -> None:
    _section(console, "Sensitive Input Validation")
    case = result.case
    console.print(Text(f"Mutation: {case.operation}", style="gql.metadata"))
    console.print(Text(f"Input: {case.argument}.{case.field}"))
    console.print(
        Text(
            "Supplied value: "
            + json.dumps(
                result.probe.typed_value if result.probe else case.value, ensure_ascii=False
            )
        )
    )
    console.print(
        Text(
            f"Target: {case.target.argument}="
            f"{json.dumps(case.target.identifier, ensure_ascii=False)}"
            if case.target
            else "Target: current object (no direct ID argument)"
        )
    )
    console.print("Operator policy: DENY")
    console.print(
        "Current request context: "
        + (
            "supplied HTTP context"
            if result.has_supplied_context_headers
            else "without user-supplied target headers"
        )
    )
    if preview:
        console.print("Maximum requests: 1")
        if result.probe:
            console.print(Text(result.probe.endpoint, style="gql.metadata"))
            _document(console, result.probe.query)
            console.print(
                Text(
                    "Variables:\n"
                    + json.dumps(
                        result.probe.variables, indent=2, sort_keys=True, ensure_ascii=False
                    )
                )
            )
            for note in result.probe.manual_adjustments:
                console.print(Text(note))
            console.print("This Mutation may change server-side state.", style="gql.warning")
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
            console.print("SENSITIVE_INPUT_POLICY_VIOLATION")
    for limitation in result.limitations:
        console.print(Text(limitation))
    console.print(Text(SENSITIVE_VALIDATION_NOTICE))
