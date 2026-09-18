"""Shared human layouts keep local review separate from attempted field/value validation."""

import json

from gqlsleuth.domain.sensitive_input import (
    SENSITIVE_REVIEW_NOTICE,
    SENSITIVE_VALIDATION_NOTICE,
    SensitiveInputCandidate,
    SensitiveInputValidationResult,
)
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def sensitive_review_section(
    candidates: tuple[SensitiveInputCandidate, ...], context: str | None = None
) -> ReportSection:
    entries = []
    for item in candidates:
        commands = []
        if item.case_template:
            commands = [
                "--mode active --sensitive-input-review",
                f'--sensitive-input-case "{item.case_template}"',
            ]
            if item.target_template:
                commands.append(f'--sensitive-input-target "{item.target_template}"')
        entries.append(
            ReportEntry(
                f"Mutation: {item.operation}",
                details=(
                    ("Endpoint", item.endpoint),
                    ("Input field", f"{item.argument}.{item.field}"),
                    ("Type", item.input_type),
                    ("Review category", item.category.value.upper()),
                ),
                paragraphs=(item.reason, *item.supporting_facts),
                code_blocks=(
                    (
                        "text",
                        "Suggested follow-up (operator-supplied values only):\n"
                        + "\n".join(commands),
                    ),
                )
                if commands
                else (),
            )
        )
    return ReportSection(
        "Sensitive Input Review",
        paragraphs=(SENSITIVE_REVIEW_NOTICE,),
        rows=(("Context", context),) if context else (),
        entries=tuple(entries),
    )


def sensitive_validation_section(result: SensitiveInputValidationResult) -> ReportSection:
    case, probe = result.case, result.probe
    return ReportSection(
        "Sensitive Input Validation",
        paragraphs=(SENSITIVE_VALIDATION_NOTICE, *result.limitations),
        rows=(
            (
                "Current request context",
                "Supplied HTTP context"
                if result.has_supplied_context_headers
                else "Without user-supplied target headers",
            ),
            ("Operator policy", "DENY"),
            ("Confirmed", str(result.confirmed)),
            ("Attempted requests", str(result.attempted_request_count)),
            ("Maximum requests", "1"),
        ),
        entries=(
            ReportEntry(
                f"Mutation: {case.operation}",
                details=(
                    ("Input field", f"{case.argument}.{case.field}"),
                    (
                        "Supplied value",
                        json.dumps(probe.typed_value if probe else case.value, ensure_ascii=False),
                    ),
                    (
                        "Target",
                        f"{case.target.argument}={case.target.identifier}"
                        if case.target
                        else "Current object",
                    ),
                    (
                        "Observed",
                        result.execution.outcome.value.upper()
                        if result.execution
                        else "NOT_ATTEMPTED",
                    ),
                    (
                        "Result",
                        result.evaluation.status.value.upper()
                        if result.evaluation
                        else "UNRESOLVED",
                    ),
                ),
                paragraphs=((result.evaluation.reason,) if result.evaluation else ())
                + (("SENSITIVE_INPUT_POLICY_VIOLATION",) if result.violation else ()),
                code_blocks=(
                    ("graphql", probe.query),
                    (
                        "json",
                        json.dumps(probe.variables, indent=2, sort_keys=True, ensure_ascii=False),
                    ),
                )
                if probe
                else (),
                evidence_references=(("Attempt", str(result.execution.evidence_id)),)
                if result.execution
                else (),
            ),
        ),
    )
