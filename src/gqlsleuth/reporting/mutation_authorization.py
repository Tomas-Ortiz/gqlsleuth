"""Human policy/Mutation observations, without unrelated response-body dumps."""

import json

from gqlsleuth.domain.mutation_authorization import (
    MUTATION_AUTHORIZATION_NOTICE,
    MutationAuthorizationResult,
)
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def mutation_authorization_section(result: MutationAuthorizationResult) -> ReportSection:
    probe = result.probe
    evidence = result.execution.evidence if result.execution else None
    entries = tuple(
        ReportEntry(
            f"Mutation: {case.operation}",
            details=(
                ("Identifier argument", case.argument),
                ("Target identifier", case.identifier),
                ("Operator-supplied expected policy", "DENY"),
                (
                    "Observed",
                    result.execution.outcome.value.upper() if result.execution else "NOT_ATTEMPTED",
                ),
                (
                    "Result",
                    result.evaluation.status.value.upper() if result.evaluation else "UNRESOLVED",
                ),
                ("HTTP status", str(evidence.response_status_code) if evidence else "Not observed"),
            ),
            paragraphs=((result.evaluation.reason,) if result.evaluation else ())
            + (("MUTATION_AUTHORIZATION_POLICY_VIOLATION",) if result.violation else ())
            + (probe.manual_adjustments if probe else ()),
            code_blocks=(
                ("graphql", probe.query),
                ("json", json.dumps(probe.variables, indent=2, sort_keys=True, ensure_ascii=False)),
            )
            if probe
            else (),
            evidence_references=(("Attempt", str(evidence.evidence_id)),) if evidence else (),
        )
        for case in result.cases
    )
    return ReportSection(
        "Mutation Authorization Validation",
        paragraphs=(MUTATION_AUTHORIZATION_NOTICE, *result.limitations),
        rows=(
            (
                "Current request context",
                "Supplied HTTP context"
                if result.has_supplied_context_headers
                else "Without user-supplied target headers",
            ),
            ("Confirmed", str(result.confirmed)),
            ("Attempted requests", str(result.attempted_request_count)),
            ("Maximum requests", "1"),
        ),
        entries=entries,
    )
