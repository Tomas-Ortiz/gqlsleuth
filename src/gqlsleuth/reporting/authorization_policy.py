"""Human policy presentation references Phase 20 evidence without copying response data."""

import json

from gqlsleuth.domain.authorization_policy import (
    POLICY_NOTICE,
    AuthorizationPolicyResult,
    PolicyStatus,
)
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def authorization_policy_section(result: AuthorizationPolicyResult) -> ReportSection:
    return ReportSection(
        "Authorization Policy Validation",
        paragraphs=(POLICY_NOTICE, *result.limitations),
        rows=(
            ("Operator-supplied DENY assertions", str(len(result.assertions))),
            ("Policy violations", str(len(result.violations))),
            ("Additional target requests", "0"),
        ),
        entries=tuple(
            ReportEntry(
                f"Case {item.case.index}: query {item.case.operation} / "
                f"context {item.assertion.context}",
                details=(
                    (
                        "Identifier",
                        f"{item.case.argument}="
                        f"{json.dumps(item.case.identifier, ensure_ascii=False)}",
                    ),
                    ("Policy provenance", "OPERATOR_SUPPLIED"),
                    ("Expected policy", "DENY"),
                    (
                        "Observed Phase 20 outcome",
                        item.observed.value.upper() if item.observed else "NOT_OBSERVED",
                    ),
                    ("Evaluation", item.status.value.upper()),
                ),
                paragraphs=(
                    ("AUTHORIZATION_POLICY_VIOLATION",)
                    if item.status is PolicyStatus.VIOLATED
                    else ()
                )
                + (item.reason,),
                evidence_references=tuple(
                    ("Phase 20 evidence", str(identifier))
                    for identifier in item.source_evidence_ids
                ),
            )
            for item in result.evaluations
        ),
    )
