"""Authentication review presentation uses only safe metadata and retained decisions."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gqlsleuth.domain.authentication import (
    AUTHENTICATION_NOTICE,
    AuthenticationProbe,
    AuthenticationSecurityResult,
    TokenSecurityReview,
)
from gqlsleuth.domain.nested_authorization import NestedOutcome
from gqlsleuth.presentation.console import _document, _section

PROBE_LABELS = {
    AuthenticationProbe.AUTHORIZATION_REMOVED: "Authorization-removed control",
    AuthenticationProbe.JWT_SIGNATURE_TAMPERED: "Tampered signature",
    AuthenticationProbe.JWT_ALG_NONE: "alg=none unsigned token",
}


def outcome_label(outcome: NestedOutcome) -> str:
    return "ACCESS_RETURNED" if outcome is NestedOutcome.RETURNED else outcome.value.upper()


def token_rows(review: TokenSecurityReview) -> tuple[tuple[str, str], ...]:
    temporal = dict(review.temporal_states)
    return (
        (
            ("Token type", review.token_type.upper()),
            ("Algorithm (unverified)", review.algorithm or "Not applicable"),
        )
        + tuple(
            (f"Header {name}", "present" if present else "absent")
            for name, present in review.header_presence
        )
        + tuple(
            (f"Claim {name}", temporal.get(name, "present" if present else "absent"))
            for name, present in review.claim_presence
        )
    )


def render_authentication(
    console: Console,
    result: AuthenticationSecurityResult,
    *,
    preview: bool = False,
    verbose: bool = False,
) -> None:
    _section(console, "Authentication & Token Security")
    console.print("Authentication carrier: Authorization: Bearer <hidden>")
    for name, value in token_rows(result.token_review):
        console.print(Text(f"{name}: {value}"))
    for observation in result.token_review.observations:
        console.print(Text(observation))
    if preview and result.selected_query is None:
        for candidate in result.candidates:
            console.print(
                Text(
                    f"[{candidate.index}] {candidate.operation} — {candidate.endpoint}",
                    style="cyan",
                )
            )
    selected = result.selected_query
    if selected:
        console.print(
            Text(f"Selected Query: {selected.operation} — {selected.endpoint}", style="cyan")
        )
        console.print("Existing baseline: SUCCESS (retained Phase 9 evidence; no replay).")
        if preview or verbose:
            _document(console, selected.query)
            console.print(Text("Variables: " + json.dumps(selected.variables, sort_keys=True)))
        if preview:
            console.print("Planned control: remove Authorization; retain all other headers.")
            console.print(
                Text(
                    "Selected JWT probes: "
                    + (", ".join(PROBE_LABELS[p] for p in result.selected_probes) or "none")
                )
            )
            console.print(
                f"Maximum additional requests: {1 + len(result.selected_probes)} (hard limit: 3)."
            )
            console.print("JWT probes run only after explicit denial by the control.")
    if not preview:
        console.print(
            f"Confirmed: {result.confirmed}; {result.attempted_request_count} requests; "
            f"{len(result.findings)} finding(s)."
        )
        table = Table(box=None, padding=(0, 1))
        for column in ("Probe", "Observed", "Policy", "HTTP"):
            table.add_column(column)
        for execution in result.executions:
            evidence = execution.evidence
            table.add_row(
                PROBE_LABELS[execution.probe_type],
                outcome_label(evidence.outcome) if evidence else "NOT_ATTEMPTED",
                evidence.policy_result.value.upper() if evidence else "NOT_EVALUATED",
                str(evidence.response_status_code)
                if evidence and evidence.response_status_code
                else "—",
            )
        if result.executions:
            console.print(table)
        for execution in result.executions:
            if verbose or execution.evidence is None:
                console.print(Text(PROBE_LABELS[execution.probe_type] + ": " + execution.reason))
        for finding in result.findings:
            console.print(Text(f"Finding: {finding.finding_type.value.upper()}. {finding.reason}"))
    for limitation in result.limitations:
        console.print(Text(limitation))
    console.print(Text(AUTHENTICATION_NOTICE))
