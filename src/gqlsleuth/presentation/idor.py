"""Bounded IDOR policy preview and evidence-linked results, without response bodies."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gqlsleuth.domain.idor import IDOR_NOTICE, IdorContextType, IdorDetectionResult, expected_policy
from gqlsleuth.domain.sequential_discovery import MAX_PHASE22_REQUESTS
from gqlsleuth.presentation.console import _document, _section


def context_description(result: IdorDetectionResult) -> str:
    return (
        f"{result.context_label} (authenticated supplied context)"
        if result.context_label
        else result.context_type.value
    )


def policy_description(result: IdorDetectionResult) -> str:
    return (
        "Seed: expected ALLOW baseline. Generated adjacent IDs: expected DENY. "
        "Neighbors run only after the exact baseline object is returned."
        if result.context_type is IdorContextType.AUTHENTICATED
        else "Anonymous access to seed and generated adjacent IDs: expected DENY. "
        "Neighbors run only after the exact seed object is returned."
    )


def render_idor(
    console: Console,
    result: IdorDetectionResult,
    *,
    preview: bool = False,
    verbose: bool = False,
) -> None:
    _section(console, "IDOR / BOLA Detection")
    console.print(Text("Context: " + context_description(result)))
    console.print(Text(policy_description(result)))
    console.print(
        f"Maximum planned requests: {len(result.probes)} (hard limit: {MAX_PHASE22_REQUESTS})."
        if preview
        else f"Confirmed: {result.confirmed}; {result.attempted_request_count} requests; "
        f"{len(result.findings)} finding(s)."
    )
    for seed in result.seeds:
        console.print(Text(f"{seed.operation}:{seed.argument}={seed.identifier}", style="cyan"))
        table = Table(box=None, padding=(0, 1))
        for title in ("ID", "Role", "Expected", "Observed", "Result"):
            table.add_column(title)
        for probe in result.probes:
            if probe.seed != seed:
                continue
            role, expected = expected_policy(result.context_type, probe)
            execution = next((item for item in result.executions if item.probe == probe), None)
            evidence = execution.evidence if execution else None
            table.add_row(
                probe.requested_identifier,
                role,
                expected.upper(),
                evidence.outcome.value.upper() if evidence else "NOT_ATTEMPTED",
                execution.policy_result.value.upper() if execution else "PLANNED",
            )
        console.print(table)
        if verbose:
            for probe in result.probes:
                if probe.seed == seed:
                    _document(console, probe.query)
                    console.print(Text("Variables: " + json.dumps(probe.variables, sort_keys=True)))
    for finding in result.findings:
        console.print(
            Text(
                f"IDOR / BOLA Finding: {finding.operation}:{finding.identifier_argument}="
                f"{finding.identifier}. {finding.reason}"
            )
        )
    for limitation in result.limitations:
        console.print(Text(limitation))
    console.print(Text(IDOR_NOTICE))
