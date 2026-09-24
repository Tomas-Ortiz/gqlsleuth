"""Compact federation preview and results without response bodies or SDL text."""

import json

from rich.console import Console
from rich.text import Text

from gqlsleuth.domain.federation import FEDERATION_LIMITATION, FederationSecurityResult
from gqlsleuth.presentation.console import _document, _section


def render_federation(
    console: Console, result: FederationSecurityResult, *, preview: bool = False
) -> None:
    _section(console, "Federation Security")
    console.print(FEDERATION_LIMITATION)
    for index, candidate in enumerate(result.candidates, 1):
        console.print(Text(f"[{index}] {candidate.endpoint}", style="cyan"))
        console.print(
            f"Service: {candidate.service_available}; entities: {candidate.entities_available}"
        )
        for note in candidate.limitations:
            console.print(Text(note))
        if preview and candidate.endpoint == result.selected_endpoint:
            for plan in candidate.plans:
                if plan.probe in result.selected_probes:
                    console.print(
                        f"Selected {plan.probe.value}; policy {plan.expected.value.upper()}"
                    )
                    _document(console, plan.query)
                    console.print(Text(json.dumps(plan.variables, sort_keys=True, indent=2)))
    if preview:
        console.print("Maximum two sequential requests; no retries or follow-up requests.")
    for attempt in result.attempts:
        console.print(
            f"{attempt.probe.value}: {attempt.outcome.value.upper()}; "
            f"HTTP {attempt.response_status_code}; "
            + (
                attempt.evaluation.value.upper()
                if attempt.evaluation
                else "OBSERVE (no policy evaluation)"
            )
        )
        if attempt.sdl_returned:
            console.print(f"SDL: {attempt.sdl_bytes} UTF-8 bytes; SHA-256 {attempt.sdl_sha256}")
    for note in result.limitations:
        console.print(Text(note))
    if result.findings:
        _section(console, "Federation Security Findings")
        for finding in result.findings:
            console.print(Text(finding.label + ": " + finding.reason))
