"""Console and shared human-report labels for bounded behavior observations."""

import json

from rich.console import Console
from rich.syntax import Syntax
from rich.text import Text

from gqlsleuth.domain.multiplicity import (
    MULTIPLICITY_NOTICE,
    MultiplicityEvidence,
    MultiplicityProbePreview,
    MultiplicityProbeType,
    MultiplicityValidationResult,
)
from gqlsleuth.presentation.console import _document, _section
from gqlsleuth.presentation.responses import ResponsePresentation, present_response_body


def probe_label(kind: MultiplicityProbeType) -> str:
    return (
        "Alias Multiplicity"
        if kind is MultiplicityProbeType.ALIAS_MULTIPLICITY
        else "HTTP Batching"
    )


def probe_guidance(kind: MultiplicityProbeType) -> str:
    if kind is MultiplicityProbeType.ALIAS_MULTIPLICITY:
        return (
            "Where resolver amplification is security-relevant, review server-side alias, "
            "depth and complexity controls."
        )
    return (
        "Where request amplification is security-relevant, review batching limits, "
        "per-operation authorization and server-side cost controls."
    )


def probe_response(evidence: MultiplicityEvidence) -> ResponsePresentation:
    return ResponsePresentation(
        evidence.observation.value.upper(),
        evidence.response_status_code,
        evidence.duration_seconds,
        present_response_body(evidence.response_body)
        if evidence.response_body is not None
        else None,
    )


def render_probe_previews(
    console: Console, candidates: tuple[tuple[int, MultiplicityProbePreview], ...], *, title: str
) -> None:
    _section(console, title)
    groups: dict[str, list[tuple[int, MultiplicityProbePreview]]] = {}
    for index, candidate in candidates:
        groups.setdefault(candidate.base.endpoint, []).append((index, candidate))
    for endpoint, entries in groups.items():
        console.print(Text("Endpoint: " + endpoint, style="gql.metadata"))
        for position, (index, candidate) in enumerate(entries):
            if position:
                console.print()
            console.print(
                Text(f"[{index}] {probe_label(candidate.probe_type)}", style="gql.heading")
            )
            console.print(
                Text("Operation: query " + candidate.base.operation_name, style="gql.metadata")
            )
            console.print(
                "Aliases requested: 3"
                if candidate.probe_type is MultiplicityProbeType.ALIAS_MULTIPLICITY
                else "Batch entries: 2 identical Query/variables request objects."
            )
            _document(console, candidate.query)
            console.print(
                "Variables: " + json.dumps(candidate.base.variables, sort_keys=True), markup=False
            )
    console.print(MULTIPLICITY_NOTICE, markup=False, style="gql.secondary")


def render_multiplicity(
    console: Console, result: MultiplicityValidationResult, *, verbose: bool = False
) -> None:
    _section(console, "Query-Shape Validation")
    console.print(
        f"{len(result.evidence)} executed; {len(result.selected_indices)} selected; "
        f"confirmed: {result.confirmed}."
    )
    for item in result.executions:
        outcome = item.evidence.observation.value if item.evidence else item.decision.value
        console.print(
            Text(
                f"{probe_label(item.candidate.probe_type)} / "
                f"query {item.candidate.base.operation_name}: {outcome.upper()}"
            )
        )
        if verbose and item.evidence:
            console.print()
            response = probe_response(item.evidence)
            console.print("Response", style="gql.response")
            for label, value in response.details:
                console.print(Text(f"{label}: {value}"))
            if response.body:
                console.print(
                    Syntax(
                        response.body.text,
                        response.body.language,
                        theme="ansi_dark",
                        background_color="default",
                        word_wrap=True,
                    )
                )
                if response.body.notice:
                    console.print(response.body.notice, markup=False)
            console.print(item.reason, markup=False)
    for limitation in result.limitations:
        console.print(limitation, markup=False)
