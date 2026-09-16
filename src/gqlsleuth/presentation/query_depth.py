"""Neutral, exact depth previews and shared bounded response presentation."""

import json

from rich.console import Console
from rich.syntax import Syntax
from rich.text import Text

from gqlsleuth.domain.query_depth import (
    DEPTH_NOTICE,
    QueryDepthEvidence,
    QueryDepthProbePreview,
    QueryDepthValidationResult,
)
from gqlsleuth.presentation.console import _document, _section
from gqlsleuth.presentation.responses import ResponsePresentation, present_response_body


def depth_response(evidence: QueryDepthEvidence) -> ResponsePresentation:
    return ResponsePresentation(
        evidence.observation.value.upper(),
        evidence.response_status_code,
        evidence.duration_seconds,
        present_response_body(evidence.response_body)
        if evidence.response_body is not None
        else None,
    )


def render_depth_previews(
    console: Console, candidates: tuple[tuple[int, QueryDepthProbePreview], ...], *, title: str
) -> None:
    _section(console, title)
    for position, (index, candidate) in enumerate(candidates):
        if position:
            console.print()
        console.print(Text("Endpoint: " + candidate.base.endpoint, style="gql.metadata"))
        console.print(Text(f"[{index}] Controlled Query Depth", style="gql.heading"))
        console.print(
            Text("Operation: query " + candidate.base.operation_name, style="gql.metadata")
        )
        console.print(
            f"Baseline depth: {candidate.baseline_depth}; "
            f"outcome: {candidate.baseline_status.value.upper()}"
        )
        console.print(
            f"Probe depth: {candidate.probe_depth}; composite list edges: {candidate.list_edges}"
        )
        console.print("Recursive path: " + " -> ".join(candidate.recursive_path), markup=False)
        _document(console, candidate.query)
        console.print(
            "Variables: " + json.dumps(candidate.base.variables, sort_keys=True), markup=False
        )
    console.print(DEPTH_NOTICE, markup=False, style="gql.secondary")


def render_query_depth(
    console: Console, result: QueryDepthValidationResult, *, verbose: bool = False
) -> None:
    _section(console, "Query-Depth Validation")
    console.print(
        f"{len(result.evidence)} executed; {len(result.selected_indices)} selected; "
        f"confirmed: {result.confirmed}."
    )
    for item in result.executions:
        status = item.evidence.observation.value if item.evidence else item.decision.value
        console.print(
            Text(
                f"Controlled Query Depth / query {item.candidate.base.operation_name}: "
                f"{status.upper()}"
            )
        )
        if verbose and item.evidence:
            console.print()
            console.print("Response", style="gql.response")
            response = depth_response(item.evidence)
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
