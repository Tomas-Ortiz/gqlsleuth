"""Compact differential candidate facts shared by console and human reports."""

from dataclasses import dataclass

from gqlsleuth.domain.differential import ContextPairReview


@dataclass(frozen=True)
class DifferentialTable:
    endpoints: tuple[str, ...]
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


def present_differential(pairs: tuple[ContextPairReview, ...]) -> DifferentialTable:
    """Retain candidate order and observations without making comparison decisions."""
    endpoints = tuple(dict.fromkeys(item.endpoint for pair in pairs for item in pair.candidates))
    headers: tuple[str, ...] = ("Contexts", "Difference", "Operation / observed states")
    if len(endpoints) > 1:
        headers += ("Endpoint",)
    rows = []
    for pair in pairs:
        for candidate in pair.candidates:
            # ASCII pair markers also work in legacy Windows redirected consoles.
            states = f"{candidate.left.state.upper()} <-> {candidate.right.state.upper()}"
            if candidate.left.http_status is not None or candidate.right.http_status is not None:
                states += (
                    f" (HTTP {candidate.left.http_status or 'none'} <-> "
                    f"{candidate.right.http_status or 'none'})"
                )
            if candidate.operation_name:
                label = candidate.operation_name
                if candidate.operation_kind:
                    label = f"{candidate.operation_kind.value} {label}"
                states = f"{label}: {states}"
            row: tuple[str, ...] = (
                f"{pair.context_a} <-> {pair.context_b}",
                candidate.kind.value.removesuffix("_difference").replace("_", " ").title(),
                states,
            )
            if len(endpoints) > 1:
                row += (candidate.endpoint,)
            rows.append(row)
    return DifferentialTable(endpoints, headers, tuple(rows))
