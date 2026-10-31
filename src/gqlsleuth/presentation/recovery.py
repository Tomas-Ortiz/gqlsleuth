"""Human-only projection of structured progressive recovery; never infer facts from prose."""

from dataclasses import dataclass

from gqlsleuth.application.progressive_introspection import ProgressiveRecoveryResult
from gqlsleuth.graphql.introspection_compatibility import deprecated_coverage_note


@dataclass(frozen=True)
class RecoveryPresentation:
    rows: tuple[tuple[str, str], ...]
    context: tuple[str, ...]
    inventory: tuple[str, ...]


def present_recovery(result: ProgressiveRecoveryResult) -> RecoveryPresentation:
    roots = dict(result.catalogue.roots) if result.catalogue else {}
    types = {item.name: item for item in result.types}
    rows = [("Recovery method", "PROGRESSIVE")]
    for role, label in (
        ("queryType", "Queries"),
        ("mutationType", "Mutations"),
        ("subscriptionType", "Subs"),
    ):
        name = roots.get(role)
        rows.append(
            (
                role.removesuffix("Type").capitalize() + " root",
                name or ("None" if role in roots else "Unknown"),
            )
        )
        item = types.get(name) if name else None
        count = (
            "0"
            if role in roots and name is None
            else str(len(item.field_names))
            + (" (partial coverage)" if result.assembled is None else "")
            if item is not None and item.field_names is not None
            else "Unknown"
        )
        rows.append(("Known " + label, count))
    incomplete = (
        str(
            sum(
                name not in types or not types[name].complete
                for name, _ in result.catalogue.types
                if not name.startswith("__")
            )
        )
        if result.catalogue
        else "Unknown"
    )
    rows.extend(
        (
            ("Types incomplete", incomplete),
            ("Requests", str(len(result.attempts))),
            ("Stop reason", result.stop_reason),
        )
    )
    if result.compatibility_omissions:
        rows.extend(
            (
                ("Compatibility", "Legacy introspection fallback used"),
                ("Coverage note", deprecated_coverage_note(result.compatibility_omissions)),
                ("Structure validated", "Yes" if result.structurally_validated else "No"),
            )
        )
    if result.attempts:
        attempt = result.attempts[-1]
        rows.append(("Last query shape", attempt.shape))
        rows.append(
            (
                "Last HTTP status",
                str(attempt.response.status_code) if attempt.response else "No response",
            )
        )
        rows.append(("Last response", attempt.classification))
    context = (
        "Full and reduced introspection were rejected by recognized query-shape restrictions.",
        "Locally assembled schema passed strict validation; schema-dependent analysis is available."
        if result.assembled is not None
        else "Recovery is incomplete. Automatic Query generation and execution remain unavailable.",
    )
    return RecoveryPresentation(
        rows=tuple(rows),
        context=context,
        inventory=tuple(
            f"{role.removesuffix('Type').capitalize()} fields "
            f"(showing {min(8, len(types[name].field_names or ()))} "
            f"of {len(types[name].field_names or ())}): "
            + ", ".join((types[name].field_names or ())[:8])
            for role, name in roots.items()
            if name in types and types[name].field_names
        ),
    )
