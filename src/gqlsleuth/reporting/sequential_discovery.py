"""Human discovery reports distinguish supplied seeds from generated neighbors."""

import json

from gqlsleuth.domain.sequential_discovery import SEQUENTIAL_NOTICE, SequentialDiscoveryResult
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def sequential_discovery_section(result: SequentialDiscoveryResult) -> ReportSection:
    entries = []
    for seed in result.seeds:
        probes = tuple(item for item in result.probes if item.seed == seed)
        entries.append(
            ReportEntry(
                f"Seed {seed.index}: query {seed.operation}",
                details=(
                    ("Operator-supplied seed", f"{seed.argument}={seed.identifier}"),
                    ("Planned IDs", ", ".join(item.requested_identifier for item in probes)),
                ),
            )
        )
        for probe in probes:
            execution = next((item for item in result.executions if item.probe == probe), None)
            evidence = execution.evidence if execution else None
            entries.append(
                ReportEntry(
                    f"query {seed.operation}: {probe.requested_identifier}",
                    details=(
                        (
                            "Source",
                            "Operator-supplied seed baseline"
                            if probe.offset == 0
                            else "GQLSleuth-generated adjacent identifier "
                            f"(offset {probe.offset:+d})",
                        ),
                        ("Endpoint", probe.endpoint),
                        ("Attempted", str(bool(execution and execution.attempted))),
                        (
                            "Outcome",
                            execution.outcome.value.upper()
                            if execution and execution.outcome
                            else "NOT_ATTEMPTED",
                        ),
                        (
                            "HTTP status",
                            str(evidence.response_status_code) if evidence else "Not observed",
                        ),
                    ),
                    paragraphs=((execution.reason,) if execution else ())
                    + tuple(
                        f"ADJACENT_OBJECT_ACCESS: {item.reason}"
                        for item in result.candidates
                        if item.seed == seed
                        and item.generated_identifier == probe.requested_identifier
                    ),
                    request_blocks=(
                        ("graphql", probe.query),
                        ("json", json.dumps(probe.variables, indent=2, sort_keys=True)),
                    ),
                    evidence_references=tuple(
                        ("Structural source", str(value)) for value in probe.source_evidence_ids
                    )
                    + ((("Attempt", str(evidence.evidence_id)),) if evidence else ()),
                )
            )
    return ReportSection(
        "Bounded Sequential Object Discovery",
        paragraphs=(SEQUENTIAL_NOTICE, *result.limitations),
        rows=(
            (
                "Context",
                "Current supplied HTTP context"
                if result.has_supplied_context_headers
                else "Without user-supplied target headers",
            ),
            ("Fixed offsets", "-1, +1"),
            ("Confirmed", str(result.confirmed)),
            ("Additional read-only requests", str(result.attempted_request_count)),
            ("Review candidates", str(len(result.candidates))),
        ),
        entries=tuple(entries),
    )
