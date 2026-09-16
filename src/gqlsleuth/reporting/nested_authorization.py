"""Human projections expose path outcomes, never returned business values."""

import json

from gqlsleuth.domain.nested_authorization import NESTED_NOTICE, NestedAuthorizationResult
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def nested_authorization_section(result: NestedAuthorizationResult) -> ReportSection:
    entries = []
    for index, candidate in enumerate(result.candidates, 1):
        executions = tuple(item for item in result.executions if item.candidate_index == index)
        pairs = tuple(item for item in result.pairs if item.candidate_index == index)
        entries.append(
            ReportEntry(
                f"query {candidate.base.operation_name} / {'.'.join(candidate.path)}",
                details=(
                    ("Endpoint", candidate.base.endpoint),
                    (
                        "Categories",
                        ", ".join(
                            dict.fromkeys(item.category.value for item in candidate.matched_rules)
                        ),
                    ),
                    ("Rules", ", ".join(item.rule_id for item in candidate.matched_rules)),
                    ("Selection depth", str(candidate.selection_depth)),
                    ("Composite list edges", str(candidate.list_edges)),
                )
                + tuple(
                    (
                        item.context,
                        f"{item.outcome.value.upper() if item.outcome else 'NOT_ATTEMPTED'}; "
                        "HTTP "
                        f"{item.evidence.response_status_code if item.evidence else 'not observed'}"
                        "; "
                        f"{item.reason}",
                    )
                    for item in executions
                ),
                paragraphs=tuple(
                    f"{pair.context_a} ↔ {pair.context_b}: {pair.kind.value.upper()} "
                    f"({pair.state_a.upper()} ↔ {pair.state_b.upper()}). {pair.reason}"
                    for pair in pairs
                ),
                evidence_references=tuple(
                    ("Source evidence", str(identifier))
                    for pair in pairs
                    for identifier in pair.source_evidence_ids
                ),
                request_blocks=(
                    ("graphql", candidate.query),
                    ("json", json.dumps(candidate.base.variables, indent=2, sort_keys=True)),
                )
                if candidate.query
                else (),
            )
        )
    return ReportSection(
        "Nested Authorization Review",
        paragraphs=(NESTED_NOTICE, *result.limitations),
        rows=(
            ("Candidate paths", str(len(result.candidates))),
            ("Additional read-only requests", str(result.request_count)),
            ("Pairwise review candidates", str(len(result.pairs))),
        ),
        entries=tuple(entries),
    )
