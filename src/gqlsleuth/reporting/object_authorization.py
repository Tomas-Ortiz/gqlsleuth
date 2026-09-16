"""Human object-review reports expose supplied IDs and outcomes, never response bodies."""

import json

from gqlsleuth.domain.object_authorization import OBJECT_NOTICE, ObjectAuthorizationResult
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def object_authorization_section(result: ObjectAuthorizationResult) -> ReportSection:
    entries = []
    for case in result.cases:
        probe = next((item for item in result.probes if item.case == case), None)
        executions = tuple(item for item in result.executions if item.case_index == case.index)
        entries.append(
            ReportEntry(
                f"Case {case.index}: query {case.operation}",
                details=(
                    (
                        "Identifier",
                        f"{case.argument}={json.dumps(case.identifier, ensure_ascii=False)}",
                    ),
                )
                + (
                    (("Operator-declared authorized context", case.declared_authorized_context),)
                    if case.declared_authorized_context
                    else ()
                )
                + tuple(
                    (
                        item.context.name,
                        "Request context: "
                        f"{'supplied' if item.context.has_supplied_context_headers else 'none'}; "
                        f"{item.outcome.value.upper() if item.outcome else 'NOT_ATTEMPTED'}; "
                        "HTTP: "
                        f"{item.evidence.response_status_code if item.evidence else 'not observed'}"
                        "; "
                        f"id match: {item.returned_id_matches}. {item.reason}",
                    )
                    for item in executions
                ),
                paragraphs=tuple(
                    f"{item.kind.value.upper()} ({item.observed_context}): {item.reason}"
                    for item in result.candidates
                    if item.case == case
                ),
                request_blocks=(
                    ("graphql", probe.query),
                    ("json", json.dumps(probe.variables, indent=2, sort_keys=True)),
                )
                if probe
                else (),
                evidence_references=tuple(
                    ("Execution evidence", str(item.evidence.evidence_id))
                    for item in executions
                    if item.evidence
                ),
            )
        )
    return ReportSection(
        "Controlled Object Authorization Validation",
        paragraphs=(OBJECT_NOTICE, *result.limitations),
        rows=(
            ("Mode", result.mode.value.upper()),
            ("Cases", str(len(result.cases))),
            ("Additional read-only requests", str(result.attempted_request_count)),
            ("Review candidates", str(len(result.candidates))),
        ),
        entries=tuple(entries),
    )
