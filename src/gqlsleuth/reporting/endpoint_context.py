"""Move explicit human-entry endpoint metadata to its containing group only."""

from dataclasses import replace

from gqlsleuth.presentation.endpoints import endpoint_groups
from gqlsleuth.reporting.presentation import ReportEntry, ReportSection


def _endpoint(entry: ReportEntry) -> str | None:
    endpoints = tuple(dict.fromkeys(value for label, value in entry.details if label == "Endpoint"))
    return endpoints[0] if len(endpoints) == 1 and endpoints[0] else None


def group_endpoint_context(section: ReportSection) -> ReportSection:
    """Preserve exceptional/unscoped entries locally; never infer endpoints from prose."""
    section = replace(section, children=tuple(group_endpoint_context(s) for s in section.children))
    if "Endpoint" in section.table_headers and not section.entries:
        index = section.table_headers.index("Endpoint")
        headers = section.table_headers[:index] + section.table_headers[index + 1 :]
        table_groups = endpoint_groups(section.table_rows, lambda row: row[index])
        children = tuple(
            ReportSection(
                "",
                endpoint=endpoint,
                table_headers=headers,
                table_rows=tuple(row[:index] + row[index + 1 :] for row in rows),
            )
            for endpoint, rows in table_groups
        )
        return replace(
            section, table_headers=(), table_rows=(), children=children + section.children
        )
    groups = endpoint_groups(section.entries, _endpoint)
    if not any(endpoint for endpoint, _ in groups):
        return section

    def scoped(entries: tuple[ReportEntry, ...], endpoint: str) -> tuple[ReportEntry, ...]:
        return tuple(
            replace(
                entry,
                details=tuple(pair for pair in entry.details if pair != ("Endpoint", endpoint)),
            )
            for entry in entries
        )

    if len(groups) == 1 and groups[0][0] and section.endpoint in (None, groups[0][0]):
        endpoint, entries = groups[0]
        assert endpoint is not None
        return replace(section, endpoint=endpoint, entries=scoped(entries, endpoint))
    return replace(
        section,
        entries=(),
        children=tuple(
            ReportSection(
                "", endpoint=endpoint, entries=scoped(entries, endpoint) if endpoint else entries
            )
            for endpoint, entries in groups
        )
        + section.children,
    )
