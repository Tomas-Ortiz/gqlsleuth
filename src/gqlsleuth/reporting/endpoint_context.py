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

    def scoped(entries: tuple[ReportEntry, ...], endpoint: str) -> tuple[ReportEntry, ...]:
        return tuple(
            replace(
                entry,
                details=tuple(pair for pair in entry.details if pair != ("Endpoint", endpoint)),
            )
            for entry in entries
        )

    if "Endpoint" in section.table_headers:
        index = section.table_headers.index("Endpoint")
        headers = section.table_headers[:index] + section.table_headers[index + 1 :]
        table_groups = dict(endpoint_groups(section.table_rows, lambda row: row[index]))
        entry_groups = dict(endpoint_groups(section.entries, _endpoint))
        endpoints = tuple(dict.fromkeys((*table_groups, *entry_groups)))
        children = tuple(
            ReportSection(
                "",
                endpoint=endpoint,
                table_headers=headers,
                table_rows=tuple(
                    row[:index] + row[index + 1 :] for row in table_groups.get(endpoint, ())
                ),
                entries=scoped(entry_groups.get(endpoint, ()), endpoint)
                if endpoint
                else entry_groups.get(endpoint, ()),
            )
            for endpoint in endpoints
        )
        if len(children) == 1 and section.endpoint in (None, children[0].endpoint):
            child = children[0]
            return replace(
                section,
                endpoint=child.endpoint,
                table_headers=headers,
                table_rows=child.table_rows,
                entries=child.entries,
            )
        return replace(
            section,
            entries=(),
            table_headers=(),
            table_rows=(),
            children=children + section.children,
        )
    groups = endpoint_groups(section.entries, _endpoint)
    if not any(endpoint for endpoint, _ in groups):
        return section

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
