"""Stable endpoint grouping for human views, without changing retained records."""

from collections.abc import Callable, Iterable


def endpoint_groups[T](
    items: Iterable[T], endpoint: Callable[[T], str | None]
) -> tuple[tuple[str | None, tuple[T, ...]], ...]:
    """Keep first-seen endpoint order and original item order within each group."""
    groups: dict[str | None, list[T]] = {}
    for item in items:
        groups.setdefault(endpoint(item) or None, []).append(item)
    return tuple((key, tuple(values)) for key, values in groups.items())
