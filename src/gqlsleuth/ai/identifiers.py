"""The narrow GraphQL identifier boundary shared by AI projections."""

import re


def identifier(value: str | None) -> str | None:
    return value if value and re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,127}", value) else None


def identifier_path(values: tuple[str, ...]) -> tuple[str, ...]:
    return values if len(values) <= 8 and all(identifier(part) for part in values) else ()
