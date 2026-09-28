"""Decode response objects without letting malformed or excessive JSON abort a scan."""

import json
from collections.abc import Iterator

# Count object/array containers, including the root. Generated selections and
# introspection type-reference wrappers are far shallower; do not use the
# interpreter's platform-dependent decoder/stack limit as the acceptance boundary.
MAX_JSON_NESTING = 128


class JsonNestingError(ValueError):
    """Untrusted JSON exceeds the supported structural nesting."""


def validate_json_nesting(value: object) -> None:
    """Check decoded JSON iteratively, with memory bounded by nesting, not breadth."""
    pending: list[Iterator[object]] = [iter((value,))]
    while pending:
        try:
            item = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue
        if isinstance(item, (dict, list)):
            if len(pending) > MAX_JSON_NESTING:
                raise JsonNestingError("Response JSON exceeds supported nesting.")
            pending.append(iter(item.values() if isinstance(item, dict) else item))


def decode_response_json(body: bytes | bytearray | str) -> object:
    """Decode and enforce the same depth bound even when the decoder accepts more."""
    try:
        value: object = json.loads(body)
    except RecursionError:
        raise JsonNestingError("Response JSON exceeds supported nesting.") from None
    validate_json_nesting(value)
    return value


def response_json_object(body: bytes) -> dict[str, object] | None:
    """Leave status/confidence decisions to callers; unusable JSON has no object."""
    try:
        value = decode_response_json(body)
    except (ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None
