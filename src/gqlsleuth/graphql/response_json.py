"""Decode response objects without letting malformed or excessive JSON abort a scan."""

import json


def response_json_object(body: bytes) -> dict[str, object] | None:
    """Leave status/confidence decisions to callers; unusable JSON has no object."""
    try:
        value: object = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None
