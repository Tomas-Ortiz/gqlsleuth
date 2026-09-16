"""Exact authorization signals shared by bounded SAFE authorization reviews."""

from gqlsleuth.rules.operation_analysis import normalize_terms

_DENIAL_CODES = {("unauthenticated",), ("unauthorized",), ("forbidden",), ("access", "denied")}
_DENIAL_PHRASES = {
    ("unauthenticated",),
    ("unauthorized",),
    ("forbidden",),
    ("access", "denied"),
    ("permission", "denied"),
    ("not", "authorized"),
    ("authentication", "required"),
}


def explicit_authorization_error(error: object, path: tuple[str, ...]) -> bool:
    if not isinstance(error, dict):
        return False
    runtime = error.get("path")
    if runtime is not None:
        if (
            not isinstance(runtime, list)
            or not runtime
            or any(
                not isinstance(part, str) and (type(part) is not int or part < 0)
                for part in runtime
            )
        ):
            return False
        normalized = tuple(part for part in runtime if isinstance(part, str))
        if not normalized or path[: len(normalized)] != normalized:
            return False
    extensions = error.get("extensions")
    code = extensions.get("code") if isinstance(extensions, dict) else None
    if isinstance(code, str) and normalize_terms(code) in _DENIAL_CODES:
        return True
    message = error.get("message")
    return isinstance(message, str) and normalize_terms(message) in _DENIAL_PHRASES
