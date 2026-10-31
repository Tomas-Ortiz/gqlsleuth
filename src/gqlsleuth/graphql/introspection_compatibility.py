"""Exact optional-argument compatibility for fixed progressive introspection templates."""

import re

from gqlsleuth.graphql.progressive_introspection import (
    DIRECTIVES_QUERY,
    ROOT_INVENTORY_QUERY,
    TYPE_QUERIES,
)
from gqlsleuth.graphql.response_json import response_json_object

# These are the only removable arguments. No returned text becomes a query selection.
TYPE_OPTIONAL_ARGUMENTS = frozenset(
    {
        "__Type.fields",
        "__Type.inputFields",
        "__Type.enumValues",
    }
)
OPTIONAL_ARGUMENTS = TYPE_OPTIONAL_ARGUMENTS | {"__Field.args", "__Directive.args"}
QUERY_ARGUMENTS = {
    ROOT_INVENTORY_QUERY: frozenset({"__Type.fields"}),
    TYPE_QUERIES[0][1]: TYPE_OPTIONAL_ARGUMENTS | {"__Field.args"},
    TYPE_QUERIES[1][1]: TYPE_OPTIONAL_ARGUMENTS | {"__Field.args"},
    TYPE_QUERIES[2][1]: TYPE_OPTIONAL_ARGUMENTS,
    DIRECTIVES_QUERY: frozenset({"__Directive.args"}),
}
_UNKNOWN_ARGUMENT = re.compile(
    r"""Unknown argument (?P<a>["'])includeDeprecated(?P=a) on field (?:"""
    r"""(?P<b>["'])(?P<owner>__Type|__Field|__Directive)\.(?P<field>fields|inputFields|enumValues|args)(?P=b)"""
    r"""|(?P<c>["'])(?P<separate_field>fields|inputFields|enumValues|args)(?P=c) of type """
    r"""(?P<d>["'])(?P<separate_owner>__Type|__Field|__Directive)(?P=d))\.?"""
)


def unsupported_optional_arguments(
    status_code: int, body: bytes, available: frozenset[str]
) -> frozenset[str]:
    """Authorize only exact validation errors for arguments present in this request.

    Every error must agree with a known compatible template. Denial/unknown extension codes,
    mixed errors and responses containing data are not compatibility authorization.
    """
    if not (200 <= status_code < 300 or status_code in {400, 413, 422}):
        return frozenset()
    document = response_json_object(body)
    if document is None or document.get("data") is not None:
        return frozenset()
    errors = document.get("errors")
    if not isinstance(errors, list) or not 1 <= len(errors) <= 8:
        return frozenset()
    rejected = set()
    for error in errors:
        if not isinstance(error, dict):
            return frozenset()
        message = error.get("message")
        if not isinstance(message, str) or len(message) > 512:
            return frozenset()
        extensions = error.get("extensions")
        if extensions is not None and (
            not isinstance(extensions, dict)
            or extensions.get("code")
            not in (None, "GRAPHQL_VALIDATION_FAILED", "GRAPHQL_VALIDATION_ERROR")
        ):
            return frozenset()
        match = _UNKNOWN_ARGUMENT.fullmatch(" ".join(message.split()))
        if match is None:
            return frozenset()
        owner = match["owner"] or match["separate_owner"]
        field = match["field"] or match["separate_field"]
        key = f"{owner}.{field}"
        if key not in OPTIONAL_ARGUMENTS or key not in available:
            return frozenset()
        rejected.add(key)
    return frozenset(rejected)


def compatible_query(query: str, unsupported: set[str]) -> tuple[str, tuple[str, ...]]:
    """Select evidence-established omissions from fixed templates, without variant probing."""
    omissions = tuple(sorted(QUERY_ARGUMENTS.get(query, frozenset()) & unsupported))
    for key in omissions:
        field = key.split(".")[1]
        query = query.replace(f"{field}(includeDeprecated: true)", field)
    return query, omissions


def deprecated_coverage_note(omissions: tuple[str, ...]) -> str:
    labels = {
        "__Type.fields": "fields",
        "__Type.inputFields": "input fields",
        "__Type.enumValues": "enum values",
        "__Field.args": "field arguments",
        "__Directive.args": "directive arguments",
    }
    return "Deprecated " + ", ".join(labels[key] for key in omissions) + " may be omitted."
