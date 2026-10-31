"""Fixed recovery selections and verified facts, separate from HTTP provenance."""

import json
import re
from dataclasses import dataclass

from gqlsleuth.domain.exceptions import SchemaParsingError
from gqlsleuth.graphql.schema_parser import parse_introspection_response

MAX_RECOVERY_TYPES = 128
MAX_RECOVERY_FIELDS = 256
MAX_RECOVERY_ARGUMENTS = 64
MAX_RECOVERY_QUERY_BYTES = 2048
MAX_RECOVERY_DEPTH = 8
NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]{0,254}\Z")
KINDS = frozenset({"SCALAR", "OBJECT", "INTERFACE", "UNION", "ENUM", "INPUT_OBJECT"})
ROOTS = ("queryType", "mutationType", "subscriptionType")

CATALOGUE_QUERY = """query {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { name kind }
  }
}"""

# Root types are objects: input-object and enum selections are unnecessary here.
ROOT_INVENTORY_QUERY = (
    "query ($name: String!) { __type(name: $name) { kind name "
    "fields(includeDeprecated: true) { name } } }"
)


def _reference(levels: int) -> str:
    result = "kind name"
    for _ in range(levels):
        result = "kind name ofType { " + result + " }"
    return result


def _type_query(levels: int) -> str:
    ref = _reference(levels)
    value = "name defaultValue type { " + ref + " }"
    return (
        "query ($name: String!) { __type(name: $name) { kind name "
        "fields(includeDeprecated: true) { name isDeprecated deprecationReason "
        "args(includeDeprecated: true) { "
        + value
        + " } type { "
        + ref
        + " } } inputFields(includeDeprecated: true) { "
        + value
        + " } interfaces { kind name } possibleTypes { kind name } "
        "enumValues(includeDeprecated: true) { name isDeprecated deprecationReason } } }"
    )


TYPE_QUERIES = (
    ("type_detail", _type_query(3)),
    ("type_shallow", _type_query(1)),
    (
        "type_inventory",
        "query ($name: String!) { __type(name: $name) { kind name "
        "fields(includeDeprecated: true) { name } inputFields(includeDeprecated: true) { name } "
        "enumValues(includeDeprecated: true) { name } } }",
    ),
)
DIRECTIVES_QUERY = (
    "query { __schema { directives { name isRepeatable locations "
    "args(includeDeprecated: true) { name defaultValue type { " + _reference(3) + " } } } } }"
)


class RecoveryDataError(ValueError):
    """Malformed or contradictory recovery facts; messages contain no raw response text."""


@dataclass(frozen=True)
class RecoveryCatalogue:
    roots: tuple[tuple[str, str | None], ...]
    types: tuple[tuple[str, str], ...]
    complete: bool


@dataclass(frozen=True)
class RecoveredType:
    name: str
    kind: str
    definition: dict[str, object]
    field_names: tuple[str, ...] | None
    complete: bool
    input_references: tuple[str, ...]
    output_references: tuple[str, ...]


@dataclass(frozen=True)
class AssembledSchema:
    """Locally assembled and strictly validated bytes; never an HTTP response."""

    body: bytes
    origin: str = "progressive_local_assembly"


def object_value(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RecoveryDataError("Recovery data contains a missing or malformed object.")
    return value


def _name(value: object) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise RecoveryDataError("Recovery data contains an invalid or oversized GraphQL name.")
    return value


def parse_catalogue(data: dict[str, object]) -> RecoveryCatalogue:
    schema = object_value(data.get("__schema"))
    roots = []
    for role in ROOTS:
        if role not in schema:
            raise RecoveryDataError("Recovery catalogue is missing a root declaration.")
        value = schema[role]
        roots.append((role, None if value is None else _name(object_value(value).get("name"))))
    if roots[0][1] is None:
        raise RecoveryDataError("Recovery catalogue has no Query root identity.")
    entries = schema.get("types")
    if not isinstance(entries, list):
        raise RecoveryDataError("Recovery catalogue has no valid type list.")
    types: dict[str, str] = {}
    complete = len(entries) <= MAX_RECOVERY_TYPES
    for entry in entries[:MAX_RECOVERY_TYPES]:
        try:
            item = object_value(entry)
            name = _name(item.get("name"))
            kind = item.get("kind")
            if not isinstance(kind, str) or kind not in KINDS:
                raise RecoveryDataError("Recovery catalogue has an invalid type kind.")
        except RecoveryDataError:
            complete = False
            continue
        if name in types and types[name] != kind:
            raise RecoveryDataError("Recovery catalogue contains contradictory type identities.")
        types[name] = kind
    for _, root in roots:
        if root is not None and root in types and types[root] != "OBJECT":
            raise RecoveryDataError("Recovery catalogue root is not an object type.")
    return RecoveryCatalogue(tuple(roots), tuple(sorted(types.items())), complete)


def _named_entries(value: object, limit: int) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > limit:
        raise RecoveryDataError("Recovery fields are missing, malformed or exceed the local limit.")
    items = [object_value(item) for item in value]
    names = [_name(item.get("name")) for item in items]
    if len(set(names)) != len(names):
        raise RecoveryDataError("Recovery data contains duplicate definitions.")
    return items


def _type_reference(value: object, catalogue: dict[str, str]) -> tuple[bool, str | None]:
    for _ in range(4):
        if not isinstance(value, dict):
            return False, None
        kind = value.get("kind")
        name = value.get("name")
        if not isinstance(kind, str):
            return False, None
        if kind in {"NON_NULL", "LIST"}:
            if name is not None:
                raise RecoveryDataError("Recovery type wrapper has a contradictory name.")
            value = value.get("ofType")
            continue
        if isinstance(name, str) and isinstance(kind, str) and kind in KINDS:
            _name(name)
            if name in catalogue and catalogue[name] != kind:
                raise RecoveryDataError("Recovery reference contradicts the catalogue type kind.")
            return name in catalogue, name
        return False, None
    return False, None


def _deprecation_known(item: dict[str, object]) -> bool:
    if "isDeprecated" not in item or "deprecationReason" not in item:
        return False
    flag, reason = item["isDeprecated"], item["deprecationReason"]
    if (
        not isinstance(flag, bool)
        or (reason is not None and not isinstance(reason, str))
        or flag != (reason is not None)
    ):
        raise RecoveryDataError("Recovery data contains contradictory deprecation metadata.")
    return True


def parse_type(data: dict[str, object], name: str, catalogue: RecoveryCatalogue) -> RecoveredType:
    item = object_value(data.get("__type"))
    kinds = dict(catalogue.types)
    if item.get("name") != name or item.get("kind") != kinds[name]:
        raise RecoveryDataError(
            "Recovery type identity does not match the requested catalogue entry."
        )
    kind = kinds[name]
    complete = True
    inputs: list[str] = []
    outputs: list[str] = []
    field_names = None
    if kind in {"OBJECT", "INTERFACE", "INPUT_OBJECT"}:
        key = "inputFields" if kind == "INPUT_OBJECT" else "fields"
        fields = _named_entries(item.get(key), MAX_RECOVERY_FIELDS)
        field_names = tuple(sorted(str(field["name"]) for field in fields))
        for field in fields:
            valid, reference = _type_reference(field.get("type"), kinds)
            complete &= valid
            if reference:
                (inputs if kind == "INPUT_OBJECT" else outputs).append(reference)
            if kind == "INPUT_OBJECT":
                complete &= "defaultValue" in field
            elif "args" not in field:
                complete = False
            else:
                complete &= _deprecation_known(field)
                for argument in _named_entries(field["args"], MAX_RECOVERY_ARGUMENTS):
                    valid, reference = _type_reference(argument.get("type"), kinds)
                    complete &= valid and "defaultValue" in argument
                    if reference:
                        inputs.append(reference)
    for key in (
        ("interfaces", "possibleTypes")
        if kind == "INTERFACE"
        else ("interfaces",)
        if kind == "OBJECT"
        else ("possibleTypes",)
        if kind == "UNION"
        else ()
    ):
        if key not in item:
            complete = False
            continue
        for relationship in _named_entries(item[key], MAX_RECOVERY_TYPES):
            valid, referenced_name = _type_reference(relationship, kinds)
            complete &= valid
            if referenced_name:
                outputs.append(referenced_name)
    if kind == "ENUM":
        values = _named_entries(item.get("enumValues"), MAX_RECOVERY_FIELDS)
        complete &= all(_deprecation_known(value) for value in values)
    return RecoveredType(
        name,
        kind,
        item,
        field_names,
        complete,
        tuple(sorted(set(inputs))),
        tuple(sorted(set(outputs))),
    )


def assemble_schema(
    catalogue: RecoveryCatalogue, types: tuple[RecoveredType, ...], directives: object
) -> AssembledSchema | None:
    """Require every catalogued application type and exact references before strict parsing."""
    expected = {name for name, _ in catalogue.types if not name.startswith("__")}
    if (
        not catalogue.complete
        or {t.name for t in types} != expected
        or not all(t.complete for t in types)
    ):
        return None
    kinds = dict(catalogue.types)
    for directive in _named_entries(directives, MAX_RECOVERY_FIELDS):
        if not isinstance(directive.get("locations"), list) or not isinstance(
            directive.get("isRepeatable"), bool
        ):
            raise RecoveryDataError("Recovery directives are missing locations.")
        for argument in _named_entries(directive.get("args"), MAX_RECOVERY_ARGUMENTS):
            valid, _ = _type_reference(argument.get("type"), kinds)
            if not valid or "defaultValue" not in argument:
                return None
    schema: dict[str, object] = {
        role: {"name": name} if name else None for role, name in catalogue.roots
    }
    schema.update(
        types=[t.definition for t in sorted(types, key=lambda t: t.name)], directives=directives
    )
    body = json.dumps(
        {"data": {"__schema": schema}}, sort_keys=True, separators=(",", ":")
    ).encode()
    try:
        parsed = parse_introspection_response(body)
    except SchemaParsingError:
        raise RecoveryDataError(
            "Locally assembled schema failed strict structural validation."
        ) from None
    for item in types:
        if item.kind == "INTERFACE":
            parsed_type = parsed.type_named(item.name)
            observed = tuple(
                sorted(
                    str(t["name"])
                    for t in _named_entries(
                        item.definition.get("possibleTypes"), MAX_RECOVERY_TYPES
                    )
                )
            )
            if parsed_type is None or parsed_type.possible_types != observed:
                raise RecoveryDataError(
                    "Recovery interface membership contradicts object definitions."
                )
    return AssembledSchema(body)
