"""Canonical federation ASTs and conservative, schema-typed response classification."""

import hashlib
import json
from dataclasses import dataclass

from graphql import GraphQLSchema, OperationType, parse_type, print_ast, validate
from graphql.language import (
    ArgumentNode,
    DocumentNode,
    FieldNode,
    InlineFragmentNode,
    NamedTypeNode,
    NameNode,
    OperationDefinitionNode,
    SelectionSetNode,
    VariableDefinitionNode,
    VariableNode,
)
from pydantic import JsonValue

from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.federation import (
    FederationOutcome,
    FederationPlan,
    FederationPolicy,
    FederationProbe,
)
from gqlsleuth.domain.nested_authorization import NestedOutcome
from gqlsleuth.domain.schema import ParsedSchema, SchemaTypeKind
from gqlsleuth.graphql.authentication import classify_authentication_response
from gqlsleuth.graphql.authorization_response import explicit_authorization_error
from gqlsleuth.graphql.object_authorization import exact_id_matches


def build_federation_plan(
    schema: ParsedSchema,
    native: GraphQLSchema,
    probe: FederationProbe,
    case: dict[str, JsonValue] | None,
    deny_sdl: bool,
) -> FederationPlan:
    variables: dict[str, JsonValue] = {}
    keys: list[tuple[str, str]] = []
    definitions: tuple[VariableDefinitionNode, ...] = ()
    if probe is FederationProbe.SERVICE:
        root = schema.type_named(schema.query_root)
        service = next((f for f in root.fields if f.name == "_service"), None) if root else None
        output = schema.type_named("_Service")
        sdl = next((f for f in output.fields if f.name == "sdl"), None) if output else None
        if not service or service.type.is_list or not sdl or sdl.type.is_list:
            raise SafeExecutionValidationError(
                "Service SDL requires a direct object and String field."
            )
        field = FieldNode(
            name=NameNode(value="_service"),
            arguments=(),
            directives=(),
            selection_set=SelectionSetNode(
                selections=(FieldNode(name=NameNode(value="sdl"), arguments=(), directives=()),)
            ),
        )
    else:
        if case is None:
            raise SafeExecutionValidationError("An explicit entity case is required.")
        entity = schema.type_named("_Entity")
        typename = case["__typename"]
        concrete = schema.type_named(typename) if isinstance(typename, str) else None
        if (
            not entity
            or typename not in entity.possible_types
            or not concrete
            or concrete.kind is not SchemaTypeKind.OBJECT
        ):
            raise SafeExecutionValidationError(
                "Entity type must be a retained concrete _Entity member."
            )
        fields = {field.name: field for field in concrete.fields}
        for name, value in sorted(case.items()):
            if name == "__typename":
                continue
            item = fields.get(name)
            scalar = schema.type_named(item.type.named_type) if item else None
            if not item or item.arguments or item.type.is_list or not scalar:
                raise SafeExecutionValidationError(
                    "Every entity key must be directly selectable without arguments."
                )
            kind = scalar.name
            valid = (
                (kind == "ID" and type(value) in (str, int))
                or (kind == "String" and type(value) is str)
                or (kind == "Int" and type(value) is int and -(2**31) <= value < 2**31)
                or (kind == "Boolean" and type(value) is bool)
                or (
                    scalar.kind is SchemaTypeKind.ENUM
                    and type(value) is str
                    and value in {e.name for e in scalar.enum_values}
                )
            )
            if not valid:
                raise SafeExecutionValidationError(
                    "Entity key value/type is not supported by its retained schema field."
                )
            keys.append((name, kind))
        root = schema.type_named(schema.query_root)
        operation = next((f for f in root.fields if f.name == "_entities"), None) if root else None
        argument = (
            next((a for a in operation.arguments if a.name == "representations"), None)
            if operation
            else None
        )
        if not argument or not argument.type.list_item or argument.type.list_item.is_list:
            raise SafeExecutionValidationError(
                "Entity representations require a single list of _Any."
            )
        variable = VariableNode(name=NameNode(value="representations"))
        definitions = (
            VariableDefinitionNode(
                variable=variable, type=parse_type(argument.type.render()), directives=()
            ),
        )
        variables = {"representations": [dict(case)]}
        field = FieldNode(
            name=NameNode(value="_entities"),
            directives=(),
            arguments=(ArgumentNode(name=NameNode(value="representations"), value=variable),),
            selection_set=SelectionSetNode(
                selections=(
                    InlineFragmentNode(
                        directives=(),
                        type_condition=NamedTypeNode(name=NameNode(value=str(typename))),
                        selection_set=SelectionSetNode(
                            selections=tuple(
                                FieldNode(name=NameNode(value=name), arguments=(), directives=())
                                for name in ("__typename", *(k for k, _ in keys))
                            )
                        ),
                    ),
                )
            ),
        )
    document = DocumentNode(
        definitions=(
            OperationDefinitionNode(
                operation=OperationType.QUERY,
                directives=(),
                variable_definitions=definitions,
                selection_set=SelectionSetNode(selections=(field,)),
            ),
        )
    )
    if validate(native, document):
        raise SafeExecutionValidationError(
            "Retained schema is incompatible with the fixed federation request."
        )
    query = print_ast(document)
    if query.startswith("{"):
        query = "query " + query
    return FederationPlan(
        probe,
        query,
        variables,
        FederationPolicy.DENY
        if deny_sdl or probe is FederationProbe.ENTITY
        else FederationPolicy.OBSERVE,
        tuple(keys),
    )


@dataclass(frozen=True)
class FederationObservation:
    outcome: FederationOutcome
    sdl_bytes: int | None = None
    sdl_sha256: str | None = None


def classify_federation_response(
    status: int, body: bytes, plan: FederationPlan
) -> FederationObservation:
    operation = "_service" if plan.probe is FederationProbe.SERVICE else "_entities"
    coarse = classify_authentication_response(status, body, operation)
    if coarse is NestedOutcome.EXPLICIT_DENIAL:
        return FederationObservation(FederationOutcome.EXPLICIT_DENIAL)
    indeterminate = FederationObservation(FederationOutcome.INDETERMINATE)
    try:
        document = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        return indeterminate
    # Denials at a selected leaf are applicable too; unrelated response paths are not.
    errors = document.get("errors") if isinstance(document, dict) else None
    paths = (
        ((operation, "sdl"),)
        if plan.probe is FederationProbe.SERVICE
        else tuple((operation, key) for key in ("__typename", *(key for key, _ in plan.key_types)))
    )
    if (
        isinstance(errors, list)
        and errors
        and all(
            any(explicit_authorization_error(error, path) for path in paths) for error in errors
        )
    ):
        return FederationObservation(FederationOutcome.EXPLICIT_DENIAL)
    if coarse is not NestedOutcome.RETURNED:
        return indeterminate
    if "errors" in document and document["errors"] not in (None, []):
        return indeterminate
    value = document["data"][operation]
    if plan.probe is FederationProbe.SERVICE:
        sdl = value.get("sdl") if isinstance(value, dict) else None
        if not isinstance(sdl, str) or not sdl.strip():
            return indeterminate
        try:
            encoded = sdl.encode("utf-8")
        except UnicodeError:
            return indeterminate
        return FederationObservation(
            FederationOutcome.SDL_RETURNED, len(encoded), hashlib.sha256(encoded).hexdigest()
        )
    cases = plan.variables.get("representations")
    if not isinstance(cases, list) or len(cases) != 1 or not isinstance(cases[0], dict):
        return indeterminate
    expected = cases[0]
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        return indeterminate
    returned = value[0]
    if returned.get("__typename") != expected["__typename"]:
        return indeterminate
    for key, kind in plan.key_types:
        actual, wanted = returned.get(key), expected[key]
        if kind == "ID":
            if not exact_id_matches(actual, str(wanted)):
                return indeterminate
        elif type(actual) is not type(wanted) or actual != wanted:
            return indeterminate
    return FederationObservation(FederationOutcome.ENTITY_RETURNED)
