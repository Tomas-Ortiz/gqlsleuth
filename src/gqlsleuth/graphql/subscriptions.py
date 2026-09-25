"""Local Subscription validation and conservative event interpretation."""

import json
from copy import deepcopy
from urllib.parse import urlsplit, urlunsplit

from graphql import GraphQLSchema, OperationType, get_variable_values, parse, validate
from graphql.language import FieldNode, OperationDefinitionNode
from pydantic import JsonValue

from gqlsleuth.domain.exceptions import HttpConfigurationError, SafeExecutionValidationError
from gqlsleuth.domain.schema import ParsedSchema
from gqlsleuth.domain.subscriptions import SubscriptionCandidate, SubscriptionOutcome
from gqlsleuth.graphql.authorization_response import explicit_authorization_error


def decode_subscription_object(text: str) -> dict[str, JsonValue]:
    """Reject ambiguous/non-JSON protocol objects as well as operator input."""

    def unique(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject(value: str) -> None:
        raise ValueError

    result = json.loads(text, object_pairs_hook=unique, parse_constant=reject)
    if type(result) is not dict:
        raise ValueError
    json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return result


def parse_subscription_object(values: list[str]) -> dict[str, JsonValue] | None:
    """Strict bounded JSON; diagnostics never include potentially secret input."""
    if not values:
        return None
    try:
        if len(values) != 1 or len(values[0].encode("utf-8")) > 4096:
            raise ValueError
        return decode_subscription_object(values[0])
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise HttpConfigurationError(
            "Supply one valid UTF-8 JSON object, at most 4096 bytes, without duplicate keys."
        ) from None


def websocket_url(endpoint: str, override: str | None = None) -> str:
    """Allow only the corresponding HTTP(S) credential origin, including effective port."""
    try:
        original = urlsplit(endpoint)
        scheme = {"http": "ws", "https": "wss"}[original.scheme]
        result = override if override is not None else urlunsplit(original._replace(scheme=scheme))
        parsed = urlsplit(result)
        if (
            len(result.encode("utf-8")) > 4096
            or parsed.scheme not in {"ws", "wss"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "#" in result
            or "\\" in result
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in result)
            or parsed.scheme != scheme
            or parsed.hostname != original.hostname
            or (parsed.port or (443 if parsed.scheme == "wss" else 80))
            != (original.port or (443 if original.scheme == "https" else 80))
            or parsed.port == 0
        ):
            raise ValueError
        return result
    except (ValueError, KeyError, UnicodeError):
        raise HttpConfigurationError(
            "WebSocket URL must be a bounded absolute ws/wss URL on the retained HTTP origin, "
            "without credentials or fragment."
        ) from None


def validate_subscription(
    schema: ParsedSchema,
    native: GraphQLSchema,
    candidate: SubscriptionCandidate,
    overrides: dict[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    root = schema.type_named(schema.subscription_root) if schema.subscription_root else None
    if (
        not root
        or candidate.root != root.name
        or candidate.field not in root.fields
        or candidate.query is None
        or candidate.variables is None
        or candidate.failure
    ):
        raise SafeExecutionValidationError("Requires a generated retained Subscription-root field.")
    document = parse(candidate.query)
    operation = document.definitions[0] if len(document.definitions) == 1 else None
    if (
        not isinstance(operation, OperationDefinitionNode)
        or operation.operation is not OperationType.SUBSCRIPTION
        or operation.name is not None
        or len(operation.selection_set.selections) != 1
    ):
        raise SafeExecutionValidationError("Requires exactly one anonymous Subscription operation.")
    field = operation.selection_set.selections[0]
    if (
        not isinstance(field, FieldNode)
        or field.alias
        or field.name.value != candidate.field.name
        or field.name.value.startswith("__")
        or validate(native, document)
    ):
        raise SafeExecutionValidationError(
            "Subscription document does not match its retained schema field."
        )
    variables = deepcopy(candidate.variables)
    if overrides is not None:
        if set(overrides) - set(variables):
            raise SafeExecutionValidationError(
                "Overrides may replace only existing generated variables."
            )
        variables.update(deepcopy(overrides))
    # Coercion validates, but exact operator JSON types/values remain the transmitted evidence.
    if isinstance(get_variable_values(native, operation.variable_definitions, variables), list):
        raise SafeExecutionValidationError(
            "Subscription variables are incompatible with the retained schema."
        )
    return variables


def classify_subscription_payload(payload: object, root: str) -> SubscriptionOutcome:
    if not isinstance(payload, dict):
        return SubscriptionOutcome.INDETERMINATE
    errors = payload.get("errors")
    if errors:
        return (
            SubscriptionOutcome.EXPLICIT_DENIAL
            if isinstance(errors, list)
            and all(explicit_authorization_error(error, (root,)) for error in errors)
            else SubscriptionOutcome.INDETERMINATE
        )
    if "errors" in payload and errors not in (None, []):
        return SubscriptionOutcome.INDETERMINATE
    data = payload.get("data")
    return (
        SubscriptionOutcome.EVENT_RETURNED
        if isinstance(data, dict) and root in data and data[root] is not None
        else SubscriptionOutcome.INDETERMINATE
    )
