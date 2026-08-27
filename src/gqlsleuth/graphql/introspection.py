"""Static introspection queries and deterministic response classification."""

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

MINIMAL_INTROSPECTION_QUERY = """{
  __schema {
    queryType {
      name
    }
  }
}"""

FULL_INTROSPECTION_QUERY = """query {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
  inputFields { ...InputValue }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}"""

INTROSPECTION_DISABLED_MARKERS = (
    "introspection is disabled",
    "introspection has been disabled",
    "introspection is not allowed",
    "introspection is forbidden",
    "introspection access is disabled",
    "introspection access is forbidden",
    "__schema is disabled",
    "__schema is forbidden",
    'cannot query field "__schema"',
    "cannot query field '__schema'",
)


class IntrospectionStatus(StrEnum):
    """Deterministic outcome of an introspection request."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    AUTHENTICATION_REQUIRED = "authentication_required"
    AUTHORIZATION_DENIED = "authorization_denied"
    ENDPOINT_ERROR = "endpoint_error"
    INVALID_RESPONSE = "invalid_response"
    NETWORK_FAILURE = "network_failure"


@dataclass(frozen=True)
class IntrospectionResponseClassification:
    """Status and concise reason derived from one HTTP response."""

    status: IntrospectionStatus
    reason: str


def classify_introspection_response(
    status_code: int,
    body: bytes,
) -> IntrospectionResponseClassification:
    """Classify an introspection response without parsing schema contents."""
    if status_code == 401:
        return IntrospectionResponseClassification(
            IntrospectionStatus.AUTHENTICATION_REQUIRED,
            "HTTP 401 requires authentication.",
        )
    if status_code == 403:
        return IntrospectionResponseClassification(
            IntrospectionStatus.AUTHORIZATION_DENIED,
            "HTTP 403 denied authorization.",
        )

    document = _json_object(body)
    if document is not None and _has_schema_object(document):
        return IntrospectionResponseClassification(
            IntrospectionStatus.ENABLED,
            "Response contains a data.__schema object.",
        )

    messages = _error_messages(document)
    disabled_message = next(
        (
            message
            for message in messages
            if any(marker in message.casefold() for marker in INTROSPECTION_DISABLED_MARKERS)
        ),
        None,
    )
    if disabled_message is not None:
        return IntrospectionResponseClassification(
            IntrospectionStatus.DISABLED,
            "GraphQL error indicates introspection is disabled: "
            f'"{_short_message(disabled_message)}"',
        )
    if messages:
        return IntrospectionResponseClassification(
            IntrospectionStatus.ENDPOINT_ERROR,
            f'GraphQL error prevented introspection: "{_short_message(messages[0])}"',
        )
    if status_code >= 400:
        return IntrospectionResponseClassification(
            IntrospectionStatus.ENDPOINT_ERROR,
            f"HTTP {status_code} prevented introspection.",
        )
    return IntrospectionResponseClassification(
        IntrospectionStatus.INVALID_RESPONSE,
        "Response does not contain a valid data.__schema object or GraphQL error.",
    )


def _has_schema_object(document: dict[str, object]) -> bool:
    data = document.get("data")
    if not isinstance(data, dict):
        return False
    typed_data = cast(dict[str, object], data)
    return isinstance(typed_data.get("__schema"), dict)


def _error_messages(document: dict[str, object] | None) -> tuple[str, ...]:
    if document is None:
        return ()
    errors = document.get("errors")
    if not isinstance(errors, list):
        return ()
    messages: list[str] = []
    for raw_error in errors:
        if not isinstance(raw_error, dict):
            continue
        error = cast(dict[str, object], raw_error)
        message = error.get("message")
        if isinstance(message, str):
            messages.append(message)
    return tuple(messages)


def _json_object(body: bytes) -> dict[str, object] | None:
    try:
        value: object = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    return cast(dict[str, object], value)


def _short_message(message: str) -> str:
    compact = " ".join(message.split())
    return compact if len(compact) <= 120 else f"{compact[:117]}..."
