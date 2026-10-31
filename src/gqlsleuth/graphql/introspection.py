"""Static introspection queries and deterministic response classification."""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from gqlsleuth.graphql.response_json import response_json_object

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

# Three ofType relationships cover [String!]! without the full query's seven.
# Descriptions are omitted; structural, default and deprecation facts are retained.
REDUCED_INTROSPECTION_QUERY = """query {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args { ...ReducedInput }
        type { ...ReducedTypeRef }
        isDeprecated
        deprecationReason
      }
      interfaces { kind name }
      possibleTypes { kind name }
      inputFields { ...ReducedInput }
      enumValues(includeDeprecated: true) { name isDeprecated deprecationReason }
    }
    directives { name locations args { ...ReducedInput } }
  }
}
fragment ReducedInput on __InputValue {
  name
  type { ...ReducedTypeRef }
  defaultValue
}
fragment ReducedTypeRef on __Type {
  kind name
  ofType {
    kind name
    ofType {
      kind name
      ofType { kind name }
    }
  }
}"""


class IntrospectionFallbackReason(StrEnum):
    """Explicit request restriction, never an inference from a generic failure."""

    DEPTH_LIMIT = "depth_limit"
    COMPLEXITY_LIMIT = "complexity_limit"
    COST_LIMIT = "cost_limit"


_RESTRICTION_CODES = {
    "QUERY_TOO_DEEP": IntrospectionFallbackReason.DEPTH_LIMIT,
    "MAX_DEPTH_EXCEEDED": IntrospectionFallbackReason.DEPTH_LIMIT,
    "QUERY_TOO_COMPLEX": IntrospectionFallbackReason.COMPLEXITY_LIMIT,
    "COMPLEXITY_LIMIT_EXCEEDED": IntrospectionFallbackReason.COMPLEXITY_LIMIT,
    "COST_LIMIT_EXCEEDED": IntrospectionFallbackReason.COST_LIMIT,
}
_DENIAL = re.compile(
    r"\b(?:authentication (?:is )?required|authorization (?:was )?denied|"
    r"unauthenticated|unauthorized|"
    r"forbidden|access denied|permission denied)\b|cannot query field [\"']?__schema\b"
)
_RESTRICTIONS = tuple(
    (
        reason,
        re.compile(
            rf"\b(?:query {word}(?: limit)? (?:is )?exceeded|"
            rf"(?:maximum|max) {'(?:query )?' if word == 'depth' else 'query '}{word}\b|"
            rf"query (?:is )?too {adjective}|{word} limit exceeded)\b"
        ),
    )
    for word, adjective, reason in (
        ("depth", "deep", IntrospectionFallbackReason.DEPTH_LIMIT),
        ("complexity", "complex", IntrospectionFallbackReason.COMPLEXITY_LIMIT),
        ("cost", "costly", IntrospectionFallbackReason.COST_LIMIT),
    )
)


def reduced_introspection_fallback_reason(
    status_code: int, body: bytes
) -> IntrospectionFallbackReason | None:
    """Recognize explicit GraphQL request limits; denials/outages take precedence."""
    # A 413 is eligible only through the same explicit GraphQL restriction checks
    # below; a generic payload-size/CDN rejection is not a query-shape signal.
    if not (200 <= status_code < 300 or status_code in {400, 413, 422}):
        return None
    document = response_json_object(body)
    if document is None or _has_schema_object(document):
        return None
    errors = document.get("errors")
    if not isinstance(errors, list):
        return None
    reasons = []
    for error in errors:
        if not isinstance(error, dict) or not isinstance(error.get("message"), str):
            return None
        message = " ".join(error["message"].casefold().split())
        extensions = error.get("extensions")
        code = extensions.get("code") if isinstance(extensions, dict) else None
        code = code.upper() if isinstance(code, str) else ""
        if (
            _DENIAL.search(message)
            or _DENIAL.search(message.replace("_", " "))
            or re.search(r"\bintrospection\b.*\b(?:disabled|not allowed|forbidden)\b", message)
            or any(marker in message for marker in INTROSPECTION_DISABLED_MARKERS)
            or code
            in {
                "AUTHENTICATION_REQUIRED",
                "AUTHORIZATION_DENIED",
                "UNAUTHENTICATED",
                "UNAUTHORIZED",
                "FORBIDDEN",
                "INTROSPECTION_DISABLED",
            }
        ):
            return None
        reason = _RESTRICTION_CODES.get(code) or next(
            (reason for reason, pattern in _RESTRICTIONS if pattern.search(message)), None
        )
        # Mixed unrelated errors do not establish a narrowly eligible rejection.
        if reason is None:
            return None
        reasons.append(reason)
    return reasons[0] if reasons else None


class IntrospectionStatus(StrEnum):
    """Deterministic outcome of an introspection request."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    AUTHENTICATION_REQUIRED = "authentication_required"
    AUTHORIZATION_DENIED = "authorization_denied"
    ENDPOINT_ERROR = "endpoint_error"
    INVALID_RESPONSE = "invalid_response"
    NETWORK_FAILURE = "network_failure"


class SchemaRetrievalStatus(StrEnum):
    """Schema source outcome, separate from demonstrated introspection support."""

    NOT_ATTEMPTED = "not_attempted"
    RETRIEVED = "retrieved"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    FAILED = "failed"


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

    document = response_json_object(body)
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


def _short_message(message: str) -> str:
    compact = " ".join(message.split())
    return compact if len(compact) <= 120 else f"{compact[:117]}..."
