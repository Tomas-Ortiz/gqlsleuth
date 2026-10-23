"""Readable review labels and explanations; canonical rule facts remain untouched."""

import re

from gqlsleuth.domain.analysis import RuleMatch

_CATEGORY_LABELS = {
    "tokens_and_sessions": "Tokens and sessions",
    "secrets_and_credentials": "Credentials and secrets",
    "user_management": "User management",
    "personal_information": "Personal information",
    "files_and_uploads": "Files and uploads",
    "read_only_business_data": "Read-only business data",
    "password_credentials": "Password credentials",
    "state_changing_business_operation": "Business operations that may modify data",
}
_LOCATION_LABELS = {
    "operation.name": "the operation name",
    "operation.description": "the operation description",
    "argument": "operation arguments",
    "argument_description": "argument descriptions",
    "argument_type": "argument types",
    "input_field": "input fields",
    "input_field_description": "input field descriptions",
    "input_field_type": "input field types",
    "return_field": "returned fields",
    "return_field_description": "returned field descriptions",
    "return_field_type": "returned field types",
    "return_type": "returned types",
}
_SAFETY_REASON = re.compile(
    r"Query name contains explicit state-changing action token\(s\): "
    r"([a-z]+(?:, [a-z]+)*)\."
)


def category_label(value: str) -> str:
    """Known category labels, with a readable fallback for future rule identifiers."""
    readable = value.replace("_", " ").strip()
    return _CATEGORY_LABELS.get(value, readable[:1].upper() + readable[1:])


def rule_explanation(match: RuleMatch) -> str:
    """Explain matching surfaces first, retaining exact locations and score contribution."""
    keywords = ", ".join(f'"{word}"' for word in match.matched_keywords)
    surfaces = tuple(
        dict.fromkeys(
            _LOCATION_LABELS.get(
                location, _LOCATION_LABELS.get(location.partition(".")[0], "schema metadata")
            )
            for location in match.locations
        )
    )
    location_label = "Technical location" if len(match.locations) == 1 else "Technical locations"
    return (
        f"{category_label(match.category.value)}: {match.reason} "
        f"Matched {keywords} in {', '.join(surfaces)} (+{match.weight}). "
        f"{location_label}: {', '.join(match.locations)}."
    )


def execution_reason(text: str) -> str:
    """Translate only the engine's exact precautionary Query skip reason, not server text."""
    match = _SAFETY_REASON.fullmatch(text)
    if match is None:
        return text
    actions = ", ".join(f'"{word}"' for word in match[1].split(", "))
    return (
        "Safe Query execution skipped this query as a precaution because its name "
        f"contains an action that may modify data: {actions}."
    )
