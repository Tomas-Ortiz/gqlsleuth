"""Pure structural handoff hints, separate from candidates, evidence and runtime IDs."""

from collections.abc import Mapping
from dataclasses import dataclass

from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.object_authorization import ObjectAuthorizationCase, ObjectAuthorizationMode
from gqlsleuth.domain.schema import ParsedSchema
from gqlsleuth.domain.security_review import (
    GraphQLSecurityReviewCandidate,
    GraphQLSecurityReviewResult,
    SecurityCandidateType,
)
from gqlsleuth.graphql.object_authorization import object_fields

FOLLOW_UP_NOTICE = (
    "Supply a known runtime object identifier. Schema analysis does not establish which IDs "
    "are valid. <CONTEXT> is an operator-supplied label, not an inferred owner. "
    "Use --object-auth-review for object authorization. Sequential object discovery requires "
    "--mode active --idor-discovery and a known canonical numeric ID; the schema does not "
    "establish numeric or sequential identifiers."
)


@dataclass(frozen=True)
class ObjectLookupFollowUpHint:
    endpoint: str
    operation: str
    identifier_argument: str
    identifier_type: str
    return_type: str
    object_auth_case_template: str
    differential_object_auth_case_template: str
    sequential_discovery_seed_template: str
    object_authorization_compatible: bool = True
    sequential_discovery_compatible: bool = True


def object_lookup_follow_up(
    candidate: GraphQLSecurityReviewCandidate, schema: ParsedSchema
) -> ObjectLookupFollowUpHint | None:
    """Reuse the structural gate called by both runtime paths through build_object_query.

    This says nothing about a generated artifact, a runtime identifier, or target access.
    More than one accepted argument is ambiguous: runtime callers explicitly choose an
    argument, whereas schema-only guidance must not invent that choice.
    """
    if candidate.candidate_type is not SecurityCandidateType.OBJECT_LOOKUP_REVIEW:
        return None
    root = schema.type_named(schema.query_root)
    field = (
        next((item for item in root.fields if candidate.subject == f"query {item.name}"), None)
        if root
        else None
    )
    if field is None:
        return None
    eligible = []
    for argument in field.arguments:
        case = ObjectAuthorizationCase(
            ObjectAuthorizationMode.ANONYMOUS_ONLY,
            None,
            field.name,
            argument.name,
            "<ID>",
            1,
        )
        try:
            object_fields(schema, case)
        except SafeExecutionValidationError:
            continue
        eligible.append(argument)
    if len(eligible) != 1:
        return None
    argument = eligible[0]
    reference = f"{field.name}:{argument.name}="
    return ObjectLookupFollowUpHint(
        candidate.endpoint,
        field.name,
        argument.name,
        argument.type.render(),
        field.type.render(),
        reference + "<ID>",
        "<CONTEXT>:" + reference + "<ID>",
        reference + "<NUMERIC_ID>",
    )


def object_lookup_follow_ups(
    review: GraphQLSecurityReviewResult | None, schemas: Mapping[str, ParsedSchema]
) -> tuple[ObjectLookupFollowUpHint, ...]:
    hints = []
    for candidate in review.candidates if review else ():
        schema = schemas.get(candidate.endpoint)
        if schema is not None:
            hint = object_lookup_follow_up(candidate, schema)
            if hint is not None:
                hints.append(hint)
    return tuple(hints)


def follow_up_commands(hint: ObjectLookupFollowUpHint) -> tuple[tuple[str, str], ...]:
    return (
        ("Object authorization", f'--object-auth-case "{hint.object_auth_case_template}"'),
        (
            "Differential object authorization",
            f'--object-auth-case "{hint.differential_object_auth_case_template}"',
        ),
        ("Sequential object discovery", f'--idor-seed "{hint.sequential_discovery_seed_template}"'),
    )
