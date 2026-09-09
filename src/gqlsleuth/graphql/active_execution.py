"""Defensive Mutation validation and deterministic primary-name safety classification."""

from gqlsleuth.domain.active import MutationDecision, MutationGenerationResult, MutationPreview
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.schema import ParsedSchema
from gqlsleuth.graphql.safe_execution import validate_operation_artifact
from gqlsleuth.rules.operation_analysis import normalize_terms

DESTRUCTIVE_ACTION_TOKENS = (
    "delete",
    "remove",
    "destroy",
    "purge",
    "drop",
    "wipe",
    "erase",
    "burn",
    "truncate",
)


def destructive_tokens(operation_name: str) -> tuple[str, ...]:
    """Inspect only exact identifier tokens, never arguments, output, or interest scores."""
    terms = frozenset(normalize_terms(operation_name))
    return tuple(token for token in DESTRUCTIVE_ACTION_TOKENS if token in terms)


def assess_mutation(
    schema: ParsedSchema | None, artifact: MutationGenerationResult
) -> MutationPreview:
    """Return a controlled decision; no invalid or blocked artifact becomes selectable."""
    if not artifact.success:
        return MutationPreview(
            artifact,
            MutationDecision.GENERATION_FAILED,
            artifact.failure_reason or "No Mutation document was generated.",
        )
    try:
        if schema is None:
            raise SafeExecutionValidationError("Parsed schema is unavailable for this endpoint.")
        validate_operation_artifact(schema, artifact, expected_kind=OperationKind.MUTATION)
    except SafeExecutionValidationError as error:
        return MutationPreview(artifact, MutationDecision.INVALID_ARTIFACT, str(error))
    tokens = destructive_tokens(artifact.operation_name)
    if tokens:
        return MutationPreview(
            artifact,
            MutationDecision.BLOCKED_SAFETY,
            f"Destructive action token(s): {', '.join(tokens)}.",
        )
    return MutationPreview(
        artifact,
        MutationDecision.EXECUTABLE,
        "State-changing operation; explicit selection and final batch confirmation required.",
    )
