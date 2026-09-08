"""Focused tests for Phase 9 safety validation and response classification."""

import pytest

from gqlsleuth.domain.analysis import (
    InterestPriority,
    OperationAnalysis,
    OperationCategory,
    OperationKind,
)
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import (
    ParsedSchema,
    SchemaField,
    SchemaNamedType,
    SchemaSummary,
    SchemaTypeKind,
    TypeReference,
)
from gqlsleuth.graphql.safe_execution import (
    classify_execution_response,
    side_effect_tokens,
    validate_safe_artifact,
)


@pytest.mark.parametrize("name", ["users", "country", "search", "systemDiagnostics"])
def test_ordinary_query_names_are_safe(name: str) -> None:
    validate_safe_artifact(_schema(name), _artifact(name, f"query {{ {name} }}"))
    assert side_effect_tokens(name) == ()


def test_exact_side_effect_tokens_are_detected_without_substring_matches() -> None:
    assert side_effect_tokens("readAndBurn") == ("burn",)
    assert side_effect_tokens("deleteUsers") == ("delete",)
    assert side_effect_tokens("burnishedHistory") == ()


def test_unsafe_or_inconsistent_artifacts_are_rejected() -> None:
    cases = (
        (
            _artifact("users", "query { users }", kind=OperationKind.MUTATION),
            _schema("users"),
            "metadata",
        ),
        (_artifact("users", "mutation { users }"), _schema("users"), "Mutation"),
        (_artifact("users", "subscription { users }"), _schema("users"), "Subscription"),
        (_artifact("missing", "query { missing }"), _schema("users"), "not present"),
        (_artifact("users", "query { country }"), _schema("users", "country"), "top-level"),
        (_artifact("users", "query { users country }"), _schema("users", "country"), "exactly one"),
    )
    for artifact, schema, message in cases:
        with pytest.raises(SafeExecutionValidationError, match=message):
            validate_safe_artifact(schema, artifact)


@pytest.mark.parametrize(
    ("status_code", "body", "expected"),
    (
        (200, b'{"data":{"users":[]}}', QueryExecutionStatus.SUCCESS),
        (200, b'{"errors":[{"message":"Invalid ID"}]}', QueryExecutionStatus.GRAPHQL_ERROR),
        (
            200,
            b'{"data":{"user":null},"errors":[{"message":"Not found"}]}',
            QueryExecutionStatus.GRAPHQL_ERROR,
        ),
        (500, b"server failed", QueryExecutionStatus.HTTP_ERROR),
        (200, b"<html>not graphql</html>", QueryExecutionStatus.INVALID_RESPONSE),
    ),
)
def test_response_classification(
    status_code: int,
    body: bytes,
    expected: QueryExecutionStatus,
) -> None:
    assert classify_execution_response(status_code, body).status is expected


def _artifact(
    name: str,
    query: str,
    *,
    kind: OperationKind = OperationKind.QUERY,
) -> QueryGenerationResult:
    operation = OperationAnalysis(
        endpoint="https://example.com/graphql",
        kind=kind,
        name=name,
        return_type=TypeReference.named("String"),
        categories=(OperationCategory.READ_ONLY_BUSINESS_DATA,),
        interest_score=0,
        priority=InterestPriority.INFORMATIONAL,
        matched_rules=(),
        reasons=(),
    )
    return QueryGenerationResult(
        operation=operation,
        query_text=query,
        variables={},
        manual_adjustments=(),
        failure_reason=None,
    )


def _schema(*field_names: str) -> ParsedSchema:
    fields = tuple(
        SchemaField(name=name, type=TypeReference.named("String")) for name in field_names
    )
    types = (
        SchemaNamedType(name="Query", kind=SchemaTypeKind.OBJECT, fields=fields),
        SchemaNamedType(name="String", kind=SchemaTypeKind.SCALAR),
    )
    return ParsedSchema(
        query_root="Query",
        mutation_root=None,
        subscription_root=None,
        types=types,
        directives=(),
        summary=SchemaSummary(
            query_root="Query",
            mutation_root=None,
            subscription_root=None,
            total_type_count=2,
            object_type_count=1,
            input_object_type_count=0,
            scalar_type_count=1,
            custom_scalar_type_count=0,
            enum_type_count=0,
            interface_type_count=0,
            union_type_count=0,
            directive_count=0,
            query_field_count=len(fields),
            mutation_field_count=0,
            subscription_field_count=0,
        ),
    )
