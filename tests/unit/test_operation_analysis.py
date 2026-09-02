"""Focused tests for deterministic Phase 7 operation analysis."""

from gqlsleuth.domain.analysis import (
    InterestPriority,
    OperationCategory,
    OperationKind,
    OperationRule,
    PriorityThresholds,
    RuleSet,
)
from gqlsleuth.domain.schema import (
    ParsedSchema,
    SchemaArgument,
    SchemaField,
    SchemaInputField,
    SchemaNamedType,
    SchemaSummary,
    SchemaTypeKind,
    TypeReference,
)
from gqlsleuth.rules.loader import load_bundled_rules
from gqlsleuth.rules.operation_analysis import analyze_schema_operations, normalize_terms

ENDPOINT = "https://example.com/graphql"


def test_identifier_normalization_supports_common_styles_without_substrings() -> None:
    assert normalize_terms("resetPassword AdminUser auth_token file-upload") == (
        "reset",
        "password",
        "admin",
        "user",
        "auth",
        "token",
        "file",
        "upload",
    )
    assert "user" not in normalize_terms("business")


def test_root_fields_use_actual_query_and_mutation_kinds_with_fallback_categories() -> None:
    schema = _schema(
        query_fields=(SchemaField(name="business", type=TypeReference.named("String")),),
        mutation_fields=(SchemaField(name="rotate", type=TypeReference.named("String")),),
    )
    rules = _rules(_rule("users", OperationCategory.USER_MANAGEMENT, ("user",), 2))

    operations = analyze_schema_operations(ENDPOINT, schema, rules)
    by_name = {operation.name: operation for operation in operations}

    assert by_name["business"].kind is OperationKind.QUERY
    assert by_name["business"].categories == (OperationCategory.READ_ONLY_BUSINESS_DATA,)
    assert by_name["rotate"].kind is OperationKind.MUTATION
    assert by_name["rotate"].categories == (OperationCategory.STATE_CHANGING_BUSINESS_OPERATION,)
    assert all(operation.priority is InterestPriority.INFORMATIONAL for operation in operations)


def test_analysis_uses_descriptions_arguments_and_one_hop_input_and_return_fields() -> None:
    operation = SchemaField(
        name="inspectAccount",
        description="Authenticate a profile.",
        arguments=(SchemaArgument(name="credentials", type=TypeReference.named("LoginInput")),),
        type=TypeReference.named("AuthPayload"),
    )
    schema = _schema(
        query_fields=(operation,),
        extra_types=(
            SchemaNamedType(
                name="LoginInput",
                kind=SchemaTypeKind.INPUT_OBJECT,
                input_fields=(
                    SchemaInputField(name="password", type=TypeReference.named("SecretText")),
                ),
            ),
            SchemaNamedType(
                name="AuthPayload",
                kind=SchemaTypeKind.OBJECT,
                fields=(
                    SchemaField(
                        name="sessionToken",
                        description="Issued token.",
                        type=TypeReference.named("SessionID"),
                    ),
                ),
            ),
        ),
    )
    rule = _rule(
        "surface",
        OperationCategory.AUTHENTICATION,
        (
            "inspect",
            "authenticate",
            "credentials",
            "login",
            "password",
            "secret",
            "auth",
            "session",
            "token",
        ),
        3,
    )

    result = analyze_schema_operations(ENDPOINT, schema, _rules(rule))[0]
    match = result.matched_rules[0]

    assert result.interest_score == 3
    assert result.priority is InterestPriority.MEDIUM_INTEREST
    assert {
        "operation.name",
        "description",
        "argument.credentials",
        "argument_type.LoginInput",
        "input_field.password",
        "input_field_type.SecretText",
        "return_type.AuthPayload",
        "return_field.sessionToken",
        "return_field_description.sessionToken",
        "return_field_type.SessionID",
    }.issubset(match.locations)


def test_each_rule_scores_once_while_distinct_rules_accumulate() -> None:
    schema = _schema(
        query_fields=(
            SchemaField(
                name="createToken",
                description="Create a token for this session.",
                type=TypeReference.named("TokenPayload"),
            ),
        ),
        extra_types=(
            SchemaNamedType(
                name="TokenPayload",
                kind=SchemaTypeKind.OBJECT,
                fields=(SchemaField(name="token", type=TypeReference.named("String")),),
            ),
        ),
    )
    rules = _rules(
        _rule("tokens", OperationCategory.TOKENS_AND_SESSIONS, ("token", "session"), 3),
        _rule(
            "state_change",
            OperationCategory.STATE_CHANGING_BUSINESS_OPERATION,
            ("create",),
            2,
        ),
    )

    result = analyze_schema_operations(ENDPOINT, schema, rules)[0]

    assert result.interest_score == 5
    assert result.priority is InterestPriority.HIGH_INTEREST
    assert [match.rule_id for match in result.matched_rules] == ["tokens", "state_change"]
    assert result.matched_rules[0].weight == 3
    assert len(result.matched_rules[0].locations) > 1


def test_categories_are_deduplicated_and_results_sort_deterministically() -> None:
    schema = _schema(
        query_fields=(
            SchemaField(name="user", type=TypeReference.named("String")),
            SchemaField(name="adminUser", type=TypeReference.named("String")),
        ),
        mutation_fields=(SchemaField(name="deleteUser", type=TypeReference.named("String")),),
    )
    rules = _rules(
        _rule("users", OperationCategory.USER_MANAGEMENT, ("user",), 2),
        _rule("accounts", OperationCategory.USER_MANAGEMENT, ("account", "user"), 1),
        _rule("admin", OperationCategory.ADMINISTRATIVE_FUNCTIONALITY, ("admin",), 3),
        _rule(
            "state_change",
            OperationCategory.STATE_CHANGING_BUSINESS_OPERATION,
            ("delete",),
            2,
        ),
    )

    operations = analyze_schema_operations(ENDPOINT, schema, rules)

    assert [operation.name for operation in operations] == ["adminUser", "deleteUser", "user"]
    assert operations[0].interest_score == 6
    assert operations[0].categories == (
        OperationCategory.USER_MANAGEMENT,
        OperationCategory.ADMINISTRATIVE_FUNCTIONALITY,
    )


def test_configured_thresholds_define_each_interest_priority() -> None:
    thresholds = PriorityThresholds(critical=8, high=5, medium=3, low=1)

    assert thresholds.priority_for(8) is InterestPriority.CRITICAL_INTEREST
    assert thresholds.priority_for(5) is InterestPriority.HIGH_INTEREST
    assert thresholds.priority_for(3) is InterestPriority.MEDIUM_INTEREST
    assert thresholds.priority_for(1) is InterestPriority.LOW_INTEREST
    assert thresholds.priority_for(0) is InterestPriority.INFORMATIONAL


def test_bundled_rules_classify_plural_camel_case_review_candidates() -> None:
    schema = _schema(
        query_fields=(SchemaField(name="exportUsers", type=TypeReference.named("String")),),
        mutation_fields=(SchemaField(name="resetPassword", type=TypeReference.named("String")),),
    )

    by_name = {
        operation.name: operation
        for operation in analyze_schema_operations(ENDPOINT, schema, load_bundled_rules())
    }

    assert by_name["exportUsers"].priority is InterestPriority.HIGH_INTEREST
    assert OperationCategory.USER_MANAGEMENT in by_name["exportUsers"].categories
    assert OperationCategory.FILES_AND_UPLOADS in by_name["exportUsers"].categories
    assert by_name["resetPassword"].interest_score == 6
    assert by_name["resetPassword"].priority is InterestPriority.HIGH_INTEREST


def _rule(
    rule_id: str,
    category: OperationCategory,
    keywords: tuple[str, ...],
    weight: int,
) -> OperationRule:
    return OperationRule(
        id=rule_id,
        category=category,
        keywords=keywords,
        weight=weight,
        reason=f"{rule_id} terminology.",
    )


def _rules(*rules: OperationRule) -> RuleSet:
    return RuleSet(
        thresholds=PriorityThresholds(critical=8, high=5, medium=3, low=1),
        rules=rules,
    )


def _schema(
    *,
    query_fields: tuple[SchemaField, ...],
    mutation_fields: tuple[SchemaField, ...] = (),
    extra_types: tuple[SchemaNamedType, ...] = (),
) -> ParsedSchema:
    roots = [SchemaNamedType(name="Query", kind=SchemaTypeKind.OBJECT, fields=query_fields)]
    mutation_root: str | None = None
    if mutation_fields:
        mutation_root = "Mutation"
        roots.append(
            SchemaNamedType(name="Mutation", kind=SchemaTypeKind.OBJECT, fields=mutation_fields)
        )
    roots.extend(extra_types)
    roots.append(SchemaNamedType(name="String", kind=SchemaTypeKind.SCALAR))
    summary = SchemaSummary(
        query_root="Query",
        mutation_root=mutation_root,
        subscription_root=None,
        total_type_count=len(roots),
        object_type_count=1 + int(mutation_root is not None),
        input_object_type_count=0,
        scalar_type_count=1,
        custom_scalar_type_count=0,
        enum_type_count=0,
        interface_type_count=0,
        union_type_count=0,
        directive_count=0,
        query_field_count=len(query_fields),
        mutation_field_count=len(mutation_fields),
        subscription_field_count=0,
    )
    return ParsedSchema(
        query_root="Query",
        mutation_root=mutation_root,
        subscription_root=None,
        types=tuple(roots),
        directives=(),
        summary=summary,
    )
