"""Focused generation reuse, forged-artifact validation, and exact-token safety tests."""

from dataclasses import replace

import pytest
from graphql import parse
from graphql.language.ast import OperationDefinitionNode, OperationType

from gqlsleuth.application.active_execution import prepare_active_mutations
from gqlsleuth.domain.active import MutationDecision
from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.exceptions import QueryGenerationError
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.graphql.active_execution import assess_mutation, destructive_tokens
from gqlsleuth.graphql.query_generation import generate_mutation, generate_query


def test_generation_reuses_complete_phase_eight_input_and_selection_semantics(phase_ten_scan):
    arguments = """input: Input!, ids: [ID!]!, when: DateTime!, flag: Boolean!,
                   count: Int!, ratio: Float!, optional: String, defaulted: Int! = 3"""
    safe, _ = phase_ten_scan(f"""
        scalar DateTime
        enum State {{ ARCHIVED @deprecated OPEN }}
        input Input {{ state: State!, text: String!, optional: Int, defaulted: Int! = 2 }}
        type Output {{ name: String id: ID! }}
        type Query {{ inspect({arguments}): Output }}
        type Mutation {{ create({arguments}): Output }}
    """)
    analysis = safe.query_generation.operation_analysis
    schema = analysis.schema_scan.schemas[0].schema
    operations = analysis.endpoints[0].operations
    query = generate_query(schema, next(op for op in operations if op.kind is OperationKind.QUERY))
    mutation = generate_mutation(
        schema, next(op for op in operations if op.kind is OperationKind.MUTATION)
    )
    assert (
        mutation.variables
        == query.variables
        == {
            "input": {"state": "OPEN", "text": "test"},
            "ids": ["1"],
            "when": "test",
            "flag": False,
            "count": 1,
            "ratio": 1.0,
        }
    )
    assert mutation.manual_adjustments == query.manual_adjustments
    assert "DateTime" in mutation.manual_adjustments[0]
    assert mutation.query_text == query.query_text.replace("query", "mutation", 1).replace(
        "inspect(", "create("
    )
    document = parse(mutation.query_text)
    operation = document.definitions[0]
    assert isinstance(operation, OperationDefinitionNode)
    assert operation.name is None
    assert operation.operation is OperationType.MUTATION
    assert "operationName" not in mutation.query_text


def test_only_actual_mutation_roots_are_generated_and_query_api_stays_strict(phase_ten_scan):
    safe, _ = phase_ten_scan("""
        schema { query: Reads mutation: Writes subscription: Events }
        type Reads { createUser: String }
        type Writes { health: String }
        type Events { updates: String }
    """)
    preview = prepare_active_mutations(safe)
    assert [item.generated_mutation.operation_name for item in preview.candidates] == ["health"]
    schema = safe.query_generation.operation_analysis.schema_scan.schemas[0].schema
    query = safe.query_generation.queries[0]
    with pytest.raises(QueryGenerationError, match="Only Mutation-root"):
        generate_mutation(schema, query.operation)
    with pytest.raises(QueryGenerationError, match="Only Query-root"):
        generate_query(schema, preview.candidates[0].generated_mutation.operation)


def test_generation_failure_isolated_and_safe_generation_disabled(phase_ten_scan):
    sdl = """
        input Cycle { children: [Cycle!]! }
        type Query { health: String }
        type Mutation { broken(input: Cycle!): String createPaste: String }
    """
    active, _ = phase_ten_scan(sdl)
    preview = prepare_active_mutations(active)
    assert [item.decision for item in preview.candidates] == [
        MutationDecision.GENERATION_FAILED,
        MutationDecision.EXECUTABLE,
    ]
    assert "cycle" in preview.candidates[0].reason.lower()
    safe, _ = phase_ten_scan(sdl, mode=ScanMode.SAFE)
    assert prepare_active_mutations(safe).candidates == ()


@pytest.mark.parametrize(
    "document",
    [
        "query { createUser }",
        "subscription { createUser }",
        "mutation { createUser } mutation { createUser }",
        "mutation { createUser } query { health }",
        "mutation { updateProfile }",
        "mutation { createUser updateProfile }",
        "mutation { ...Fields } fragment Fields on Mutation { createUser }",
        "not graphql",
        "fragment Fields on Mutation { createUser }",
        "mutation Named { createUser }",
        "mutation { alias: createUser }",
    ],
)
def test_forged_documents_never_become_selectable(phase_ten_scan, document):
    safe, _ = phase_ten_scan()
    preview = prepare_active_mutations(safe)
    artifact = next(
        item.generated_mutation
        for item in preview.candidates
        if item.generated_mutation.operation_name == "createUser"
    )
    schema = safe.query_generation.operation_analysis.schema_scan.schemas[0].schema
    assessed = assess_mutation(schema, replace(artifact, query_text=document))
    assert assessed.decision is MutationDecision.INVALID_ARTIFACT
    assert not assessed.selectable


def test_forged_metadata_missing_root_and_inconsistent_failure_are_rejected(phase_ten_scan):
    safe, _ = phase_ten_scan()
    artifact = prepare_active_mutations(safe).candidates[0].generated_mutation
    schema = safe.query_generation.operation_analysis.schema_scan.schemas[0].schema
    for forged in (
        replace(artifact, operation=replace(artifact.operation, kind=OperationKind.QUERY)),
        replace(artifact, operation=replace(artifact.operation, name="missing")),
        replace(artifact, failure_reason="failed"),
    ):
        assert assess_mutation(schema, forged).decision is MutationDecision.INVALID_ARTIFACT
    assert (
        assess_mutation(replace(schema, mutation_root=None), artifact).decision
        is MutationDecision.INVALID_ARTIFACT
    )
    assert assess_mutation(None, artifact).decision is MutationDecision.INVALID_ARTIFACT


@pytest.mark.parametrize(
    "token", ["delete", "remove", "destroy", "purge", "drop", "wipe", "erase", "burn", "truncate"]
)
@pytest.mark.parametrize("style", ["{token}User", "{title}User", "user_{token}", "user-{token}"])
def test_destructive_exact_tokens_across_identifier_styles(token, style):
    assert destructive_tokens(style.format(token=token, title=token.title())) == (token,)


@pytest.mark.parametrize(
    "name",
    [
        "assetUpdate",
        "burnishedHistory",
        "dropper",
        "undeleteUser",
        "createUser",
        "updateProfile",
        "setPreference",
    ],
)
def test_substring_collisions_and_normal_actions_are_selectable_by_name(name):
    assert destructive_tokens(name) == ()


def test_safety_ignores_arguments_output_fields_and_interest_score(phase_ten_scan):
    safe, _ = phase_ten_scan("""
        type Query { health: String }
        type Mutation { createUser(delete: String!): Output }
        type Output { purge: String burn: String }
    """)
    preview = prepare_active_mutations(safe)
    assert preview.candidates[0].selectable
