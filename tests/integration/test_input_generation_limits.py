"""Offline adversarial input expansion and shared-generator compatibility regressions."""

import json

import httpx
import pytest
from graphql import build_schema, introspection_from_schema

from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.active import MutationDecision
from gqlsleuth.domain.exceptions import QueryGenerationError
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.schema import TypeReference
from gqlsleuth.graphql import query_generation as generation
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.rules.loader import load_bundled_rules
from gqlsleuth.rules.operation_analysis import analyze_schema_operations


def _inputs(depth, *, branching=False):
    names = ("left", "right") if branching else ("child",)
    return (
        "\n".join(
            f"input I{i} {{ " + " ".join(f"{name}: I{i + 1}!" for name in names) + " }"
            for i in range(depth)
        )
        + f"\ninput I{depth} {{ value: String! }}"
    )


def _schema(sdl):
    return parse_introspection_response(
        json.dumps({"data": introspection_from_schema(build_schema(sdl))}).encode()
    )


def _generate(sdl):
    schema = _schema(sdl)
    operation = analyze_schema_operations(
        "https://example.com/graphql", schema, load_bundled_rules()
    )[0]
    return generation.generate_query(schema, operation)


@pytest.mark.parametrize(
    ("depth", "branching", "reason"), [(500, False, "depth"), (12, True, "expansion")]
)
def test_input_limits_isolate_failure_through_safe_workflow(
    phase_ten_scan, depth, branching, reason
):
    result, requests = phase_ten_scan(
        "type Query { inspect(input: I0!): String ping: String }"
        + _inputs(depth, branching=branching),
        mode=ScanMode.SAFE,
    )
    failed, valid = result.query_generation.queries
    assert failed.operation_name == "inspect"
    assert not failed.success
    assert reason in failed.failure_reason
    assert failed.query_text is None
    assert failed.variables == {}
    assert valid.operation_name == "ping" and valid.success
    assert valid.query_text == "query {\n  ping\n}"
    assert valid.variables == {}
    assert len(requests) == 3  # Minimal/full introspection and only the valid Query.
    assert requests[-1] == {"query": valid.query_text, "variables": {}}
    assert len(result.executions) == 1
    assert [e.query for e in result.query_generation.query_evidence] == [valid.query_text]
    assert [e.query for e in result.execution_evidence] == [valid.query_text]


def test_branching_work_stops_before_document_construction(monkeypatch):
    calls = 0
    original = generation._placeholder

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    def unexpected(*args, **kwargs):
        pytest.fail("An exhausted operation must not reach document construction")

    monkeypatch.setattr(generation, "_placeholder", counted)
    monkeypatch.setattr(generation, "_render_query", unexpected)
    with pytest.raises(QueryGenerationError, match="expansion limit"):
        _generate("type Query { inspect(input: I0!): String }" + _inputs(12, branching=True))
    assert calls == 2049  # 2048 allowed visits, then rejection before allocating a value.


def test_work_limit_is_shared_across_root_arguments():
    fields = " ".join(f"f{i}: String!" for i in range(520))
    _generate("type Query { inspect(a: Input!): String } input Input { " + fields + " }")
    with pytest.raises(QueryGenerationError, match="expansion limit"):
        _generate(
            "type Query { inspect(a: Input!, b: Input!): String } input Input { " + fields + " }"
        )


@pytest.mark.parametrize(("depth", "accepted"), [(30, True), (31, False)])
def test_depth_boundary_counts_non_null_wrappers(depth, accepted):
    sdl = "type Query { inspect(input: I0!): String }" + _inputs(depth)
    if accepted:
        assert _generate(sdl).success  # 64 visits along the path, including the leaf.
    else:
        with pytest.raises(QueryGenerationError, match="depth limit"):
            _generate(sdl)


@pytest.mark.parametrize("branching", [False, True])
def test_mutation_failure_is_not_selectable_or_executable(phase_ten_scan, branching):
    safe, _ = phase_ten_scan(
        "type Query { ping: String }"
        "type Mutation { inspect(input: I0!): String ping: String }"
        + _inputs(12 if branching else 500, branching=branching)
    )
    preview = prepare_active_mutations(safe)
    failed, valid = preview.candidates
    assert failed.generated_mutation.operation_name == "inspect"
    assert failed.decision is MutationDecision.GENERATION_FAILED
    assert not failed.selectable
    assert failed.generated_mutation.query_text is None
    assert failed.generated_mutation.variables == {}
    assert valid.selectable
    assert valid.generated_mutation.query_text == "mutation {\n  ping\n}"

    def unexpected(request):
        pytest.fail("Failed Mutation generation must never send HTTP")

    with HttpClient(transport=httpx.MockTransport(unexpected)) as client:
        result = execute_selected_mutations(
            preview, selected_indices=(1,), confirmed=True, client=client
        )
    assert not result.execution_evidence
    assert not any(e.evidence_type is EvidenceType.MUTATION_EXECUTION for e in result.evidence)


def test_normal_nested_inputs_remain_exact_for_query_and_mutation(phase_ten_scan):
    safe, _ = phase_ten_scan("""
        scalar DateTime
        enum Choice { ZETA ALPHA }
        input Profile { email: String! choice: Choice! when: DateTime! optional: String }
        input Input { profiles: [[Profile!]!]! enabled: Boolean! id: ID! count: Int! ratio: Float! }
        type Query { inspect(input: Input!): String }
        type Mutation { inspect(input: Input!): String }
    """)
    query = safe.query_generation.queries[0]
    mutation = prepare_active_mutations(safe).candidates[0].generated_mutation
    expected = {
        "input": {
            "count": 1,
            "enabled": False,
            "id": "1",
            "ratio": 1.0,
            "profiles": [[{"choice": "ALPHA", "email": "test@example.com", "when": "test"}]],
        }
    }
    assert query.variables == mutation.variables == expected
    assert (
        query.manual_adjustments
        == mutation.manual_adjustments
        == ("Custom scalar 'DateTime' may require manual adjustment.",)
    )
    for kind, artifact in (("query", query), ("mutation", mutation)):
        assert artifact.query_text == f"{kind} ($input: Input!) {{\n  inspect(input: $input)\n}}"


def test_optional_bound_expansion_is_bounded_and_stays_optional():
    result = _generate(
        "type Query { items(options: Options): [Item] } type Item { id: ID }"
        "input Options { limit: Int required: I0! }" + _inputs(12, branching=True)
    )
    assert result.variables == {}
    assert result.query_text == "query {\n  items {\n    id\n  }\n}"


def test_explicit_input_path_cannot_reset_shared_work_or_depth():
    schema = _schema(
        "type Query { ping: String } input Input { child: Input fields: Fields! }"
        "input Fields { " + " ".join(f"f{i}: String!" for i in range(520)) + " }"
    )
    with pytest.raises(QueryGenerationError, match="expansion limit"):
        generation.generate_input_path(
            schema, TypeReference.named("Input"), ("child",), input_name="input"
        )
    shallow = _schema("type Query { ping: String } input Input { child: Input }")
    with pytest.raises(QueryGenerationError, match="depth limit"):
        generation.generate_input_path(
            shallow, TypeReference.named("Input"), ("child",) * 500, input_name="input"
        )


def test_list_wrappers_cannot_bypass_depth_limit():
    schema = _schema("type Query { ping: String }")
    reference = TypeReference.named("String")
    for _ in range(64):
        reference = TypeReference.list_of(reference)
    with pytest.raises(QueryGenerationError, match="depth limit"):
        generation.generate_input_path(schema, reference, (), input_name="input")


def test_optional_bound_attempts_share_work_limit(monkeypatch):
    visits = 0
    original = generation._placeholder

    def counted(*args, **kwargs):
        nonlocal visits
        visits += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(generation, "_placeholder", counted)
    # Each path fails at depth; later candidates must not restart the work allowance.
    arguments = " ".join(f"a{i}: Options" for i in range(100))
    result = _generate(
        f"type Query {{ items({arguments}): [Item] }} type Item {{ id: ID }}"
        "input Options { limit: Int required: I0! }" + _inputs(100)
    )
    assert result.variables == {}
    assert visits <= 2048 + 100  # At most one rejecting visit per optional attempt.


def test_subscription_required_inputs_use_same_controlled_failure():
    schema = _schema(
        "type Query { ping: String } type Subscription { event(input: I0!): String }" + _inputs(500)
    )
    field = schema.type_named("Subscription").fields[0]
    with pytest.raises(QueryGenerationError, match="depth limit"):
        generation.generate_subscription(schema, field)
