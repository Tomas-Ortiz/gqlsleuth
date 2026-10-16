"""The emitted combined-reference bound and typed validation have one contract."""

import json
from itertools import product

import pytest

from fixtures.ai_response import reference_items, security_answer_fields
from fixtures.phase16_smoke import SDL
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIValidationError
from gqlsleuth.ai.prompt import build_response_schema, validate_interpretation


@pytest.fixture
def context(phase_ten_scan):
    original = build_ai_context(phase_ten_scan(SDL)[0])
    return original.model_copy(
        update={
            "operations": tuple(
                original.operations[0].model_copy(
                    update={"operation": f"endpoint_1/query/item{i}", "name": f"item{i}"}
                )
                for i in range(3)
            ),
            "security_facts": tuple(
                original.security_facts[0].model_copy(update={"security_fact_ref": f"SF{i + 1}"})
                for i in range(3)
            ),
        }
    )


def referenced_payload(context, section, refs):
    payload = security_answer_fields(context)
    if section == "summary_interpretation":
        payload[section]["references"] = refs
    elif section == "review_insights":
        payload[section] = [
            {
                "references": refs,
                "interpretation": "Review these related access requirements together.",
                "manual_follow_up": "Manually compare the intended business policies.",
            }
        ]
    else:
        payload[section] = [
            {"references": refs, "text": "Untested behavior remains outside the assessment scope."}
        ]
    return payload


@pytest.mark.parametrize(
    "section,definition",
    [
        ("summary_interpretation", "AISummaryInterpretation"),
        ("review_insights", "AIReviewInsight"),
        ("limitations", "AIInterpretiveLimitation"),
    ],
)
def test_emitted_cardinality_matches_validation_for_every_reference_mix(
    context, section, definition
):
    before = serialize_context(context)
    schema = build_response_schema(context)
    spec = schema["$defs"][definition]["properties"]["references"]
    assert spec["maxItems"] == 3 and spec["uniqueItems"] is True
    assert spec["items"]["discriminator"]["propertyName"] == "kind"
    for operation_count, fact_count in product(range(4), repeat=2):
        refs = reference_items(
            [o.operation for o in context.operations[:operation_count]],
            [f.security_fact_ref for f in context.security_facts[:fact_count]],
        )
        payload = referenced_payload(context, section, refs)
        schema_cardinality_valid = spec.get("minItems", 0) <= len(refs) <= spec["maxItems"]
        if schema_cardinality_valid:
            result = validate_interpretation(json.dumps(payload), context)
            entry = getattr(result, section)
            if section != "summary_interpretation":
                entry = entry[0]
            assert [r.model_dump() for r in entry.references] == refs
        else:
            with pytest.raises(AIValidationError) as caught:
                validate_interpretation(json.dumps(payload), context)
            # Empty summary references are a context-dependent membership requirement.
            if refs or section == "review_insights":
                assert caught.value.stage == "schema"
            else:
                assert caught.value.code == "missing_summary_references"
    assert serialize_context(context) == before


@pytest.mark.parametrize(
    "refs,code",
    [
        (reference_items(["endpoint_1/query/item0"] * 2), "invalid_security_references"),
        (reference_items(security_facts=["SF1", "SF1"]), "invalid_security_references"),
        (reference_items(["endpoint_1/query/invented"]), "unknown_operation_reference"),
        (reference_items(security_facts=["SF999"]), "invalid_security_references"),
        ([{"kind": "unknown", "ref": "SF1"}], "invalid_schema"),
        ([{"kind": "operation", "ref": "SF1"}], "unknown_operation_reference"),
        ([{"kind": "security_fact", "ref": "endpoint_1/query/item0"}], "invalid_schema"),
        ([{"kind": "operation", "ref": "endpoint_1/query/item0", "extra": "x"}], "invalid_schema"),
    ],
)
def test_strict_reference_kind_membership_and_duplicates(context, refs, code):
    with pytest.raises(AIValidationError, match=code):
        validate_interpretation(
            json.dumps(referenced_payload(context, "summary_interpretation", refs)), context
        )


def test_outgoing_reference_enums_and_primary_operation_contract(context):
    definitions = build_response_schema(context)["$defs"]
    assert definitions["AIOperationReference"]["properties"]["ref"]["enum"] == [
        o.operation for o in context.operations
    ]
    assert definitions["AISecurityFactReference"]["properties"]["ref"]["enum"] == [
        f.security_fact_ref for f in context.security_facts
    ]
    primary = definitions["AIOperationInterpretation"]
    assert primary["additionalProperties"] is False
    assert set(primary["properties"]) == {"operation", "interpretation", "manual_follow_up"}
    assert primary["properties"]["operation"]["type"] == "string"
    payload = security_answer_fields(context)
    payload["operation_interpretations"][0]["references"] = reference_items(
        [context.operations[1].operation]
    )
    with pytest.raises(AIValidationError, match="invalid_schema"):
        validate_interpretation(json.dumps(payload), context)


def test_previous_two_array_shape_is_not_accepted(context):
    payload = security_answer_fields(context)
    summary = payload["summary_interpretation"]
    del summary["references"]
    summary.update(operations=[o.operation for o in context.operations], security_facts=["SF1"])
    with pytest.raises(AIValidationError, match="invalid_schema"):
        validate_interpretation(json.dumps(payload), context)
