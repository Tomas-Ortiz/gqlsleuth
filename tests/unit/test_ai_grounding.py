"""Detailed prose cannot infer causes or security from ordinary outcomes/review interest."""

import json
from copy import deepcopy

import httpx
import pytest

from fixtures.ai_response import reference_items, security_answer_fields, set_operations
from fixtures.whole_scan_ai import SDL, assemble
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AIAnalysisStatus, AISecurityFact
from gqlsleuth.ai.prompt import collect_interpretation_quality_warnings, validate_interpretation
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient


@pytest.fixture
def completed(phase_ten_scan):
    safe, _ = phase_ten_scan(
        "type Query { profile: String account: String items: [Item] } type Item { id: ID }",
        mode=ScanMode.SAFE,
    )

    def respond(request):
        query = json.loads(request.content)["query"]
        if "profile" in query:
            return httpx.Response(200, json={"errors": [{"message": "Fake application error"}]})
        if "account" in query:
            return httpx.Response(403, text="Fake rejection")
        return httpx.Response(200, json={"data": None})

    with HttpClient(transport=httpx.MockTransport(respond)) as client:
        return execute_generated_queries(safe.query_generation, client=client)


def answer(context):
    return security_answer_fields(context)


@pytest.mark.parametrize(
    "name,text,code",
    [
        (
            "profile",
            "GRAPHQL_ERROR indicates authorization failure.",
            "unsupported_outcome_inference",
        ),
        (
            "account",
            "HTTP_ERROR proves authentication enforcement.",
            "unsupported_outcome_inference",
        ),
        ("account", "HTTP failure confirms rate limiting.", "unsupported_outcome_inference"),
        (
            "account",
            "The rejection demonstrates depth protection.",
            "unsupported_outcome_inference",
        ),
        (
            "account",
            "The error suggests input validation is working.",
            "unsupported_outcome_inference",
        ),
        (
            "items",
            "Its success may suggest that authentication controls are in place, "
            "though further review is needed.",
            "unsupported_outcome_inference",
        ),
        ("profile", "INDETERMINATE proves abuse prevention.", "unsupported_outcome_inference"),
        (
            "profile",
            "NETWORK_FAILURE was caused by authorization.",
            "unsupported_outcome_inference",
        ),
        (
            "profile",
            "The query returned a GraphQL error, indicating potential issues with query "
            "structure or data access.",
            "unsupported_outcome_inference",
        ),
        (
            "profile",
            "Its failure may suggest underlying system issues requiring manual review.",
            "unsupported_outcome_inference",
        ),
        (
            "items",
            "Its success may suggest no immediate security concerns.",
            "unsupported_outcome_inference",
        ),
        (
            "items",
            "The query was successful, indicating it may be used for auditing purposes.",
            "unsupported_outcome_inference",
        ),
        (
            "items",
            "Its categories suggest it could be a high-risk operation.",
            "unsupported_review_conclusion",
        ),
        (
            "items",
            "Its categories suggest it could be a low-risk operation.",
            "unsupported_review_conclusion",
        ),
    ],
)
def test_ordinary_outcome_cannot_establish_cause_control_or_risk(completed, name, text, code):
    context = build_ai_context(completed)
    assert context.counts["query_graphql_error"] == context.counts["query_http_error"] == 1
    payload = answer(context)
    operation = next(o for o in context.operations if o.name == name)
    set_operations(payload, [{"operation": operation.operation, "interpretation": text}])
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert code in warnings
    assert text not in str(warnings)


@pytest.mark.parametrize(
    "text",
    [
        "The structural candidate reveals a vulnerability.",
        "The operation is vulnerable.",
        "The query lacks list bounding, which may require manual review for data exposure.",
    ],
)
def test_schema_review_is_not_a_runtime_conclusion(completed, text):
    context = build_ai_context(completed)
    fact = next(f for f in context.security_facts if f.candidate_type == "list_bounding_review")
    payload = answer(context)
    payload["summary_interpretation"] = {
        "references": reference_items([], [fact.security_fact_ref]),
        "text": text,
    }
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_review_conclusion" in warnings


@pytest.mark.parametrize(
    "text",
    [
        "This operation warrants manual authorization review.",
        "The supplied categories suggest an authentication role. Review manually.",
        "Manually verify whether authentication controls are enforced for the intended policy.",
        "Manual review is needed to determine if the authentication policy is correctly enforced.",
        "Manual review is needed to determine whether authorization controls "
        "are properly enforced.",
        "GRAPHQL_ERROR limits runtime assessment. Its cause is not supplied; review manually.",
        "HTTP_ERROR does not establish authentication enforcement. Review the intended policy.",
        "The error does not indicate authorization failure. Its cause remains unknown.",
        "The supplied schema lacks list bounding; runtime controls may still exist.",
        "Successful execution does not suggest no immediate security concerns.",
        "The query was successful, indicating no immediate issues with query execution.",
        "Based on the provided facts, manual review is required.",
        "The provided facts do not establish input validation enforcement.",
        "Manual review is needed to determine whether input validation is provided.",
        "The provider supplies input validation information for manual review.",
        "Providing input validation context does not establish enforcement.",
        "Input validation information provided for manual review remains unverified.",
        "The supplied input validation information provides context for manual review.",
        "The scope was limited to the provided operations and security facts, with no coverage "
        "for most capabilities such as authorization policy, sensitive input validation, "
        "and others.",
    ],
)
def test_calibrated_manual_review_and_negated_inferences_remain_valid(completed, text):
    context = build_ai_context(completed)
    payload = answer(context)
    # Positive SUCCESS prose must refer to the successful operation, not this fixture's
    # first (GRAPHQL_ERROR) operation. The causal-language contract is unchanged.
    operation = (
        next(o for o in context.operations if o.name == "items")
        if text.startswith("The query was successful")
        else context.operations[0]
    )
    set_operations(payload, [{"operation": operation.operation, "interpretation": text}])
    result = validate_interpretation(json.dumps(payload), context)
    assert result.operation_interpretations[0].interpretation == text


@pytest.mark.parametrize(
    "text",
    [
        "Protection is provided.",
        "Authentication is enforced.",
        "Authorization is enforced.",
        "Input validation prevents malicious values.",
        "Rate limiting protects the operation.",
        "Rate limiting protection is present.",
        "Access controls prevent unauthorized use.",
        "Depth protection blocks deep requests.",
        "Abuse controls are effective.",
        "Security controls mitigate abuse.",
        "The supplied facts prove input validation enforcement.",
        "The supplied facts proved input validation enforcement.",
        "Input validation enforcement is proven by these facts.",
        "Manual review is needed to determine whether input validation is provided, "
        "but protection is provided.",
    ],
)
def test_asserted_control_effect_or_state_requires_scoped_evidence(completed, text):
    context = build_ai_context(completed)
    payload = answer(context)
    set_operations(
        payload, [{"operation": context.operations[0].operation, "interpretation": text}]
    )
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_control_claim" in warnings


@pytest.mark.parametrize(
    "text",
    [
        "Manual review is needed to determine if the authentication policy is correctly enforced. "
        "Its success suggests authentication controls are in place.",
        "Manual review is needed to determine if the authentication policy is correctly enforced, "
        "but authentication controls are enforced.",
        "Manual review is needed to determine if the authentication policy is correctly enforced "
        "and its success proves authentication enforcement.",
    ],
)
def test_conditional_review_does_not_exempt_an_unsupported_assertion(completed, text):
    context = build_ai_context(completed)
    payload = answer(context)
    set_operations(
        payload, [{"operation": context.operations[0].operation, "interpretation": text}]
    )
    code = "unsupported_outcome_inference" if "success" in text else "unsupported_control_claim"
    typed = validate_interpretation(json.dumps(payload), context)
    assert code in collect_interpretation_quality_warnings(typed, context)


def test_explicit_control_requires_matching_cited_capability(phase_ten_scan):
    context = build_ai_context(assemble(phase_ten_scan(SDL)[0]))
    depth = next(f for f in context.security_facts if f.capability == "query_depth")
    assert depth.control_observed
    payload = answer(context)
    payload["summary_interpretation"] = {
        "references": reference_items([], [depth.security_fact_ref]),
        "text": "The supplied control indicates depth protection for this bounded probe only.",
    }
    assert validate_interpretation(json.dumps(payload), context).summary_interpretation
    payload["summary_interpretation"]["text"] = "Depth protection blocks the supplied probe only."
    assert validate_interpretation(json.dumps(payload), context).summary_interpretation
    payload["summary_interpretation"]["text"] = "The rejection proves authorization enforcement."
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_outcome_inference" in warnings
    payload["summary_interpretation"] = security_answer_fields(context)["summary_interpretation"]
    set_operations(
        payload,
        [
            {
                "operation": context.operations[0].operation,
                "interpretation": "The error confirms depth protection.",
            }
        ],
    )
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_outcome_inference" in warnings


def test_satisfied_typed_policy_supports_scoped_authorization_interpretation(completed):
    context = build_ai_context(completed)
    fact = AISecurityFact(
        security_fact_ref="SF2",
        capability="authorization_policy",
        category="policy_satisfied",
        expected="deny",
        evaluation="satisfied",
        outcome="explicit_denial",
    )
    context = context.model_copy(update={"security_facts": (*context.security_facts, fact)})
    payload = answer(context)
    payload["summary_interpretation"] = {
        "references": reference_items([], [fact.security_fact_ref]),
        "text": "The satisfied DENY policy indicates authorization enforcement "
        "for this probe only.",
    }
    assert validate_interpretation(json.dumps(payload), context).summary_interpretation


@pytest.mark.parametrize("section", ["summary_interpretation", "review_insights", "limitations"])
def test_grounding_covers_all_prose_and_follow_up(completed, section):
    context = build_ai_context(completed)
    payload = answer(context)
    text = "The error proves authorization enforcement."
    if section == "summary_interpretation":
        payload[section]["text"] = text
    elif section == "review_insights":
        payload[section] = [
            {
                "references": reference_items([o.operation for o in context.operations[:2]], []),
                "interpretation": "Review manually.",
                "manual_follow_up": text,
            }
        ]
    else:
        payload[section] = [{"text": text, "references": reference_items([], [])}]
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_outcome_inference" in warnings


def test_grounding_failure_is_nonfatal_after_bounded_regeneration(completed):
    before = deepcopy(completed)
    context = build_ai_context(completed)
    payload = answer(context)
    set_operations(
        payload,
        [
            {
                "operation": context.operations[0].operation,
                "interpretation": "GRAPHQL_ERROR proves authorization enforcement.",
            }
        ],
    )
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "message": {"role": "assistant", "content": json.dumps(payload)},
            },
        )

    result = interpret_completed_scan(
        completed, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.SUCCESS
    assert "unsupported_outcome_inference" in result.quality_warnings
    assert result.validation_failures == () and result.interpretation is not None
    assert len(requests) == 1 and completed == before and completed.evidence == before.evidence


@pytest.mark.parametrize(
    "text",
    [
        "GraphQL error occurred. This indicates authentication enforcement.",
        "The request failed. This may indicate authorization controls blocked it.",
        "The operation returned an error. This suggests input validation rejected the request.",
        "The request succeeded. This indicates access controls are functioning.",
        "The failure was likely caused by authorization controls.",
        "The successful response indicates access control is functioning.",
        "The GraphQL error occurred because rate limiting blocked the operation.",
        "The query returned a GraphQL error. This may indicate an issue with query structure "
        "or data access.",
        "The query returned a GraphQL error, indicating an issue with query structure "
        "or data access.",
        "The request was skipped. This confirms authentication enforcement.",
    ],
)
def test_adjacent_and_same_sentence_outcome_attribution_rejected(completed, text):
    context = build_ai_context(completed)
    payload = answer(context)
    set_operations(
        payload, [{"operation": context.operations[0].operation, "interpretation": text}]
    )
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_outcome_inference" in warnings


@pytest.mark.parametrize(
    "text",
    [
        "The GraphQL error does not establish whether authentication was involved.",
        "Manual review is needed to determine whether authorization affected the outcome.",
        "Manual review is needed to determine whether authentication affected the observed error.",
        "The cause of the GraphQL error cannot be determined from the supplied facts.",
        "The cause cannot be determined from the supplied facts.",
        "GraphQL error occurred. This does not indicate authentication enforcement.",
        "The provided facts describe an error. Manual review of input validation is required.",
    ],
)
def test_calibrated_unknown_causes_remain_valid(completed, text):
    context = build_ai_context(completed)
    payload = answer(context)
    set_operations(
        payload, [{"operation": context.operations[0].operation, "interpretation": text}]
    )
    assert (
        validate_interpretation(json.dumps(payload), context)
        .operation_interpretations[0]
        .interpretation
        == text
    )


def test_adjacent_cause_requires_matching_explicit_reference(completed):
    context = build_ai_context(completed)
    fact = AISecurityFact(
        security_fact_ref="SF2",
        capability="authentication",
        category="security_observation",
        control_observed=True,
    )
    context = context.model_copy(update={"security_facts": (*context.security_facts, fact)})
    payload = answer(context)
    payload["summary_interpretation"] = {
        "references": reference_items([], [fact.security_fact_ref]),
        "text": "The request failed. This indicates authentication enforcement "
        "for this probe only.",
    }
    assert validate_interpretation(json.dumps(payload), context).summary_interpretation
    unrelated = fact.model_copy(update={"capability": context.security_facts[0].capability})
    context = context.model_copy(
        update={"security_facts": (*context.security_facts[:-1], unrelated)}
    )
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_outcome_inference" in warnings
