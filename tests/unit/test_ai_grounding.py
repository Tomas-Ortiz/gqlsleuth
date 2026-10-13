"""Detailed prose cannot infer causes or security from ordinary outcomes/review interest."""

import json
from copy import deepcopy

import httpx
import pytest

from fixtures.ai_response import security_answer_fields
from fixtures.whole_scan_ai import SDL, assemble
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AIAnalysisStatus, AISecurityFact, AIValidationError
from gqlsleuth.ai.prompt import execution_summary, validate_interpretation
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
    return {
        **security_answer_fields(context),
        "scan_summary": {"text": execution_summary(context), "operations": []},
        "operation_review": [],
        "limitations": [],
    }


@pytest.mark.parametrize(
    "name,text,code",
    [
        ("profile", "GRAPHQL_ERROR indicates authorization failure.", "unsupported_control_claim"),
        ("account", "HTTP_ERROR proves authentication enforcement.", "unsupported_control_claim"),
        ("account", "HTTP failure confirms rate limiting.", "unsupported_control_claim"),
        ("account", "The rejection demonstrates depth protection.", "unsupported_control_claim"),
        ("account", "The error suggests input validation is working.", "unsupported_control_claim"),
        (
            "items",
            "Its success may suggest that authentication controls are in place, "
            "though further review is needed.",
            "unsupported_control_claim",
        ),
        ("profile", "INDETERMINATE proves abuse prevention.", "unsupported_control_claim"),
        ("profile", "NETWORK_FAILURE was caused by authorization.", "unsupported_control_claim"),
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
    payload["operation_review"] = [{"operation": operation.operation, "explanation": text}]
    with pytest.raises(AIValidationError) as caught:
        validate_interpretation(json.dumps(payload), context)
    assert (caught.value.stage, caught.value.code) == ("facts", code)
    assert text not in str(caught.value)


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
    payload["security_fact_reviews"] = [
        {
            "security_fact_ref": fact.security_fact_ref,
            "interpretation": text,
            "manual_follow_up": "Review server-side limits manually.",
        }
    ]
    with pytest.raises(AIValidationError, match="unsupported_review_conclusion"):
        validate_interpretation(json.dumps(payload), context)


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
    ],
)
def test_calibrated_manual_review_and_negated_inferences_remain_valid(completed, text):
    context = build_ai_context(completed)
    payload = answer(context)
    payload["operation_review"] = [
        {"operation": context.operations[0].operation, "explanation": text}
    ]
    result = validate_interpretation(json.dumps(payload), context)
    assert result.operation_review[0].explanation == text


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
    payload["operation_review"] = [
        {"operation": context.operations[0].operation, "explanation": text}
    ]
    with pytest.raises(AIValidationError, match="unsupported_control_claim"):
        validate_interpretation(json.dumps(payload), context)


def test_explicit_control_requires_matching_cited_capability(phase_ten_scan):
    context = build_ai_context(assemble(phase_ten_scan(SDL)[0]))
    depth = next(f for f in context.security_facts if f.capability == "query_depth")
    assert depth.control_observed
    payload = answer(context)
    payload["control_observations"] = [
        {
            "security_fact_ref": depth.security_fact_ref,
            "text": "The supplied control indicates depth protection for this bounded probe only.",
        }
    ]
    assert validate_interpretation(json.dumps(payload), context).control_observations
    payload["control_observations"][0]["text"] = "The rejection proves authorization enforcement."
    with pytest.raises(AIValidationError, match="unsupported_control_claim"):
        validate_interpretation(json.dumps(payload), context)
    payload["control_observations"] = []
    payload["operation_review"] = [
        {
            "operation": context.operations[0].operation,
            "explanation": "The error confirms depth protection.",
        }
    ]
    with pytest.raises(AIValidationError, match="unsupported_control_claim"):
        validate_interpretation(json.dumps(payload), context)


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
    payload["control_observations"] = [
        {
            "security_fact_ref": fact.security_fact_ref,
            "text": "The satisfied DENY policy indicates authorization enforcement "
            "for this probe only.",
        }
    ]
    assert validate_interpretation(json.dumps(payload), context).control_observations


@pytest.mark.parametrize("section", ["security_summary", "security_fact_reviews", "limitations"])
def test_grounding_covers_all_prose_and_follow_up(completed, section):
    context = build_ai_context(completed)
    payload = answer(context)
    text = "The error proves authorization enforcement."
    if section == "security_summary":
        payload[section]["text"] = text
    elif section == "security_fact_reviews":
        payload[section] = [
            {
                "security_fact_ref": context.security_facts[0].security_fact_ref,
                "interpretation": "Review manually.",
                "manual_follow_up": text,
            }
        ]
    else:
        payload[section] = [{"text": text, "operations": []}]
    with pytest.raises(AIValidationError, match="unsupported_control_claim"):
        validate_interpretation(json.dumps(payload), context)


def test_grounding_failure_is_nonfatal_after_bounded_regeneration(completed):
    before = deepcopy(completed)
    context = build_ai_context(completed)
    payload = answer(context)
    payload["operation_review"] = [
        {
            "operation": context.operations[0].operation,
            "explanation": "GRAPHQL_ERROR proves authorization enforcement.",
        }
    ]
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
    assert result.status is AIAnalysisStatus.INVALID_RESPONSE
    assert result.error_code == "unsupported_control_claim" and result.interpretation is None
    assert len(requests) == 5 and completed == before and completed.evidence == before.evidence
