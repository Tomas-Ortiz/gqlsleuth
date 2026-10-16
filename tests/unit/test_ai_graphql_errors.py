"""Equivalent GraphQL error wording has the same bounded causal-grounding rules."""

import json

import httpx
import pytest

from fixtures.ai_response import reference_items, security_answer_fields, set_operations
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AISecurityFact
from gqlsleuth.ai.prompt import collect_interpretation_quality_warnings, validate_interpretation
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient


@pytest.fixture
def context(phase_ten_scan):
    safe, _ = phase_ten_scan("type Query { profile: String }", mode=ScanMode.SAFE)
    with HttpClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"errors": [{"message": "Fake error"}]})
        )
    ) as client:
        return build_ai_context(execute_generated_queries(safe.query_generation, client=client))


def response(context, text):
    payload = security_answer_fields(context)
    set_operations(
        payload, [{"operation": context.operations[0].operation, "interpretation": text}]
    )
    return json.dumps(payload)


@pytest.mark.parametrize(
    "outcome",
    [
        "GraphQL error",
        "GraphQL errors",
        "A GraphQL error",
        "The GraphQL error",
        "The GraphQL errors",
        "The operation returned a GraphQL error",
        "The operation returned GraphQL errors",
        "GRAPHQL_ERROR",
    ],
)
@pytest.mark.parametrize("link", [" may indicate", ". This could reflect"])
def test_singular_plural_same_and_adjacent_sentence_cause_rejected(context, outcome, link):
    text = outcome + link + " a misconfiguration."
    typed = validate_interpretation(response(context, text), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_outcome_inference" in warnings


@pytest.mark.parametrize(
    "claim",
    [
        "may indicate a misconfiguration",
        "might indicate data exposure",
        "could indicate data exposure",
        "suggest an authorization weakness",
        "may suggest an authentication weakness",
        "could suggest missing validation",
        "may reflect insufficient input validation",
        "could reflect rate limiting",
        "possibly indicate an access-control weakness",
        "potentially indicate security-control enforcement",
        "may indicate a vulnerability",
        "may indicate a confirmed security risk",
        "may not indicate actual security issues but could suggest misconfigurations "
        "or internal data exposure",
    ],
)
def test_speculation_does_not_authorize_error_cause_or_risk(context, claim):
    typed = validate_interpretation(response(context, "The GraphQL errors " + claim + "."), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_outcome_inference" in warnings


@pytest.mark.parametrize(
    "text",
    [
        "The GraphQL errors do not establish their underlying cause.",
        "Manual review is needed to determine the cause of the GraphQL errors.",
        "The supplied facts are insufficient to determine whether authorization was involved.",
        "The GraphQL errors do not establish whether input validation affected the request.",
        "The cause of the observed GraphQL errors remains undetermined.",
        "The operation returned GraphQL errors. Their cause cannot be determined "
        "from the supplied facts.",
        "The GraphQL errors do not establish whether authorization controls were involved.",
        "The supplied facts are insufficient to determine whether the GraphQL errors "
        "relate to input validation.",
    ],
)
def test_calibrated_error_scope_preserves_exact_prose(context, text):
    result = validate_interpretation(response(context, text), context)
    assert result.operation_interpretations[0].interpretation == text


@pytest.mark.parametrize("outcome", ["GraphQL error", "GraphQL errors"])
def test_matching_explicit_control_preserves_existing_scoped_support(context, outcome):
    fact = AISecurityFact(
        security_fact_ref="SF999",
        capability="query_depth",
        category="security_observation",
        outcome="rejected",
        control_observed=True,
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"] = {
        "references": reference_items(security_facts=[fact.security_fact_ref]),
        "text": f"The {outcome} indicates depth protection for this bounded probe only.",
    }
    assert validate_interpretation(json.dumps(payload), context)
    payload["summary_interpretation"]["text"] = (
        f"The {outcome} indicates an authorization weakness."
    )
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_outcome_inference" in warnings
