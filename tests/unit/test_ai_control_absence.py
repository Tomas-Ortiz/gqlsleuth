"""Direct missing-control assertions are not review facts or evidence limitations."""

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
    safe, _ = phase_ten_scan(
        "type Query { profile: String } "
        "type Mutation { updateUser(ownerId: ID, role: String): String }",
        mode=ScanMode.SAFE,
    )
    with HttpClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"errors": [{"message": "Fake error"}]})
        )
    ) as client:
        return build_ai_context(execute_generated_queries(safe.query_generation, client=client))


def response(context, text, name="updateUser"):
    payload = security_answer_fields(context)
    operation = next(o for o in context.operations if o.name == name)
    set_operations(payload, [{"operation": operation.operation, "interpretation": text}])
    return json.dumps(payload)


@pytest.mark.parametrize(
    "text",
    [
        "The operation lacks authorization controls.",
        "The operation lacks authentication controls.",
        "The mutation lacks input validation.",
        "The mutation lacks input validation controls.",
        "The operation lacks rate limiting.",
        "The operation lacks access control.",
        "The operation lacks ownership checks.",
        "The operation lacks security controls.",
        "The operation is missing authentication controls.",
        "The operation is missing authorization controls.",
        "The operation is missing input validation.",
        "The operation has no authorization controls.",
        "The mutation has no input validation controls.",
        "The mutation does not have authorization controls.",
        "The mutation does not enforce authorization.",
        "The mutation does not perform input validation.",
        "The operation lacks authorization.",
        "CreateUser mutation lacks authorization and input validation controls.",
        "Login mutation lacks explicit authorization checks and may expose credentials.",
        "UploadPaste mutation lacks file validation and may allow malicious uploads.",
    ],
)
def test_unexecuted_review_operation_does_not_establish_control_absence(context, text):
    operation = next(o for o in context.operations if o.name == "updateUser")
    assert not operation.attempted and operation.interest_score > 0
    typed = validate_interpretation(response(context, text), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_control_claim" in warnings


@pytest.mark.parametrize(
    "text",
    [
        "The supplied evidence does not establish whether authorization controls are present.",
        "Manual review is needed to determine whether input validation is enforced.",
        "The available facts are insufficient to determine whether authorization controls exist.",
        "The assessment lacks enough runtime evidence to determine whether "
        "input validation is enforced.",
        "The supplied evidence lacks enough information to determine whether "
        "authorization controls are present.",
        "The available evidence lacks enough information to determine whether "
        "authorization controls are present.",
        "Based on the provided facts, manual review is required.",
        "The provider supplies input validation information for manual review.",
    ],
)
def test_evidence_limitations_and_manual_uncertainty_are_not_absence(context, text):
    assert validate_interpretation(response(context, text), context)


@pytest.mark.parametrize("status", ["success", "graphql_error", "skipped_safety"])
def test_generic_outcome_does_not_support_absence(context, status):
    from gqlsleuth.domain.execution import QueryExecutionStatus

    operations = tuple(
        o.model_copy(
            update={
                "execution_status": QueryExecutionStatus(status),
                "attempted": status != "skipped_safety",
            }
        )
        if o.name == "profile"
        else o
        for o in context.operations
    )
    context = context.model_copy(update={"operations": operations})
    typed = validate_interpretation(
        response(context, "The operation lacks authorization.", "profile"), context
    )
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_control_claim" in warnings


@pytest.mark.parametrize("capability", ["query_depth", "authorization_policy"])
def test_positive_or_unrelated_control_fact_does_not_prove_absence(context, capability):
    fact = AISecurityFact(
        security_fact_ref="SF999",
        capability=capability,
        category="security_observation",
        control_observed=True,
    )
    context = context.model_copy(update={"security_facts": (*context.security_facts, fact)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"] = {
        "references": reference_items(security_facts=[fact.security_fact_ref]),
        "text": "The operation lacks authorization controls.",
    }
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_control_claim" in warnings


def test_review_fact_and_unobserved_control_are_not_explicit_absence(context):
    fact = AISecurityFact(
        security_fact_ref="SF999",
        capability="structural_review",
        category="review_candidate",
        candidate_type="object_lookup_review",
        control_observed=False,
    )
    context = context.model_copy(update={"security_facts": (fact,)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"] = {
        "references": reference_items(security_facts=[fact.security_fact_ref]),
        "text": "The operation lacks authorization.",
    }
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_control_claim" in warnings


def test_evidence_limitation_does_not_exempt_appended_control_assertion(context):
    text = (
        "The available evidence lacks enough information to determine whether authorization "
        "controls are present; the operation lacks authorization controls."
    )
    typed = validate_interpretation(response(context, text), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_control_claim" in warnings
