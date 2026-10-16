"""Review metadata supports review directions, not risk or observed contents."""

import json

import pytest

from fixtures.ai_response import reference_items, security_answer_fields, set_operations
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.ai.models import AISecurityFact
from gqlsleuth.ai.prompt import collect_interpretation_quality_warnings, validate_interpretation
from gqlsleuth.ai.regeneration import corrective_instruction
from gqlsleuth.domain.models import ScanMode


@pytest.fixture
def context(phase_ten_scan):
    scan, _ = phase_ten_scan(
        "type Query { items: [User] me: User login: String } "
        "type User { id: ID token: String } "
        "type Mutation { createUser: User uploadPaste: String }",
        mode=ScanMode.SAFE,
    )
    return build_ai_context(scan)


def response(context, text, name="createUser"):
    payload = security_answer_fields(context)
    operation = next(o for o in context.operations if o.name == name)
    set_operations(payload, [{"operation": operation.operation, "interpretation": text}])
    return json.dumps(payload)


@pytest.mark.parametrize(
    "text",
    [
        "The operation may not have authorization controls.",
        "The operation might not have authorization controls.",
        "The mutation might lack input validation.",
        "The mutation may lack input validation.",
        "The query may be missing authorization controls.",
        "The query could be missing input validation.",
        "The operation could lack rate limiting.",
        "The operation might lack rate limiting.",
        "The endpoint may not enforce authorization.",
        "The operation might not enforce input validation.",
        "The operation may not have explicit data exposure controls.",
        "System diagnostics and me queries may not have explicit data exposure controls.",
        "This operation is authentication-related. "
        "It may not have adequate authentication controls.",
    ],
)
def test_modal_absence_requires_evidence(context, text):
    assert not next(o for o in context.operations if o.name == "createUser").attempted
    typed = validate_interpretation(response(context, text), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_control_claim" in warnings


@pytest.mark.parametrize(
    "text",
    [
        "The evidence may not be sufficient to determine whether "
        "authorization controls are present.",
        "The supplied facts may not establish whether input validation is enforced.",
        "The supplied facts might not establish whether input validation is enforced.",
        "The available evidence might not allow a conclusion about authorization.",
        "The assessment lacks enough information to determine whether rate limiting is present.",
        "The assessment lacks enough information to determine whether authorization exists.",
        "Authorization should be manually reviewed for this operation.",
        "Validate whether authorization is consistently enforced.",
        "Review server-side pagination and result limits.",
        "Validate whether result size is constrained server-side.",
        "Authentication behavior warrants manual validation.",
        "Because this operation was flagged for list-bounding review, validate enforced pagination "
        "and result limits.",
        "This object lookup warrants manual authorization review.",
        "The mutation's schema role makes authorization and input validation "
        "useful areas to assess.",
        "The authentication-related review category indicates that authentication behavior "
        "should be manually validated.",
        "Manual review should determine whether recursive traversal is effectively bounded.",
        "The operation appears related to account creation.",
        "The mutation name and schema role suggest an account-creation workflow.",
        "The operation appears relevant to session/authentication review.",
        "The schema indicates an upload-oriented operation.",
        "This query is flagged for list-bounding review. Manual validation should check "
        "server-side result limits.",
        "This mutation appears related to account creation. "
        "Authorization should be manually validated.",
        "Check whether the query returns session tokens.",
        "The facts do not establish data-exposure risk.",
    ],
)
def test_calibrated_review_and_evidence_limitations_remain_valid(context, text):
    result = validate_interpretation(response(context, text), context)
    assert result.operation_interpretations[0].interpretation == text


@pytest.mark.parametrize(
    "text",
    [
        "This query has potential for data exposure.",
        "This query may expose excessive data.",
        "This operation may allow unauthorized access.",
        "This operation may permit authentication bypass.",
        "This operation may permit injection.",
        "This operation may cause denial of service.",
        "This object lookup may permit unauthorized object access.",
        "This operation may expose sensitive data.",
        "This mutation may permit unauthorized modification.",
        "This query creates a data-exposure risk.",
        "Large amounts of data may be returned.",
        "Authorization is weak.",
        "The items query is flagged for list bounding review "
        "due to its potential for data exposure.",
        "createUser may allow unauthorized access.",
        "uploadPaste may allow unauthorized data storage.",
        "This query is flagged for list-bounding review. It may expose excessive data.",
        "This mutation is marked for authorization review. It may allow unauthorized access.",
    ],
)
def test_review_metadata_is_not_a_risk_rationale(context, text):
    typed = validate_interpretation(response(context, text), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_review_conclusion" in warnings


@pytest.mark.parametrize(
    "text",
    [
        "The operation handles session tokens.",
        "The query returns authentication tokens.",
        "The operation exposes sensitive data.",
        "The operation exposes sensitive information.",
        "The mutation stores uploaded data.",
        "The query returns user records.",
        "The response contained user data.",
        "The operation creates users.",
        "The operation stores uploaded files.",
        "The operation handles tokens_and_sessions.",
        "The operation handles user_management and secrets_and_credentials.",
        "The query may expose read_only_business_data.",
        "Me query may expose user tokens or sessions.",
        "The operation appears related to authentication. It returns session tokens.",
    ],
)
def test_category_or_schema_role_is_not_runtime_content(context, text):
    typed = validate_interpretation(response(context, text, name="me"), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_review_conclusion" in warnings


def fact_response(context, fact, text):
    context = context.model_copy(update={"security_facts": (*context.security_facts, fact)})
    payload = security_answer_fields(context)
    payload["summary_interpretation"] = {
        "references": reference_items([], [fact.security_fact_ref]),
        "text": text,
    }
    return context, json.dumps(payload)


def test_explicit_scoped_finding_can_support_object_access(context):
    fact = AISecurityFact(
        security_fact_ref="SF90",
        capability="idor_bola",
        category="finding",
        finding_type="object_level_authorization_failure",
        expected="deny",
    )
    context, payload = fact_response(
        context, fact, "The tested object probe recorded unauthorized object access."
    )
    assert validate_interpretation(payload, context).summary_interpretation
    # The same fact cannot justify arbitrary content or risk for another subject.
    for text in (
        "This mutation may allow unauthorized access.",
        "The query returns session tokens.",
    ):
        _, payload = fact_response(context, fact, text)
        typed = validate_interpretation(payload, context)
        warnings = collect_interpretation_quality_warnings(typed, context)
        assert "unsupported_review_conclusion" in warnings


@pytest.mark.parametrize("supported", [True, False])
def test_actual_sdl_observation_not_schema_name_supports_scoped_content(context, supported):
    fact = AISecurityFact(
        security_fact_ref="SF90",
        capability="federation",
        category="security_observation",
        sdl_returned=supported,
    )
    context, payload = fact_response(context, fact, "The federation probe returned SDL.")
    if supported:
        assert validate_interpretation(payload, context).summary_interpretation
    else:
        typed = validate_interpretation(payload, context)
        warnings = collect_interpretation_quality_warnings(typed, context)
        assert "unsupported_review_conclusion" in warnings


@pytest.mark.parametrize(
    "text",
    [
        "The supplied facts might not establish whether input validation is enforced. "
        "The mutation may lack input validation.",
        "Manual review should determine whether authorization exists, but the operation "
        "may not have authorization controls.",
    ],
)
def test_evidence_limitation_does_not_exempt_appended_assertion(context, text):
    typed = validate_interpretation(response(context, text), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_control_claim" in warnings


@pytest.mark.parametrize("section", ["summary", "insight", "limitation", "follow_up"])
def test_review_guard_applies_to_every_prose_section(context, section):
    payload = security_answer_fields(context)
    text = "The operation handles session tokens."
    refs = reference_items([o.operation for o in context.operations[:2]], [])
    if section == "summary":
        payload["summary_interpretation"] = {"text": text, "references": refs}
    elif section == "insight":
        payload["review_insights"] = [
            {"references": refs, "interpretation": "Review manually.", "manual_follow_up": text}
        ]
    elif section == "limitation":
        payload["limitations"] = [{"text": text, "references": refs}]
    else:
        payload["operation_interpretations"][0]["manual_follow_up"] = text
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_review_conclusion" in warnings


def test_review_warning_never_has_a_regeneration_correction():
    code = "unsupported_review_conclusion"
    assert corrective_instruction((code, code), 3) is None
