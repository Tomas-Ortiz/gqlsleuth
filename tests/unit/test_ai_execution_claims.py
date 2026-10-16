"""Canonical execution truth applies to prose as well as the exact summary."""

import json
from copy import deepcopy

import httpx
import pytest

from fixtures.ai_response import reference_items, security_answer_fields, set_operations
from gqlsleuth.ai.context import build_ai_context, serialize_context
from gqlsleuth.ai.models import AIAnalysisStatus
from gqlsleuth.ai.prompt import collect_interpretation_quality_warnings, validate_interpretation
from gqlsleuth.application.ai_assistance import interpret_completed_scan
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.infrastructure.ollama import OllamaClient
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


@pytest.fixture
def scan(phase_ten_scan):
    safe, _ = phase_ten_scan(
        "type Query { users: [User] me: User deleteAllPastes: String } "
        "type User { id: ID } type Mutation { login: String createUser: User uploadPaste: String }",
        mode=ScanMode.SAFE,
    )

    def reply(request):
        query = json.loads(request.content)["query"]
        if "me" in query:
            return httpx.Response(200, json={"errors": [{"message": "Fake business error"}]})
        return httpx.Response(200, json={"data": None})

    with HttpClient(transport=httpx.MockTransport(reply)) as client:
        return execute_generated_queries(safe.query_generation, client=client)


def answer(context):
    return security_answer_fields(context)


@pytest.mark.parametrize(
    "name,text,valid",
    [
        ("users", "`users` executed successfully.", True),
        ("users", "The operation succeeded.", True),
        ("users", "The query was not executed.", False),
        ("users", "The operation failed.", False),
        ("me", "`me` returned a GraphQL error.", True),
        ("me", "The query failed with a GraphQL error.", True),
        ("me", "`me` succeeded.", False),
        ("me", "`me` was not executed.", False),
        ("deleteAllPastes", "`deleteAllPastes` was skipped by GQLSleuth.", True),
        ("deleteAllPastes", "GQLSleuth skipped the operation for safety.", True),
        ("deleteAllPastes", "SKIPPED_SAFETY was recorded.", True),
        ("deleteAllPastes", "`deleteAllPastes` was blocked by the target.", False),
        ("deleteAllPastes", "`deleteAllPastes` was blocked by the server.", False),
        ("deleteAllPastes", "`deleteAllPastes` failed.", False),
        ("deleteAllPastes", "`deleteAllPastes` executed successfully.", False),
        ("login", "`login` succeeded.", False),
        ("login", "CRITICAL-interest mutation for login. SUCCESS was observed.", False),
        ("createUser", "`createUser` executed.", False),
        ("createUser", "HIGH-interest mutation for user creation. SUCCESS was observed.", False),
        ("uploadPaste", "`uploadPaste` failed.", False),
        ("uploadPaste", "The operation returned a result.", False),
        ("login", "The mutation was not executed. Runtime behavior was not observed.", True),
        ("login", "Successful schema retrieval enables manual review.", True),
        ("login", "Successful introspection enables manual review.", True),
        ("login", "The scanner successfully parsed schema metadata.", True),
        ("login", "Manually verify whether the operation succeeds.", True),
    ],
)
def test_operation_execution_claims(scan, name, text, valid):
    context = build_ai_context(scan)
    operation = next(o for o in context.operations if o.name == name)
    payload = answer(context)
    set_operations(payload, [{"operation": operation.operation, "interpretation": text}])
    if valid:
        assert (
            validate_interpretation(json.dumps(payload), context)
            .operation_interpretations[0]
            .interpretation
            == text
        )
    else:
        typed = validate_interpretation(json.dumps(payload), context)
        warnings = collect_interpretation_quality_warnings(typed, context)
        assert "unsupported_execution_claim" in warnings


@pytest.mark.parametrize(
    "text,valid",
    [
        ("The mutations executed successfully.", False),
        ("Two mutations succeeded.", False),
        ("The scan successfully executed two mutations.", False),
        ("No mutations were executed.", True),
        ("Mutations were not executed, but two succeeded.", False),
        ("Mutation behavior was not validated because no mutations were executed.", True),
        ("Nine queries were executed: seven succeeded and two returned GraphQL errors.", True),
        ("Nine queries were executed, seven successfully and two with GraphQL errors.", True),
        ("Seven queries succeeded.", True),
        ("All nine queries succeeded.", False),
        ("Eight queries succeeded.", False),
        ("No queries were attempted.", False),
        ("The target blocked all mutations.", False),
        ("Mutations were skipped by GQLSleuth's safety controls.", False),
    ],
)
def test_aggregate_claims_use_complete_counts_not_truncated_operation_list(scan, text, valid):
    context = build_ai_context(scan)
    context = context.model_copy(
        update={
            "counts": {
                **context.counts,
                "query_requests": 9,
                "query_success": 7,
                "query_graphql_error": 2,
            }
        }
    )
    payload = answer(context)
    payload["summary_interpretation"]["text"] = text
    if valid:
        assert (
            validate_interpretation(json.dumps(payload), context).summary_interpretation.text
            == text
        )
    else:
        typed = validate_interpretation(json.dumps(payload), context)
        warnings = collect_interpretation_quality_warnings(typed, context)
        assert "unsupported_execution_claim" in warnings


@pytest.mark.parametrize(
    "section",
    [
        "summary",
        "interpretation",
        "follow_up",
        "global_interpretation",
        "global_follow_up",
        "limitation",
    ],
)
def test_execution_claims_checked_across_all_free_prose_sections(scan, section):
    context = build_ai_context(scan)
    payload = answer(context)
    bad = "The mutation `login` succeeded."
    if section == "summary":
        payload["summary_interpretation"]["text"] = bad
    elif section in {"interpretation", "follow_up"}:
        entry = next(
            i for i in payload["operation_interpretations"] if i["operation"].endswith("/login")
        )
        entry["interpretation" if section == "interpretation" else "manual_follow_up"] = bad
    elif section.startswith("global"):
        payload["review_insights"] = [
            {
                "references": reference_items([o.operation for o in context.operations[:2]], []),
                "interpretation": "Review related roles.",
                "manual_follow_up": "Review manually.",
            }
        ]
        payload["review_insights"][0][
            "interpretation" if section == "global_interpretation" else "manual_follow_up"
        ] = bad
    else:
        payload["limitations"] = [{"text": bad, "references": reference_items([], [])}]
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_execution_claim" in warnings


@pytest.mark.parametrize(
    "metadata",
    [
        {"generated": True},
        {"selected": True},
        {"selectable": True},
    ],
)
def test_generation_selection_or_preview_is_not_execution(scan, metadata):
    context = build_ai_context(scan)
    operations = tuple(
        o.model_copy(update=metadata) if o.name == "createUser" else o for o in context.operations
    )
    context = context.model_copy(update={"operations": operations})
    payload = answer(context)
    payload["summary_interpretation"]["text"] = "The mutation `createUser` executed."
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_execution_claim" in warnings


def test_execution_quality_warning_retains_prose_without_retry_or_target_requests(
    scan, monkeypatch
):
    context = build_ai_context(scan)
    before = deepcopy(scan)
    good = answer(context)
    bad = deepcopy(good)
    bad["summary_interpretation"]["text"] = "Two mutations succeeded. QUALITYEXECUTIONCANARY."
    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "done": True,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(bad if len(requests) == 1 else good),
                },
            },
        )

    monkeypatch.setattr(
        HttpClient, "send", lambda *a, **k: pytest.fail("Unexpected target request")
    )
    result = interpret_completed_scan(
        scan, client=OllamaClient(transport=httpx.MockTransport(respond))
    )
    assert result.status is AIAnalysisStatus.SUCCESS and result.attempt_count == 1
    assert result.validation_failures == ()
    assert "unsupported_execution_claim" in result.quality_warnings
    assert scan == before and scan.evidence == before.evidence
    assert (
        result.interpretation.summary_interpretation.text == bad["summary_interpretation"]["text"]
    )
    assert all(r["messages"][1]["content"] == serialize_context(context) for r in requests)
    assert "QUALITYEXECUTIONCANARY" not in json.dumps(requests)
    for format in ReportFormat:
        assert "QUALITYEXECUTIONCANARY" in render_report(
            build_report(scan, ai_interpretation=result), format
        )
    assert len(requests) == 1


@pytest.mark.parametrize(
    "changes,text,valid",
    [
        (
            {"execution_status": "network_failure", "attempted": True, "http_status": None},
            "The operation returned a result.",
            False,
        ),
        (
            {"execution_status": "network_failure", "attempted": True, "http_status": None},
            "NETWORK_FAILURE was recorded.",
            True,
        ),
        (
            {"execution_status": "http_error", "attempted": True, "http_status": 403},
            "The target denied the operation.",
            True,
        ),
        (
            {"execution_status": "http_error", "attempted": True, "http_status": 500},
            "The target denied the operation.",
            False,
        ),
        (
            {"execution_status": "skipped_limit", "attempted": False},
            "SKIPPED_LIMIT was recorded.",
            True,
        ),
        (
            {"execution_status": None, "attempted": False, "mutation_decision": "not_selected"},
            "NOT_SELECTED was recorded.",
            True,
        ),
        (
            {"execution_status": None, "attempted": False, "mutation_decision": "declined"},
            "The operator declined the operation.",
            True,
        ),
        (
            {"execution_status": None, "attempted": False},
            "The operation may have succeeded.",
            False,
        ),
        ({"execution_status": None, "attempted": False}, "The operation was NOT_RUN.", True),
    ],
)
def test_exact_error_and_scanner_decisions(scan, changes, text, valid):
    context = build_ai_context(scan)
    operation = next(o for o in context.operations if o.name == "login").model_copy(update=changes)
    context = context.model_copy(
        update={
            "operations": tuple(operation if o.name == "login" else o for o in context.operations)
        }
    )
    payload = answer(context)
    set_operations(payload, [{"operation": operation.operation, "interpretation": text}])
    if valid:
        validate_interpretation(json.dumps(payload), context)
    else:
        typed = validate_interpretation(json.dumps(payload), context)
        warnings = collect_interpretation_quality_warnings(typed, context)
        assert "unsupported_execution_claim" in warnings


def test_aggregate_scanner_safety_requires_recorded_decision(scan):
    context = build_ai_context(scan)
    operations = tuple(
        o.model_copy(update={"mutation_safety": "blocked_safety"}) if o.kind == "mutation" else o
        for o in context.operations
    )
    context = context.model_copy(update={"operations": operations})
    payload = answer(context)
    payload["summary_interpretation"]["text"] = (
        "Mutations were skipped by GQLSleuth's safety controls."
    )
    validate_interpretation(json.dumps(payload), context)
    payload["summary_interpretation"]["text"] = "The target blocked all mutations."
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_execution_claim" in warnings


def test_unknown_named_execution_has_no_support(scan):
    context = build_ai_context(scan)
    payload = answer(context)
    payload["summary_interpretation"]["text"] = "`unknownOperation` succeeded."
    typed = validate_interpretation(json.dumps(payload), context)
    warnings = collect_interpretation_quality_warnings(typed, context)
    assert "unsupported_execution_claim" in warnings
