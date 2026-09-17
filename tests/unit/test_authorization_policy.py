"""Pure policy parsing/evaluation over authentic offline Phase 20 result fixtures."""

import json
from dataclasses import replace
from uuid import uuid4

import httpx
import pytest

from fixtures.phase20_target import SDL, response_for
from gqlsleuth.application import object_authorization
from gqlsleuth.application.authorization_policy import evaluate_authorization_policy
from gqlsleuth.application.differential_review import ContextScanResult, compare_context_scans
from gqlsleuth.domain.authorization_policy import (
    MAX_PHASE21_ASSERTIONS,
    ExpectedPolicy,
    PolicyProvenance,
    PolicyStatus,
    parse_policy_assertions,
)
from gqlsleuth.domain.differential import NamedAuthContext
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.domain.object_authorization import ObjectOutcome, parse_object_cases
from gqlsleuth.infrastructure.http import HttpClient


@pytest.fixture
def source(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL, mode=ScanMode.SAFE)[0]

    def build(entries=("order:id=100",), names=()):
        cases = parse_object_cases(list(entries), names)
        contexts = tuple(
            NamedAuthContext(name, (("X-Test-Context", name),) if len(names) > 1 else ())
            for name in names
        )
        scan = (
            compare_context_scans(
                Target.parse("https://example.com/graphql"),
                tuple(ContextScanResult(name, safe) for name in names),
            )
            if len(names) > 1
            else safe
        )

        def handler(request):
            status, data = response_for(
                request.method, request.headers, json.loads(request.content)
            )
            return httpx.Response(status, json=data)

        monkeypatch.setattr(
            object_authorization,
            "HttpClient",
            lambda settings: HttpClient(settings, transport=httpx.MockTransport(handler)),
        )
        return object_authorization.execute_object_authorization(
            scan, cases=cases, contexts=contexts, enabled=True
        )

    return build


def evaluate(source, values=("1",), names=(), **kwargs):
    return evaluate_authorization_policy(
        source,
        assertions=parse_policy_assertions(list(values), cases=source.cases, context_names=names),
        cases=source.cases,
        context_names=names,
        enabled=True,
        object_review_enabled=True,
        **kwargs,
    )


@pytest.mark.parametrize(
    "value", ["0", "-1", "x", "2", "*", "all", "1-2", "1,2", "1:x:y", "1:foo", "1 ", "١"]
)
def test_invalid_anonymous_references(value):
    with pytest.raises(HttpConfigurationError):
        parse_policy_assertions([value], cases=parse_object_cases(["order:id=PRIVATE:VALUE=1"]))


def test_reference_order_provenance_duplicates_and_owner():
    names = ("clienteA", "clienteB", "foo")
    cases = parse_object_cases(
        ["clienteA:order:id=123", "clienteA:order:id=123", "clienteB:order:id=456"], names
    )
    policies = parse_policy_assertions(
        ["2:clienteA", "01:foo", "1:clienteB"], cases=cases, context_names=names
    )
    assert [(item.index, item.case_index, item.context) for item in policies] == [
        (1, 2, "clienteA"),
        (2, 1, "foo"),
        (3, 1, "clienteB"),
    ]
    assert all(
        item.expected is ExpectedPolicy.DENY
        and item.provenance is PolicyProvenance.OPERATOR_SUPPLIED
        and not item.implicit_anonymous
        for item in policies
    )
    for invalid in (["1"], ["1:ClienteB"], ["1:SECRET"], ["1:clienteB", "01:clienteB"], []):
        with pytest.raises(HttpConfigurationError) as error:
            parse_policy_assertions(invalid, cases=cases, context_names=names)
        assert "SECRET" not in str(error.value)
    with pytest.raises(HttpConfigurationError, match="operator-declared authorized context.*#1"):
        parse_policy_assertions(["1:clienteA"], cases=cases, context_names=names)
    assert MAX_PHASE21_ASSERTIONS == 9
    with pytest.raises(HttpConfigurationError, match="1.*9"):
        parse_policy_assertions(["1:clienteB"] * 10, cases=cases, context_names=names)
    # Nine is a hard ceiling, not permission to bypass identity/owner validation.
    with pytest.raises(HttpConfigurationError, match="duplicate"):
        parse_policy_assertions(["1:clienteB"] * 9, cases=cases, context_names=names)


@pytest.mark.parametrize(
    "names,entry",
    [((), "1"), (("foo",), "1"), (("foo",), "1:foo"), (("anonymous",), "1:anonymous")],
)
def test_unambiguous_anonymous_and_bare_names(names, entry):
    policy = parse_policy_assertions(
        [entry], cases=parse_object_cases(["order:id=100"], names), context_names=names
    )[0]
    assert policy.context == (names[0] if names else "anonymous")
    assert policy.implicit_anonymous is (not names)


@pytest.mark.parametrize(
    "outcome,status",
    [
        (ObjectOutcome.TARGET_RETURNED, PolicyStatus.VIOLATED),
        (ObjectOutcome.EXPLICIT_DENIAL, PolicyStatus.SATISFIED),
        (ObjectOutcome.INDETERMINATE, PolicyStatus.UNRESOLVED),
        (ObjectOutcome.NETWORK_FAILURE, PolicyStatus.UNRESOLVED),
    ],
)
def test_matrix_uses_classification_never_business_bodies(source, monkeypatch, outcome, status):
    result = source()
    execution = result.executions[0]
    match = True if outcome is ObjectOutcome.TARGET_RETURNED else None
    evidence = execution.evidence.model_copy(
        update={"outcome": outcome, "returned_id_matches": match}
    )
    result = replace(
        result,
        executions=(
            replace(execution, outcome=outcome, returned_id_matches=match, evidence=evidence),
        ),
    )
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Policy made HTTP"))
    monkeypatch.setattr(
        object_authorization,
        "build_object_query",
        lambda *args: pytest.fail("Policy generated Query"),
    )
    monkeypatch.setattr(
        object_authorization,
        "execute_object_authorization",
        lambda *args, **kwargs: pytest.fail("Policy reran Phase 20"),
    )
    first = evaluate(result)
    assert first.evaluations[0].status is status
    assert first.evaluations[0].observed is outcome
    assert first.evaluations[0].source_evidence_ids == (evidence.evidence_id,)
    assert len(first.violations) == int(status is PolicyStatus.VIOLATED)
    if first.violations:
        assert first.violations[0].result_type == "authorization_policy_violation"
        assert "operator-supplied DENY" in first.violations[0].evaluation.reason
    for body in (b"not even JSON", b'{"total":9000,"email":"SECRET","roles":["arbitrary"]}'):
        changed = replace(
            result,
            executions=(
                replace(
                    result.executions[0],
                    evidence=evidence.model_copy(update={"response_body": body}),
                ),
            ),
        )
        assert evaluate(changed) == first
    assert not hasattr(first, "evidence")


def test_differential_and_unattempted_owner_short_circuit(source):
    names = ("clienteA", "clienteB", "foo")
    result = source(
        ("clienteA:order:id=123", "clienteB:order:id=456", "clienteA:order:id=999"), names
    )
    before = result.evidence
    policy = evaluate(result, ("1:clienteB", "1:foo", "2:clienteA", "3:clienteB"), names)
    assert [item.status for item in policy.evaluations] == [
        PolicyStatus.VIOLATED,
        PolicyStatus.VIOLATED,
        PolicyStatus.SATISFIED,
        PolicyStatus.UNRESOLVED,
    ]
    assert (
        not policy.evaluations[-1].source_evidence_ids and policy.evaluations[-1].observed is None
    )
    assert "not executed" in policy.evaluations[-1].reason
    assert result.evidence == before and len(result.candidates) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "context",
        "id",
        "case_index",
        "mode",
        "outcome",
        "id_match",
        "query",
        "variables",
        "evidence_type",
        "missing_evidence",
        "duplicate_evidence",
        "missing_execution",
        "missing_probe",
        "case_identity",
        "attempt_type",
    ],
)
def test_inconsistent_sources_unresolved(source, mutation):
    result = source()
    cases = result.cases
    execution = result.executions[0]
    evidence = execution.evidence
    changes = {
        "context": {"context": "other"},
        "id": {"identifier": "999"},
        "mode": {"execution_mode": ScanMode.ACTIVE},
        "outcome": {"outcome": ObjectOutcome.EXPLICIT_DENIAL},
        "id_match": {"returned_id_matches": False},
        "query": {"query": "query { other }"},
        "variables": {"variables": {"id": "999"}},
        "evidence_type": {"evidence_type": "nested_authorization_probe"},
    }
    if mutation in changes:
        result = replace(
            result,
            executions=(
                replace(execution, evidence=evidence.model_copy(update=changes[mutation])),
            ),
        )
    elif mutation == "attempt_type":
        result = replace(result, executions=(replace(execution, attempted="invalid"),))
    elif mutation == "missing_evidence":
        result = replace(result, executions=(replace(execution, evidence=None),))
    elif mutation == "case_index":
        result = replace(result, executions=(replace(execution, case_index=2),))
    elif mutation == "duplicate_evidence":
        result = replace(
            result,
            executions=(execution, replace(execution, case_index=2)),
            attempted_request_count=2,
        )
    elif mutation == "missing_execution":
        result = replace(result, executions=(), attempted_request_count=0)
    elif mutation == "missing_probe":
        result = replace(result, probes=())
    else:
        result = replace(result, cases=(replace(cases[0], identifier="999"),))
    policy = evaluate_authorization_policy(
        result,
        assertions=parse_policy_assertions(["1"], cases=cases),
        cases=cases,
        enabled=True,
        object_review_enabled=True,
    )
    assert policy.evaluations[0].status is PolicyStatus.UNRESOLVED
    assert not policy.violations and policy.limitations
    assert not policy.evaluations[0].source_evidence_ids


@pytest.mark.parametrize(
    "change",
    [
        {"expected": "allow"},
        {"expected": "deny"},
        {"provenance": "inferred"},
        {"context": "other"},
        {"index": True},
        {"case_index": 2},
        {"implicit_anonymous": False},
    ],
)
def test_forged_assertions_rejected(source, change):
    result = source()
    assertion = replace(parse_policy_assertions(["1"], cases=result.cases)[0], **change)
    with pytest.raises(HttpConfigurationError):
        evaluate_authorization_policy(
            result,
            assertions=(assertion,),
            cases=result.cases,
            enabled=True,
            object_review_enabled=True,
        )


def test_enablement_and_missing_result_fail_closed(source):
    result = source()
    assertions = parse_policy_assertions(["1"], cases=result.cases)
    for kwargs in (
        {},
        {"enabled": True},
        {"enabled": 1, "object_review_enabled": True},
        {"enabled": True, "object_review_enabled": True, "mode": ScanMode.ACTIVE},
    ):
        with pytest.raises(HttpConfigurationError):
            evaluate_authorization_policy(
                result, assertions=assertions, cases=result.cases, **kwargs
            )
    missing = evaluate_authorization_policy(
        None, assertions=assertions, cases=result.cases, enabled=True, object_review_enabled=True
    )
    assert missing.limitations and not missing.violations
    assert missing.evaluations[0].status is PolicyStatus.UNRESOLVED


def test_same_uuid_cannot_support_another_context(source):
    names = ("clienteA", "clienteB")
    result = source(("clienteA:order:id=123",), names)
    left, right = result.executions
    result = replace(
        result,
        executions=(
            left,
            replace(
                right,
                evidence=right.evidence.model_copy(
                    update={"evidence_id": left.evidence.evidence_id}
                ),
            ),
        ),
    )
    assert not evaluate(result, ("1:clienteB",), names).violations
    result = replace(
        result,
        executions=(
            left,
            replace(right, evidence=right.evidence.model_copy(update={"evidence_id": uuid4()})),
        ),
    )
    assert len(evaluate(result, ("1:clienteB",), names).violations) == 1
