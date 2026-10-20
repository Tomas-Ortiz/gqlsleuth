"""Exact abuse signals and status-level consistency without business-data comparison."""

import json

import pytest

from fixtures.phase27_target import INELIGIBLE_ERRORS
from gqlsleuth.domain.execution import QueryExecutionStatus as Status
from gqlsleuth.graphql.abuse_controls import classify_abuse_response, eligible_baseline


def classify(body, status=200, baseline=Status.GRAPHQL_ERROR, baseline_http=200):
    return classify_abuse_response(
        status,
        json.dumps(body).encode(),
        baseline_status=baseline,
        baseline_http_status=baseline_http,
    )


@pytest.mark.parametrize(
    "code,kind",
    [
        ("RATE_LIMITED", "rate_limit"),
        ("too_many_requests", "rate_limit"),
        ("THROTTLED", "rate_limit"),
        ("rateLimited", "rate_limit"),
        ("ACCOUNT_LOCKED", "lockout"),
        ("USER_LOCKED", "lockout"),
        ("CAPTCHA_REQUIRED", "challenge"),
        ("CHALLENGE_REQUIRED", "challenge"),
    ],
)
def test_exact_extension_signals(code, kind):
    body = {"errors": [{"message": "Fixture", "extensions": {"code": code}}]}
    result = classify(body)
    assert result.outcome.value == "control_signal_observed"
    assert result.signal.kind.value == kind and result.signal.source == "graphql_code"
    assert not eligible_baseline(Status.GRAPHQL_ERROR, 200, json.dumps(body).encode())


@pytest.mark.parametrize(
    "message,kind",
    [
        ("Too many requests.", "rate_limit"),
        ("Rate limit exceeded", "rate_limit"),
        ("too many attempts", "rate_limit"),
        ("try again later", "rate_limit"),
        ("Account locked", "lockout"),
        ("Temporarily locked", "lockout"),
        ("CAPTCHA required!", "challenge"),
    ],
)
def test_exact_message_fallback(message, kind):
    body = {"errors": [{"message": message}]}
    result = classify(body)
    assert result.signal.kind.value == kind and result.signal.source == "graphql_message"
    assert not eligible_baseline(Status.GRAPHQL_ERROR, 200, json.dumps(body).encode())


@pytest.mark.parametrize(
    "text",
    [
        "Invalid credentials",
        "unauthorized",
        "forbidden",
        "validation failed",
        "limit",
        "error",
        "blocked",
        "denied",
        "not rate limited",
        "RATE_LIMITED_EXTRA",
        "The account is not locked",
        "Too many requests may be allowed",
        "RATE_LIMITEDNESS",
    ],
)
def test_no_substring_or_generic_error_signals(text):
    result = classify({"errors": [{"message": text, "extensions": {"code": text}}]})
    assert result.signal is None
    assert result.outcome.value == (
        "no_control_signal"
        if text in {"Invalid credentials", "unauthorized", "forbidden"}
        else "indeterminate"
    )


def test_http429_without_graphql_and_retry_after_not_required():
    result = classify_abuse_response(
        429, b"Too many requests", baseline_status=Status.SUCCESS, baseline_http_status=200
    )
    assert result.signal.kind.value == "rate_limit"
    assert result.signal.source == "http_status"
    assert result.repeat_status is Status.HTTP_ERROR


def test_status_only_no_raw_business_or_error_comparison():
    assert classify({"errors": [{"message": "Access denied"}]}).outcome.value == "no_control_signal"
    assert (
        classify(
            {"data": {"search": [{"id": "999", "balance": 42}]}}, baseline=Status.SUCCESS
        ).outcome.value
        == "no_control_signal"
    )
    assert classify({"data": None}, baseline=Status.SUCCESS).outcome.value == "no_control_signal"


@pytest.mark.parametrize(
    "status,body",
    [
        (500, {"error": "unavailable"}),
        (200, []),
        (200, {"data": 123}),
        (403, {"error": "denied"}),
        (200, {"errors": [{"message": "Invalid"}]}),
    ],
)
def test_material_status_changes_are_unresolved(status, body):
    assert classify(body, status, Status.SUCCESS).outcome.value == "indeterminate"


@pytest.mark.parametrize(
    "status,http,body,eligible",
    [
        (Status.SUCCESS, 200, {"data": None}, True),
        (Status.GRAPHQL_ERROR, 200, {"errors": [{"message": "Invalid credentials"}]}, True),
        (Status.GRAPHQL_ERROR, 400, {"errors": [{"message": "Invalid input"}]}, False),
        (Status.HTTP_ERROR, 401, {"detail": "Unauthorized"}, True),
        (Status.HTTP_ERROR, 403, {"detail": "Forbidden"}, True),
        (Status.HTTP_ERROR, 500, {"detail": "Unavailable"}, False),
        (Status.HTTP_ERROR, 404, {"detail": "Missing"}, False),
        (Status.HTTP_ERROR, 429, {"detail": "Too many requests"}, False),
        (Status.GRAPHQL_ERROR, 200, {"errors": [{"message": "rate limit exceeded"}]}, False),
        (Status.SUCCESS, 200, {"data": 123}, False),
        (Status.HTTP_ERROR, 403, {}, False),
        (Status.NETWORK_FAILURE, 200, {"data": None}, False),
    ],
)
def test_conservative_baseline_eligibility(status, http, body, eligible):
    assert eligible_baseline(status, http, json.dumps(body).encode()) is eligible


def test_malformed_and_extension_code_precedence():
    result = classify_abuse_response(
        403, b"<html>Forbidden</html>", baseline_status=Status.HTTP_ERROR, baseline_http_status=403
    )
    assert result.outcome.value == "indeterminate"
    assert (
        classify(
            {"errors": [{"message": "try again later", "extensions": {"code": "BUSINESS_ERROR"}}]}
        ).signal
        is None
    )
    assert classify({"message": "rate limit exceeded"}).signal is None
    assert (
        classify({"data": {"message": "rate limit exceeded"}}, baseline=Status.SUCCESS).signal
        is None
    )


@pytest.mark.parametrize("message,code", INELIGIBLE_ERRORS)
def test_structural_or_ambiguous_errors_are_not_usable_baselines_or_repeats(message, code):
    error = {"message": message}
    if code:
        error["extensions"] = {"code": code}
    body = {"errors": [error]}
    for http_status in (200, 400, 401, 403):
        assert not eligible_baseline(Status.GRAPHQL_ERROR, http_status, json.dumps(body).encode())
    result = classify(body)
    assert result.outcome.value == "indeterminate" and result.signal is None


@pytest.mark.parametrize(
    "message,code",
    [
        ("Invalid credentials", None),
        ("Invalid credentials", "BAD_USER_INPUT"),
        ("Authentication failed", None),
        ("Incorrect username or password", None),
        ("Account disabled", None),
        ("Login failed", None),
        ("Access denied", None),
        ("Invalid token", None),
        ("Session expired", None),
        ("  INVALID   CREDENTIALS. ", None),
        ("Credenciales incorrectas", "UNAUTHENTICATED"),
        ("Non-English application outcome", "FORBIDDEN"),
        ("Authentication outcome", "invalidCredentials"),
    ],
)
def test_meaningful_application_errors_remain_eligible(message, code):
    body = {"errors": [{"message": message, "extensions": {"code": code}}]}
    assert eligible_baseline(Status.GRAPHQL_ERROR, 200, json.dumps(body).encode())
    assert classify(body).outcome.value == "no_control_signal"


def test_mixed_structural_errors_win_over_application_errors_and_partial_data():
    body = {
        "data": {"login": None},
        "errors": [
            {"message": "Invalid credentials"},
            {"message": 'Variable "$username" was not provided.'},
        ],
    }
    assert not eligible_baseline(Status.GRAPHQL_ERROR, 200, json.dumps(body).encode())
    assert classify(body).outcome.value == "indeterminate"


def test_explicit_control_signal_still_stops_even_with_an_unusable_error():
    body = {
        "errors": [
            {"message": "Syntax Error: bad document"},
            {"message": "Fixture", "extensions": {"code": "RATE_LIMITED"}},
        ]
    }
    assert not eligible_baseline(Status.GRAPHQL_ERROR, 200, json.dumps(body).encode())
    assert classify(body).outcome.value == "control_signal_observed"


@pytest.mark.parametrize("body", [b"not JSON", b"[]", b'{"errors":[{"message":null}]}'])
def test_malformed_baseline_cannot_be_treated_as_graphql_application_error(body):
    assert not eligible_baseline(Status.GRAPHQL_ERROR, 200, body)
