"""Accessible projections retain canonical facts, provenance, and execution semantics."""

import json
from copy import deepcopy
from dataclasses import replace
from html import unescape
from io import StringIO

import httpx
import pytest
from rich.console import Console

from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application.safe_execution import execute_generated_queries
from gqlsleuth.domain.analysis import OperationCategory, RuleMatch
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.completed import render_completed_assessment
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.security_review import candidate_label
from gqlsleuth.presentation.terminology import category_label, execution_reason, rule_explanation
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import _execution_entry
from gqlsleuth.reporting.renderers import render_report


@pytest.mark.parametrize(
    "value,label",
    [
        ("tokens_and_sessions", "Tokens and sessions"),
        ("secrets_and_credentials", "Credentials and secrets"),
        ("read_only_business_data", "Read-only business data"),
        ("user_management", "User management"),
        ("personal_information", "Personal information"),
        ("files_and_uploads", "Files and uploads"),
        ("password_credentials", "Password credentials"),
        ("future_category", "Future category"),
    ],
)
def test_shared_category_labels(value, label):
    assert category_label(value) == label


@pytest.mark.parametrize(
    "locations,explanation",
    [
        (("operation.name",), "the operation name"),
        (("operation.description",), "the operation description"),
        (("argument.password",), "operation arguments"),
        (("argument_type.UserInput",), "argument types"),
        (("input_field.email",), "input fields"),
        (("return_field.accessToken", "return_field.refreshToken"), "returned fields"),
        (("return_type.AuditObject",), "returned types"),
    ],
)
def test_layered_rule_explanations_keep_exact_provenance(locations, explanation):
    match = RuleMatch(
        "password_credentials",
        OperationCategory.SECRETS_AND_CREDENTIALS,
        3,
        ("password", "passcode"),
        locations,
        "Password or passcode credential terminology.",
    )
    text = rule_explanation(match)
    assert text.startswith("Credentials and secrets:")
    assert 'Matched "password", "passcode"' in text and "(+3)" in text
    assert explanation in text and match.reason in text
    assert all(location in text for location in locations)
    assert "password_credentials" not in text


@pytest.mark.parametrize("action", ["delete", "burn", "update"])
def test_query_skip_reason_is_precautionary_and_preserves_actions(action):
    canonical = f"Query name contains explicit state-changing action token(s): {action}."
    text = execution_reason(canonical)
    assert "Safe Query execution skipped" in text and "as a precaution" in text
    assert "may modify data" in text and f'"{action}"' in text
    assert execution_reason("Server error: " + canonical) == "Server error: " + canonical


@pytest.fixture
def accessible_report(phase_ten_scan, monkeypatch):
    safe, requests = phase_ten_scan(
        """
        type Query {
            login(password: String!): Session
            users: [User]
            health: String
            nested(input: Recursive!): User
            deleteAllPastes: String
            readAndBurn: String
            systemUpdate: String
        }
        type Session { accessToken: String refreshToken: String }
        type User { id: ID friends: [User] }
        input Recursive { next: Recursive }
        """,
        mode=ScanMode.SAFE,
    )

    def handler(request):
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            json={"errors": [{"message": "Placeholder rejected by local fixture."}]}
            if "login(" in payload["query"]
            else {"data": None},
        )

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        safe = execute_generated_queries(safe.query_generation, client=client)
    report = build_report(safe)
    # Include the informational operation to exercise its fallback category label too.
    report = replace(report, review_candidates=tuple(q.generated.operation for q in report.queries))
    monkeypatch.setattr("gqlsleuth.presentation.completed.build_report", lambda *a, **k: report)
    monkeypatch.setattr(HttpClient, "send", lambda *a, **k: pytest.fail("Rendering sent HTTP"))
    return safe, report, requests


@pytest.mark.parametrize("format", ["console", "markdown", "html"])
def test_all_human_formats_share_terms_without_changing_data(accessible_report, format):
    safe, report, requests = accessible_report
    before = deepcopy((safe, report, requests, build_ai_context(safe)))
    canonical = render_report(report, ReportFormat.JSON)
    if format == "console":
        stream = StringIO()
        render_completed_assessment(
            Console(file=stream, width=140, theme=CONSOLE_THEME, color_system=None),
            safe,
            verbose=True,
        )
        text = stream.getvalue()
        assert "ATTACK SURFACE" in text and "OPERATION REVIEW CANDIDATES" in text
        assert "deleteAllPastes\nEXECUTION\n" in text
        assert "\nREQUEST\nGraphQL document:" in text and "\nRESPONSE\nMETADATA\n" in text
    else:
        text = unescape(render_report(report, ReportFormat(format))).replace("\\", "")
        assert "Attack Surface" in text and "Operation Review Candidates" in text
        assert text.count("Safety Notice") == 1
    plain = " ".join(text.split())
    for label in ("Credentials and secrets", "Tokens and sessions", "Read-only business data"):
        assert label in plain
    for kind, label in (
        (SecurityCandidateType.LIST_BOUNDING_REVIEW, "Result Size Limit Review"),
        (SecurityCandidateType.COMPLEX_INPUT_REVIEW, "Complex / Nested Input Review"),
        (SecurityCandidateType.RECURSIVE_GRAPH_REVIEW, "Recursive Relationship Review"),
    ):
        assert candidate_label(kind) == label and label in plain
        assert kind.value in canonical
    assert "argument.password" in plain and '"password"' in plain and "(+3)" in plain
    assert "password_credentials:" not in plain
    assert "Execution attempted" in plain and "Attempted (execution evidence)" not in plain
    assert "as a precaution" in plain and '"delete"' in plain
    assert "Checked root arguments and nested input objects up to 3 levels" in plain
    assert "Runtime controls may exist outside the schema" in plain
    assert "does not prove runtime enforcement" in plain
    assert "Recursive input:" in plain and "Cycle:" in plain
    assert "not confirmed vulnerabilities" in plain
    for term in ("GraphQL", "Query", "schema", "HTTP", "Variables"):
        assert term in text
    for value in ("secrets_and_credentials", "tokens_and_sessions", "read_only_business_data"):
        assert value in canonical
    assert json.loads(canonical)["report_schema_version"] == 2
    assert render_report(report, ReportFormat.JSON) == canonical
    assert (safe, report, requests, build_ai_context(safe)) == before


def test_execution_attempt_includes_connection_failure(phase_ten_scan):
    safe, _ = phase_ten_scan("type Query { health: String }")

    def unavailable(request):
        raise httpx.ConnectError("Offline fixture", request=request)

    with HttpClient(transport=httpx.MockTransport(unavailable)) as client:
        failed = execute_generated_queries(safe.query_generation, client=client)
    report = build_report(failed)
    item = report.queries[0]
    assert item.execution.attempted and item.execution.response is None
    entry = _execution_entry(item, report.evidence)
    assert dict(entry.details)["Execution attempted"] == "Yes"
    assert dict(entry.details)["Status"] == "NETWORK_FAILURE"
    assert "Request sent" not in dict(entry.details)
