"""Offline regressions for ambiguous description/domain terms in root prioritization."""

import json
from pathlib import Path

import pytest
from graphql import build_schema, introspection_from_schema

from gqlsleuth.application.endpoint_discovery import EndpointDiscoveryResult
from gqlsleuth.application.graphql_detection import GraphQLDetectionResult
from gqlsleuth.application.introspection import IntrospectionScanResult
from gqlsleuth.application.operation_analysis import analyze_schema_results
from gqlsleuth.application.query_generation import generate_analyzed_queries
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.application.schema_parsing import EndpointSchemaResult, SchemaScanResult
from gqlsleuth.domain.analysis import InterestPriority, OperationCategory
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report
from gqlsleuth.rules.loader import load_bundled_rules
from gqlsleuth.rules.operation_analysis import analyze_schema_operations, match_output_field

ENDPOINT = "https://example.com/graphql"
SDL = (Path(__file__).parents[1] / "fixtures" / "operation_interest.graphql").read_text(
    encoding="utf-8"
)


def parsed(sdl):
    return parse_introspection_response(
        json.dumps({"data": introspection_from_schema(build_schema(sdl))}).encode()
    )


def operations(sdl):
    return analyze_schema_operations(ENDPOINT, parsed(sdl), load_bundled_rules())


def test_measured_noisy_fixture_drops_only_three_weak_candidates():
    results = operations(SDL)
    by_name = {item.name: item for item in results}
    # Before refinement: ability=1, concealed=2, combined=3; 14/14 were candidates.
    assert len(results) == 14
    assert sum(item.interest_score > 0 for item in results) == 11
    for name, weights in [("ability", [0]), ("concealed", [0]), ("combined", [0, 0])]:
        item = by_name[name]
        assert item.interest_score == 0 and item.priority is InterestPriority.INFORMATIONAL
        assert item.categories == (OperationCategory.READ_ONLY_BUSINESS_DATA,)
        assert [m.weight for m in item.matched_rules] == weights
        assert all("Context-only" in m.reason for m in item.matched_rules)
    combined = by_name["combined"]
    assert combined.matched_rules[0].locations == (
        "input_field.is_hidden",
        "return_field.is_hidden",
    )
    assert combined.matched_rules[1].locations == ("argument_description.where",)
    assert results == operations(SDL)
    assert [item.name for item in results if item.interest_score] == [
        "adminResetPassword",
        "login",
        "createUser",
        "systemDiagnostics",
        "findAccounts",
        "me",
        "searchUsers",
        "systemDebug",
        "internalStatus",
        "entries",
        "search",
    ]
    for item in results:
        assert item.interest_score == sum(match.weight for match in item.matched_rules)


@pytest.mark.parametrize("term", ["filter", "search", "find", "lookup"])
@pytest.mark.parametrize("location", ["operation", "argument", "input_field"])
def test_generic_search_descriptions_are_context_only(term, location):
    descriptions = {location: f'"{term} the ordinary rows"'}
    result = operations(f"""
        type Query {{ {descriptions.get("operation", "")}
            entries({descriptions.get("argument", "")} where: Criteria): String }}
        input Criteria {{ {descriptions.get("input_field", "")} value: String }}
    """)[0]
    assert result.interest_score == 0
    assert result.matched_rules[0].matched_keywords == (term,)
    assert result.matched_rules[0].weight == 0


@pytest.mark.parametrize("name", ["hidden", "is_hidden", "hiddenAbility", "hidden_value"])
def test_bare_hidden_in_names_does_not_imply_internal_functionality(name):
    results = operations(f"""
        type Query {{ {name}(where: Criteria): Entry }}
        input Criteria {{ {name}: Boolean }}
        type Entry {{ {name}: Boolean }}
    """)
    assert results[0].interest_score == 0
    assert OperationCategory.INTERNAL_FUNCTIONALITY not in results[0].categories
    assert results[0].matched_rules[0].matched_keywords == ("hidden",)


@pytest.mark.parametrize("surface", ["operation", "argument", "input_field", "type"])
def test_search_names_still_contribute_with_description_provenance(surface):
    names = {surface: "Filter"}
    result = operations(f"""
        type Query {{ {names.get("operation", "entries")}(
            "filter the rows" {names.get("argument", "where")}: {names.get("type", "Criteria")}
        ): String }}
        input {names.get("type", "Criteria")} {{ {names.get("input_field", "value")}: String }}
    """)[0]
    assert result.interest_score == 1
    assert result.categories == (OperationCategory.SEARCH,)
    assert result.matched_rules[0].weight == 1
    assert any("description" in loc for loc in result.matched_rules[0].locations)


def test_strong_local_lab_examples_preserve_scores_categories_and_priorities():
    by_name = {item.name: item for item in operations(SDL)}
    for name, score, priority, categories in [
        (
            "login",
            9,
            InterestPriority.CRITICAL_INTEREST,
            (
                OperationCategory.AUTHENTICATION,
                OperationCategory.TOKENS_AND_SESSIONS,
                OperationCategory.SECRETS_AND_CREDENTIALS,
            ),
        ),
        (
            "createUser",
            7,
            InterestPriority.HIGH_INTEREST,
            (
                OperationCategory.USER_MANAGEMENT,
                OperationCategory.PERSONAL_INFORMATION,
                OperationCategory.SECRETS_AND_CREDENTIALS,
            ),
        ),
        (
            "systemDiagnostics",
            6,
            InterestPriority.HIGH_INTEREST,
            (OperationCategory.SECRETS_AND_CREDENTIALS, OperationCategory.DEBUGGING),
        ),
        ("me", 3, InterestPriority.MEDIUM_INTEREST, (OperationCategory.TOKENS_AND_SESSIONS,)),
        ("systemDebug", 3, InterestPriority.MEDIUM_INTEREST, (OperationCategory.DEBUGGING,)),
    ]:
        item = by_name[name]
        assert (item.interest_score, item.priority, item.categories) == (
            score,
            priority,
            categories,
        )


@pytest.mark.parametrize("name", ["internalStatus", "privateData", "internalHidden"])
def test_strong_internal_signals_still_contribute(name):
    item = operations(f"type Query {{ {name}: String }}")[0]
    assert item.interest_score == 2
    assert item.categories == (OperationCategory.INTERNAL_FUNCTIONALITY,)


def test_specific_descriptions_remain_meaningful_and_weak_category_does_not_leak():
    item = operations("""
        type Query { "credential material" entries("filter rows" where: String): String }
    """)[0]
    assert item.interest_score == 3
    assert item.categories == (OperationCategory.SECRETS_AND_CREDENTIALS,)
    assert [(m.rule_id, m.weight) for m in item.matched_rules] == [
        ("secrets_and_credentials", 3),
        ("search", 0),
    ]


def test_nested_authorization_terminal_field_matching_is_not_rescored():
    schema = parsed("type Query { entry: Entry } type Entry { is_hidden: Boolean }")
    matches = match_output_field(schema.type_named("Entry").fields[0], load_bundled_rules())
    assert [(m.rule_id, m.weight) for m in matches] == [("internal_functionality", 2)]


def test_analysis_and_report_projection_are_offline_and_preserve_zero_match_provenance(monkeypatch):
    monkeypatch.setattr(HttpClient, "send", lambda *a, **k: pytest.fail("Unexpected HTTP request"))
    schema = parsed(
        SDL.replace(
            "entries(filter: Criteria): Entry",
            '"credential material" entries("filter rows" where: Criteria): Entry',
        )
    )
    discovery = EndpointDiscoveryResult(Target.parse(ENDPOINT), ScanMode.SAFE, (), ())
    detection = GraphQLDetectionResult(discovery, (), ())
    introspection = IntrospectionScanResult(detection, (), ())
    schemas = SchemaScanResult(
        introspection, (EndpointSchemaResult(ENDPOINT, True, schema, None, None),), ()
    )
    analysis = analyze_schema_results(schemas, load_bundled_rules())
    assert len(analysis.endpoints[0].review_candidates) == 11
    report = build_report(SafeExecutionScanResult(generate_analyzed_queries(analysis), (), ()))
    canonical = render_report(report, ReportFormat.JSON)
    data = json.loads(canonical)
    assert data["report_schema_version"] == 2
    assert len(data["review_candidates"]) == 11
    noisy = next(i for i in data["queries"] if i["generated"]["operation"]["name"] == "combined")
    assert [m["weight"] for m in noisy["generated"]["operation"]["matched_rules"]] == [0, 0]
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format).replace("\\", "")
        assert "searchUsers" in text and "(+1)" in text
        assert "Context-only terminology" in text and "(+0)" in text
    assert render_report(report, ReportFormat.JSON) == canonical
