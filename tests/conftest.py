"""Offline full-workflow fixture for Phase 10 regression boundaries."""

import json
from collections.abc import Callable

import httpx
import pytest
from graphql import build_schema, introspection_from_schema

from gqlsleuth.application.graphql_detection import discover_and_detect_graphql
from gqlsleuth.application.introspection import introspect_detected_endpoints
from gqlsleuth.application.operation_analysis import analyze_schema_results
from gqlsleuth.application.query_generation import generate_analyzed_queries
from gqlsleuth.application.safe_execution import SafeExecutionScanResult, execute_generated_queries
from gqlsleuth.application.schema_parsing import parse_introspection_schemas
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.graphql.introspection import FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION_QUERY
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.rules.loader import load_bundled_rules

DEFAULT_ACTIVE_SCHEMA = """
type Query { health: String readAndBurn: String }
type Mutation {
  createUser(id: ID!): String
  updateProfile: String
  setPreference: String
  deleteUser: String
  purgeLogs: String
  burnHistory: String
}
"""


@pytest.fixture
def phase_ten_scan() -> Callable[..., tuple[SafeExecutionScanResult, list[dict[str, object]]]]:
    def scan(
        sdl: str = DEFAULT_ACTIVE_SCHEMA,
        mode: ScanMode = ScanMode.ACTIVE,
    ) -> tuple[SafeExecutionScanResult, list[dict[str, object]]]:
        introspection = introspection_from_schema(build_schema(sdl))
        requests: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, json={"data": {"__typename": "Query"}})
            payload = json.loads(request.content)
            requests.append(payload)
            if payload["query"] == MINIMAL_INTROSPECTION_QUERY:
                return httpx.Response(
                    200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
                )
            if payload["query"] == FULL_INTROSPECTION_QUERY:
                return httpx.Response(200, json={"data": introspection})
            assert payload["query"].startswith("query")
            return httpx.Response(200, json={"data": None})

        with HttpClient(transport=httpx.MockTransport(handler)) as client:
            detection = discover_and_detect_graphql(
                Target.parse("https://example.com/graphql"), mode=mode, client=client
            )
            introspections = introspect_detected_endpoints(detection, client=client)
            schemas = parse_introspection_schemas(introspections)
            analysis = analyze_schema_results(schemas, load_bundled_rules())
            generated = generate_analyzed_queries(analysis)
            return execute_generated_queries(generated, client=client), requests

    return scan
