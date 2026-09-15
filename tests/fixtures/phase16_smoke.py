"""Local metadata-only Phase 16 smoke: no HTTP transport or GraphQL execution allowed."""

import argparse
import json
from pathlib import Path
from unittest.mock import patch

from graphql import build_schema, introspection_from_schema
from rich.console import Console

from gqlsleuth.application.endpoint_discovery import EndpointDiscoveryResult
from gqlsleuth.application.graphql_detection import GraphQLDetectionResult
from gqlsleuth.application.introspection import IntrospectionScanResult
from gqlsleuth.application.operation_analysis import analyze_schema_results
from gqlsleuth.application.query_generation import QueryGenerationScanResult
from gqlsleuth.application.reporting import generate_reports
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.application.schema_parsing import EndpointSchemaResult, SchemaScanResult
from gqlsleuth.application.security_review import review_analyzed_schemas
from gqlsleuth.domain.models import ScanMode, Target
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.graphql.schema_parser import parse_introspection_response
from gqlsleuth.presentation.console import CONSOLE_THEME, render_security_review
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.rules.loader import load_bundled_rules

SDL = Path(__file__).with_name("phase16_schema.graphql").read_text(encoding="utf-8")
ENDPOINT = "https://local-fixture.example/graphql"


def local_result():
    """Assemble existing composition from a local fixture, without fake HTTP evidence."""
    parsed = parse_introspection_response(
        json.dumps({"data": introspection_from_schema(build_schema(SDL))}).encode()
    )
    discovery = EndpointDiscoveryResult(Target.parse(ENDPOINT), ScanMode.SAFE, (), ())
    detection = GraphQLDetectionResult(discovery, (), ())
    introspection = IntrospectionScanResult(detection, (), ())
    schemas = SchemaScanResult(
        introspection, (EndpointSchemaResult(ENDPOINT, True, parsed, None, None),), ()
    )
    analysis = analyze_schema_results(schemas, load_bundled_rules())
    review = review_analyzed_schemas(analysis)
    return SafeExecutionScanResult(QueryGenerationScanResult(analysis, (), (), review), (), ())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("reports/phase16-smoke"))
    args = parser.parse_args()
    forbidden = AssertionError("Metadata-only smoke attempted network or execution")
    with (
        patch("gqlsleuth.infrastructure.http.HttpClient.send", side_effect=forbidden),
        patch("gqlsleuth.infrastructure.ollama.OllamaClient.interpret", side_effect=forbidden),
        patch("socket.socket.connect", side_effect=forbidden),
        patch("graphql.graphql_sync", side_effect=forbidden),
    ):
        result = local_result()
        review = result.query_generation.security_review
        assert {item.candidate_type for item in review.candidates} == set(SecurityCandidateType)
        console = Console(theme=CONSOLE_THEME)
        render_security_review(console, review, verbose=True)
        paths = generate_reports(result, formats=tuple(ReportFormat), output_directory=args.output)
        for path in paths:
            console.print(str(path))
        console.print("Phase 16-specific HTTP requests: 0")
        console.print("Phase 16-specific GraphQL operations executed: 0")
        console.print("Fixture schema loaded locally; no scan requests were needed.")


if __name__ == "__main__":
    main()
