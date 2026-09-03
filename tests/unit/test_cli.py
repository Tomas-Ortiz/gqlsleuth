"""Tests for stable CLI behavior and Phase 8 workflow delegation."""

import pytest
from typer.testing import CliRunner

import gqlsleuth.cli as cli_module
from gqlsleuth import __version__
from gqlsleuth.application.endpoint_discovery import (
    EndpointDiscoveryResult,
    EndpointProbeResult,
)
from gqlsleuth.application.graphql_detection import (
    CandidateDetectionResult,
    GraphQLDetectionResult,
)
from gqlsleuth.application.introspection import (
    EndpointIntrospectionResult,
    IntrospectionScanResult,
)
from gqlsleuth.application.operation_analysis import (
    EndpointOperationAnalysisResult,
    OperationAnalysisScanResult,
)
from gqlsleuth.application.query_generation import QueryGenerationScanResult
from gqlsleuth.application.schema_parsing import EndpointSchemaResult, SchemaScanResult
from gqlsleuth.domain.analysis import (
    InterestPriority,
    OperationAnalysis,
    OperationCategory,
    OperationKind,
    RuleMatch,
)
from gqlsleuth.domain.models import ConfidenceLevel, ScanMode, Target
from gqlsleuth.domain.query_generation import QueryGenerationResult
from gqlsleuth.domain.schema import ParsedSchema, SchemaSummary, TypeReference
from gqlsleuth.graphql.introspection import IntrospectionStatus
from gqlsleuth.infrastructure.http import HttpResponse

runner = CliRunner()
app = cli_module.app


@pytest.fixture(autouse=True)
def scan_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ScanMode]]:
    """Keep CLI tests offline while recording application-service delegation."""
    calls: list[tuple[str, ScanMode]] = []

    def fake_scan(
        target_url: str,
        *,
        mode: ScanMode = ScanMode.SAFE,
    ) -> QueryGenerationScanResult:
        target = Target.parse(target_url)
        calls.append((target_url, mode))
        candidate_url = f"{target.scheme}://{target.host}/graphql"
        response = HttpResponse(
            request_url=candidate_url,
            final_url=candidate_url,
            status_code=404,
            headers={},
            body=b"",
            duration_seconds=0,
            redirect_count=0,
        )
        discovery = EndpointDiscoveryResult(
            target=target,
            mode=mode,
            probes=(EndpointProbeResult(candidate_url=candidate_url, response=response),),
            evidence=(),
        )
        detection = CandidateDetectionResult(
            candidate_url=candidate_url,
            get_signals=(),
            post_probe_required=True,
            post_response=response,
            post_signals=(),
            post_error_type=None,
            post_error_message=None,
            confidence=ConfidenceLevel.CONFIRMED,
            reason="Valid data.__typename string.",
        )
        detection_result = GraphQLDetectionResult(
            discovery=discovery,
            detections=(detection,),
            confirmation_evidence=(),
        )
        introspection = EndpointIntrospectionResult(
            endpoint=candidate_url,
            status=IntrospectionStatus.ENABLED,
            minimal_response=response,
            minimal_error_type=None,
            minimal_error_message=None,
            full_retrieval_attempted=True,
            full_response=response,
            full_error_type=None,
            full_error_message=None,
            reason="Full introspection response was retrieved.",
        )
        introspection_result = IntrospectionScanResult(
            detection=detection_result,
            introspections=(introspection,),
            introspection_evidence=(),
        )
        summary = SchemaSummary(
            query_root="Query",
            mutation_root="Mutation",
            subscription_root=None,
            total_type_count=4,
            object_type_count=2,
            input_object_type_count=0,
            scalar_type_count=2,
            custom_scalar_type_count=0,
            enum_type_count=0,
            interface_type_count=0,
            union_type_count=0,
            directive_count=0,
            query_field_count=2,
            mutation_field_count=1,
            subscription_field_count=0,
        )
        schema = ParsedSchema(
            query_root="Query",
            mutation_root="Mutation",
            subscription_root=None,
            types=(),
            directives=(),
            summary=summary,
        )
        schema_scan = SchemaScanResult(
            introspection=introspection_result,
            schemas=(
                EndpointSchemaResult(
                    endpoint=candidate_url,
                    success=True,
                    schema=schema,
                    error_type=None,
                    error_message=None,
                ),
            ),
            schema_evidence=(),
        )
        operations = (
            _operation(
                candidate_url,
                "resetPassword",
                OperationKind.MUTATION,
                InterestPriority.HIGH_INTEREST,
                6,
                ("password", "reset"),
            ),
            _operation(
                candidate_url,
                "exportUsers",
                OperationKind.QUERY,
                InterestPriority.MEDIUM_INTEREST,
                4,
                ("export", "user"),
            ),
        )
        analysis_result = OperationAnalysisScanResult(
            schema_scan=schema_scan,
            endpoints=(
                EndpointOperationAnalysisResult(
                    endpoint=candidate_url,
                    success=True,
                    operations=operations,
                    error_type=None,
                    error_message=None,
                ),
            ),
            operation_evidence=(),
        )
        return QueryGenerationScanResult(
            operation_analysis=analysis_result,
            queries=(
                QueryGenerationResult(
                    operation=operations[1],
                    query_text="query {\n  exportUsers\n}",
                    variables={},
                    manual_adjustments=(),
                    failure_reason=None,
                ),
            ),
            query_evidence=(),
        )

    monkeypatch.setattr(cli_module, "run_query_generation_scan", fake_scan)
    return calls


def _operation(
    endpoint: str,
    name: str,
    kind: OperationKind,
    priority: InterestPriority,
    score: int,
    keywords: tuple[str, ...],
) -> OperationAnalysis:
    match = RuleMatch(
        rule_id=name.casefold(),
        category=OperationCategory.USER_MANAGEMENT,
        weight=score,
        matched_keywords=keywords,
        locations=("operation.name",),
        reason="Deterministic test terminology.",
    )
    return OperationAnalysis(
        endpoint=endpoint,
        kind=kind,
        name=name,
        return_type=TypeReference.named("String"),
        categories=(OperationCategory.USER_MANAGEMENT,),
        interest_score=score,
        priority=priority,
        matched_rules=(match,),
        reasons=(match.reason,),
    )


def test_root_help_describes_authorized_use() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Authorized GraphQL security discovery and analysis" in result.stdout
    assert "explicitly authorized" in result.stdout
    assert "scan" in result.stdout
    assert "version" in result.stdout


def test_version_command_reports_package_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"GQLSleuth {__version__}"


def test_scan_command_runs_safe_query_generation_workflow() -> None:
    target = "https://example.com"

    result = runner.invoke(app, ["scan", target])
    output = " ".join(result.stdout.split())

    assert result.exit_code == 0
    assert "query generation completed" in output
    assert "GraphQL: CONFIRMED" in output
    assert "Introspection: ENABLED" in output
    assert "Schema: PARSED" in output
    assert "Query root: Query" in output
    assert "Mutation root: Mutation" in output
    assert "Types: 4; Queries: 2; Mutations: 1; Subscriptions: 0" in output
    assert "2 root operation(s); 2 security-review candidate(s)" in output
    assert "HIGH INTEREST [mutation] resetPassword" in output
    assert "interest score 6" in output
    assert "MEDIUM INTEREST [query] exportUsers" in output
    assert "interest score 4" in output
    assert output.index("resetPassword") < output.index("exportUsers")
    assert "Generated read-only queries: 1/1" in output
    assert "query { exportUsers }" in output
    assert "generated 1/1 read-only query artifact(s)" in output
    assert "Generated queries were not executed" in output
    assert "processed 1 schema result(s)" in output
    assert "not vulnerability severities or vulnerability confirmation" in output.lower()
    assert target in output
    assert "Effective mode: safe" in output


def test_scan_command_requires_a_target() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "Missing argument 'TARGET'" in result.stderr


def test_scan_help_exposes_current_scan_options() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "--mode" in result.stdout
    assert "safe" in result.stdout
    assert "active" in result.stdout
    assert "--config" not in result.stdout


def test_scan_accepts_explicit_safe_mode() -> None:
    result = runner.invoke(app, ["scan", "https://example.com", "--mode", "safe"])
    output = " ".join(result.stdout.split())

    assert result.exit_code == 0
    assert "Effective mode: safe" in output
    assert "not vulnerability severities or vulnerability confirmation" in output


def test_scan_accepts_active_with_the_same_non_executing_query_generation_behavior() -> None:
    result = runner.invoke(app, ["scan", "https://example.com", "--mode", "active"])
    output = " ".join(result.stdout.split())

    assert result.exit_code == 0
    assert "Effective mode: active" in output
    assert "same non-executing query-generation behavior" in output
    assert "not vulnerability severities or vulnerability confirmation" in output


def test_scan_reports_invalid_target_without_a_traceback() -> None:
    result = runner.invoke(app, ["scan", "ftp://example.com"])

    assert result.exit_code == 2
    assert "Unsupported target scheme" in result.stderr
    assert "Traceback" not in result.stderr


def test_scan_delegates_target_and_mode_to_phase_eight_workflow(
    scan_calls: list[tuple[str, ScanMode]],
) -> None:
    result = runner.invoke(app, ["scan", "https://example.com"])

    assert result.exit_code == 0
    assert scan_calls == [("https://example.com", ScanMode.SAFE)]
