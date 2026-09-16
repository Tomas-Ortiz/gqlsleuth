"""Offline CLI, reporting, transport and independent-stage integration boundaries."""

import base64
import json
from dataclasses import replace

import httpx
import pytest
from typer.testing import CliRunner

from fixtures.phase17_target import SDL, response_for
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.multiplicity import execute_multiplicity, prepare_multiplicity
from gqlsleuth.domain.models import EvidenceType
from gqlsleuth.domain.multiplicity import MultiplicityDecision as Decision
from gqlsleuth.graphql.safe_execution import classify_execution_response
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


def multi_endpoint(safe):
    generated = safe.query_generation
    analysis = generated.operation_analysis
    other = "https://second.example/graphql"
    artifacts = tuple(
        replace(item, operation=replace(item.operation, endpoint=other))
        for item in generated.queries
    )
    schema_scan = replace(
        analysis.schema_scan,
        schemas=analysis.schema_scan.schemas
        + tuple(replace(item, endpoint=other) for item in analysis.schema_scan.schemas),
    )
    generated = replace(
        generated,
        operation_analysis=replace(analysis, schema_scan=schema_scan),
        queries=generated.queries + artifacts,
    )
    executions = safe.executions + tuple(
        replace(
            item,
            generated_query=next(
                artifact for artifact in artifacts if artifact.operation_name == item.operation_name
            ),
        )
        for item in safe.executions
    )
    return replace(safe, query_generation=generated, executions=executions)


@pytest.mark.parametrize("selection", [(1, 2, 3, 4), (1, 3), (3, 4)])
def test_global_budget_across_endpoints(phase_ten_scan, selection):
    preview = prepare_multiplicity(multi_endpoint(phase_ten_scan(SDL)[0]))
    requests = []

    def handler(request):
        requests.append(request)
        status, body = response_for("POST", "/accepted", json.loads(request.content))
        return httpx.Response(status, json=body)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = execute_multiplicity(
            preview, selected_indices=selection, confirmed=True, client=client
        )
    assert len(requests) == (1 if selection == (1, 3) else 2)
    assert len({item.probe_type for item in result.evidence}) == len(requests)
    assert sum(item.decision is Decision.SKIPPED_LIMIT for item in result.executions) == len(
        selection
    ) - len(requests)


@pytest.fixture
def probe_cli(phase_ten_scan, monkeypatch):
    requests, results, baselines = [], [], []

    def scan(target, *, mode, http_settings=None):
        safe, baseline = phase_ten_scan(SDL, mode=mode)
        baselines.append(baseline)
        return safe

    def handler(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if isinstance(payload, dict) and payload["query"].startswith("mutation"):
            return httpx.Response(200, json={"data": {"createItem": {"id": "1"}}})
        status, body = response_for("POST", "/accepted", payload)
        return httpx.Response(status, json=body)

    def probes(preview, **kwargs):
        with HttpClient(
            kwargs.pop("http_settings", None), transport=httpx.MockTransport(handler)
        ) as client:
            result = execute_multiplicity(preview, client=client, **kwargs)
        results.append(result)
        return result

    def mutations(preview, **kwargs):
        with HttpClient(
            kwargs.pop("http_settings", None), transport=httpx.MockTransport(handler)
        ) as client:
            return execute_selected_mutations(preview, client=client, **kwargs)

    monkeypatch.setattr(cli, "run_safe_execution_scan", scan)
    monkeypatch.setattr(cli, "execute_multiplicity", probes)
    monkeypatch.setattr(cli, "execute_selected_mutations", mutations)
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    return requests, results, baselines


@pytest.mark.parametrize(
    "input,count",
    [
        ("\n\n", 0),
        ("1\nn\n\n", 0),
        ("1\n\n\n", 0),
        ("1\ny\n\n", 1),
        ("2\ny\n\n", 1),
        ("2,1,2\ny\n\n", 2),
    ],
)
def test_cli_explicit_selection_and_baseline_requests(probe_cli, input, count):
    requests, results, baselines = probe_cli
    safe = CliRunner().invoke(cli.app, ["scan", "https://example.com"])
    assert safe.exit_code == 0 and not results
    assert "Query-Shape" not in safe.output
    active = CliRunner().invoke(
        cli.app, ["scan", "https://example.com", "--mode", "active"], input=input
    )
    assert active.exit_code == 0, active.exception
    assert len(requests) == count == len(results[0].evidence)
    assert baselines[0] == baselines[1]
    assert active.output.count("selected active Query-Shape checks?") <= 1
    assert active.output.index("Query-Shape Validation") < active.output.index(
        "Active Mutation candidates"
    )
    if count:
        assert "Selected Query-Shape checks" in active.output


@pytest.mark.parametrize("invalid", ["all", "*", "1-2", "0", "9", "1,3", "-1"])
def test_cli_retries_invalid_selection(probe_cli, invalid):
    result = CliRunner().invoke(
        cli.app, ["scan", "https://example.com", "--mode", "active"], input=invalid + "\n\n\n"
    )
    assert result.exit_code == 0
    assert "Choose individual comma-separated" in result.output
    assert not probe_cli[0]


def test_cli_noninteractive_never_infers_confirmation(probe_cli, monkeypatch):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    result = CliRunner().invoke(
        cli.app, ["scan", "https://example.com", "--mode", "active"], input="1,2\ny\n"
    )
    assert result.exit_code == 0
    assert "Interactive selection and confirmation are required" in result.output
    assert not probe_cli[0]


def test_cli_rejects_more_than_two_and_enter_clears_selection(
    phase_ten_scan, probe_cli, monkeypatch
):
    safe = multi_endpoint(phase_ten_scan(SDL)[0])
    monkeypatch.setattr(cli, "run_safe_execution_scan", lambda *args, **kwargs: safe)
    result = CliRunner().invoke(
        cli.app, ["scan", "https://example.com", "--mode", "active"], input="1,2,3\n\n\n"
    )
    assert result.exit_code == 0
    assert "Select at most 2 Query-Shape checks" in result.output
    assert not probe_cli[0] and not probe_cli[1][0].selected_indices


def test_mutation_and_probe_confirmations_are_independent(probe_cli):
    result = CliRunner().invoke(
        cli.app, ["scan", "https://example.com", "--mode", "active"], input="1,2\ny\n1\ny\n"
    )
    assert result.exit_code == 0, result.exception
    assert len(probe_cli[0]) == 3
    assert result.output.count("selected active Query-Shape checks?") == 1
    assert result.output.count("selected Mutations?") == 1
    assert probe_cli[0][-1]["query"].startswith("mutation")


@pytest.mark.parametrize("selected,confirmed", [((), False), ((1,), False), ((1, 2), True)])
def test_reports_evidence_ai_and_phase_sixteen_isolation(phase_ten_scan, selected, confirmed):
    safe = phase_ten_scan(SDL)[0]

    def handler(request):
        status, body = response_for("POST", "/accepted", json.loads(request.content))
        return httpx.Response(status, json=body)

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        probes = execute_multiplicity(
            prepare_multiplicity(safe),
            selected_indices=selected,
            confirmed=confirmed,
            client=client,
        )
        before = execute_selected_mutations(prepare_active_mutations(safe), client=client)
    after = replace(before, multiplicity=probes)
    assert build_ai_context(before) == build_ai_context(after)
    assert (
        after.safe_execution.query_generation.security_review
        == safe.query_generation.security_review
    )
    assert (
        tuple(
            item
            for item in after.evidence
            if item.evidence_type is not EvidenceType.GRAPHQL_BEHAVIOR_PROBE
        )
        == before.evidence
    )
    report = build_report(after)
    canonical = json.loads(render_report(report, ReportFormat.JSON))
    assert canonical["multiplicity"]["selected_indices"] == list(selected)
    assert canonical["multiplicity"]["confirmed"] is confirmed
    actual = [
        item for item in canonical["evidence"] if item["evidence_type"] == "graphql_behavior_probe"
    ]
    assert len(actual) == (2 if confirmed else 0)
    for original, encoded in zip(probes.evidence, actual, strict=True):
        assert base64.b64decode(encoded["response_body"]["data"]) == original.response_body
        assert encoded["request_json"] == original.request_json
    for format in (ReportFormat.HTML, ReportFormat.MARKDOWN):
        text = render_report(report, format)
        assert "Controlled GraphQL Multiplicity Validation" in text
        assert text.count("Safety Notice") == 1
        assert text.index("Controlled GraphQL Multiplicity Validation") < text.index(
            "Safety Notice"
        )
        assert "not vulnerability confirmation" in text
    assert "multiplicity" not in json.loads(render_report(build_report(safe), ReportFormat.JSON))


@pytest.mark.parametrize("cross_origin", [False, True])
def test_batch_redirect_header_protection_and_normal_classifier(phase_ten_scan, cross_origin):
    preview = prepare_multiplicity(phase_ten_scan(SDL)[0])
    headers = []

    def handler(request):
        headers.append(dict(request.headers))
        if len(headers) == 1:
            return httpx.Response(
                307, headers={"Location": "https://other.example/next" if cross_origin else "/next"}
            )
        return httpx.Response(200, json=[{"data": None}] * 2)

    settings = HttpClientSettings(custom_headers=(("Authorization", "PHASE17_TEST_SECRET"),))
    with HttpClient(settings, transport=httpx.MockTransport(handler)) as client:
        result = execute_multiplicity(preview, selected_indices=(2,), confirmed=True, client=client)
    assert "authorization" in headers[0]
    assert ("authorization" in headers[1]) is not cross_origin
    assert len(result.evidence) == 1
    assert (
        classify_execution_response(200, b'[{"data":null},{"data":null}]').status.value
        == "invalid_response"
    )
