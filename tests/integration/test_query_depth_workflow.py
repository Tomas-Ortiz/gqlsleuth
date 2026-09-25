"""Depth-stage integration without external targets or additional AI context."""

import base64
import json
from dataclasses import replace
from io import StringIO

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from fixtures.phase18_target import SDL, is_depth_probe, response_for
from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.application.multiplicity import execute_multiplicity, prepare_multiplicity
from gqlsleuth.application.query_depth import execute_query_depth, prepare_query_depth
from gqlsleuth.domain.models import EvidenceType
from gqlsleuth.domain.query_depth import QueryDepthDecision as Decision
from gqlsleuth.infrastructure.http import HttpClient, HttpClientSettings
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.query_depth import render_depth_previews, render_query_depth
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.renderers import render_report


def second_endpoint(safe):
    generation = safe.query_generation
    analysis = generation.operation_analysis
    scan = analysis.schema_scan
    other = "https://second.example/graphql"
    artifacts = tuple(
        replace(item, operation=replace(item.operation, endpoint=other))
        for item in generation.queries
    )
    schemas = replace(
        scan,
        schemas=scan.schemas + tuple(replace(item, endpoint=other) for item in scan.schemas),
        introspection=replace(
            scan.introspection,
            introspections=scan.introspection.introspections
            + tuple(replace(item, endpoint=other) for item in scan.introspection.introspections),
        ),
    )
    review = replace(
        generation.security_review,
        candidates=generation.security_review.candidates
        + tuple(replace(item, endpoint=other) for item in generation.security_review.candidates),
    )
    return replace(
        safe,
        query_generation=replace(
            generation,
            queries=generation.queries + artifacts,
            operation_analysis=replace(analysis, schema_scan=schemas),
            security_review=review,
        ),
        executions=safe.executions
        + tuple(
            replace(
                item,
                generated_query=next(
                    artifact
                    for artifact in artifacts
                    if artifact.operation_name == item.operation_name
                ),
            )
            for item in safe.executions
        ),
    )


@pytest.mark.parametrize("network_failure", [False, True])
def test_one_global_attempt_across_endpoints(phase_ten_scan, network_failure):
    preview = prepare_query_depth(second_endpoint(phase_ten_scan(SDL)[0]))
    assert [item.base.endpoint for item in preview.candidates] == [
        "https://example.com/graphql",
        "https://second.example/graphql",
    ]
    requests = []

    def handler(request):
        requests.append(request)
        if network_failure:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(200, json={"data": {"album": None}})

    with HttpClient(transport=httpx.MockTransport(handler)) as client:
        result = execute_query_depth(
            preview, selected_indices=(2, 1, 1, 2), confirmed=True, client=client
        )
    assert len(requests) == len(result.evidence) == 1
    assert str(requests[0].url) == preview.candidates[0].base.endpoint
    assert [item.decision for item in result.executions] == [
        Decision.EXECUTED,
        Decision.SKIPPED_LIMIT,
    ]


@pytest.fixture
def depth_cli(phase_ten_scan, monkeypatch):
    requests, depths, baselines = [], [], []

    def scan(target, *, mode, http_settings=None):
        safe, baseline = phase_ten_scan(SDL, mode=mode)
        baselines.append(baseline)
        return safe

    def handler(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if isinstance(payload, dict) and payload["query"].startswith("mutation"):
            return httpx.Response(200, json={"data": {"createAlbum": {"id": "1"}}})
        status, data = response_for("POST", "/accepted", payload)
        return httpx.Response(status, json=data)

    def depth(preview, **kwargs):
        with HttpClient(
            kwargs.pop("http_settings", None), transport=httpx.MockTransport(handler)
        ) as client:
            result = execute_query_depth(preview, client=client, **kwargs)
        depths.append(result)
        return result

    def shape(preview, **kwargs):
        with HttpClient(
            kwargs.pop("http_settings", None), transport=httpx.MockTransport(handler)
        ) as client:
            return execute_multiplicity(preview, client=client, **kwargs)

    def mutations(preview, **kwargs):
        with HttpClient(
            kwargs.pop("http_settings", None), transport=httpx.MockTransport(handler)
        ) as client:
            return execute_selected_mutations(preview, client=client, **kwargs)

    monkeypatch.setattr(cli, "run_safe_execution_scan", scan)
    monkeypatch.setattr(cli, "execute_query_depth", depth)
    monkeypatch.setattr(cli, "execute_multiplicity", shape)
    monkeypatch.setattr(cli, "execute_selected_mutations", mutations)
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: True)
    return requests, depths, baselines


@pytest.mark.parametrize(
    "input,count", [("\n\n\n", 0), ("\n1\nn\n\n", 0), ("\n1\n\n\n", 0), ("\n1\ny\n\n", 1)]
)
def test_independent_cli_selection_and_unchanged_safe_sequence(depth_cli, input, count):
    safe = CliRunner().invoke(cli.app, ["scan", "https://example.com"])
    assert safe.exit_code == 0 and "Query-Depth" not in safe.output
    active = CliRunner().invoke(
        cli.app, ["scan", "https://example.com", "--mode", "active"], input=input
    )
    assert active.exit_code == 0, active.exception
    assert len(depth_cli[0]) == count == len(depth_cli[1][0].evidence)
    assert depth_cli[2][0] == depth_cli[2][1]
    assert (
        active.output.index("Query-Shape Validation")
        < active.output.index("Active Query-Depth candidates")
        < active.output.index("Active Mutation candidates")
    )
    assert active.output.count("selected active Query-Depth check?") <= 1


@pytest.mark.parametrize("invalid", ["all", "*", "1-2", "0", "9"])
def test_cli_invalid_selection_can_be_cleared(depth_cli, invalid):
    result = CliRunner().invoke(
        cli.app,
        ["scan", "https://example.com", "--mode", "active"],
        input="\n" + invalid + "\n\n\n",
    )
    assert result.exit_code == 0 and "Choose an individual Query-Depth" in result.output
    assert not depth_cli[0]


def test_cli_maximum_selection(depth_cli, phase_ten_scan, monkeypatch):
    safe = second_endpoint(phase_ten_scan(SDL)[0])
    monkeypatch.setattr(cli, "run_safe_execution_scan", lambda *args, **kwargs: safe)
    result = CliRunner().invoke(
        cli.app, ["scan", "https://example.com", "--mode", "active"], input="\n1,2\n\n\n"
    )
    assert result.exit_code == 0 and "Select at most 1 Query-Depth" in result.output
    assert not depth_cli[0] and not depth_cli[1][0].selected_indices


def test_noninteractive_never_confirms(depth_cli, monkeypatch):
    monkeypatch.setattr(cli, "_interactive_stdin", lambda: False)
    result = CliRunner().invoke(
        cli.app, ["scan", "https://example.com", "--mode", "active"], input="1\ny\n"
    )
    assert result.exit_code == 0
    assert "zero Query-Depth checks execute" in " ".join(result.output.split())
    assert not depth_cli[0]


def test_all_three_confirmations_and_budgets_are_independent(depth_cli):
    result = CliRunner().invoke(
        cli.app, ["scan", "https://example.com", "--mode", "active"], input="1,2\ny\n1\ny\n1\ny\n"
    )
    assert result.exit_code == 0, result.exception
    requests = depth_cli[0]
    assert len(requests) == 4
    assert "gqlsleuthAlias" in requests[0]["query"]
    assert isinstance(requests[1], list) and len(requests[1]) == 2
    assert is_depth_probe(requests[2])
    assert requests[3]["query"].startswith("mutation")
    for prompt in (
        "selected active Query-Shape checks?",
        "selected active Query-Depth check?",
        "selected Mutations?",
    ):
        assert result.output.count(prompt) == 1


@pytest.mark.parametrize("selected,confirmed", [((), False), ((1,), False), ((1,), True)])
def test_reports_exact_evidence_and_ai_exclusion(phase_ten_scan, selected, confirmed):
    safe = phase_ten_scan(SDL)[0]
    body = b'{"data":{"album":{"id":"1"}},"extensions":{"large":"' + b"x" * 100000 + b'"}}'
    with HttpClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    ) as client:
        result = execute_query_depth(
            prepare_query_depth(safe), selected_indices=selected, confirmed=confirmed, client=client
        )
        active = execute_selected_mutations(prepare_active_mutations(safe), client=client)
        shape = execute_multiplicity(prepare_multiplicity(safe), client=client)
    before = replace(active, multiplicity=shape)
    after = replace(before, query_depth=result)
    assert build_ai_context(before).operations == build_ai_context(after).operations
    assert after.multiplicity == before.multiplicity and after.safe_execution is safe
    assert (
        tuple(
            item
            for item in after.evidence
            if item.evidence_type is not EvidenceType.GRAPHQL_BEHAVIOR_PROBE
        )
        == before.evidence
    )
    report = build_report(after)
    encoded = json.loads(render_report(report, ReportFormat.JSON))
    previous = json.loads(
        render_report(build_report(before, generated_at=report.generated_at), ReportFormat.JSON)
    )
    assert encoded["multiplicity"] == previous["multiplicity"]
    assert encoded["query_depth"]["selected_indices"] == list(selected)
    assert encoded["query_depth"]["confirmed"] is confirmed
    evidence = [
        item for item in encoded["evidence"] if item["evidence_type"] == "graphql_behavior_probe"
    ]
    assert len(evidence) == int(confirmed)
    if evidence:
        assert base64.b64decode(evidence[0]["response_body"]["data"]) == body
        assert evidence[0]["query"] == result.candidates[0].query
        assert evidence[0]["variables"] == {"id": "1"}
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        rendered = render_report(report, format)
        assert "Controlled Query Depth Validation" in rendered
        assert "Baseline depth" in rendered and "Probe depth" in rendered
        assert "x" * 100000 not in rendered
        assert rendered.count("Safety Notice") == 1
        assert rendered.index("Controlled Query Depth Validation") < rendered.index("Safety Notice")
        if not confirmed:
            section = rendered.split("Controlled Query Depth Validation", 1)[1].split(
                "Safety Notice"
            )[0]
            assert "HTTP status" not in section
    assert "query_depth" not in json.loads(render_report(build_report(safe), ReportFormat.JSON))


@pytest.mark.parametrize("cross_origin", [False, True])
def test_depth_retains_redirect_header_protection(phase_ten_scan, cross_origin):
    headers = []

    def handler(request):
        headers.append(dict(request.headers))
        if len(headers) == 1:
            return httpx.Response(
                307, headers={"Location": "https://other.example/next" if cross_origin else "/next"}
            )
        return httpx.Response(200, json={"data": {"album": None}})

    settings = HttpClientSettings(custom_headers=(("Authorization", "PHASE18_FAKE_SECRET"),))
    with HttpClient(settings, transport=httpx.MockTransport(handler)) as client:
        result = execute_query_depth(
            prepare_query_depth(phase_ten_scan(SDL)[0]),
            selected_indices=(1,),
            confirmed=True,
            client=client,
        )
    assert "authorization" in headers[0]
    assert ("authorization" in headers[1]) is not cross_origin
    assert len(result.evidence) == 1


def test_narrow_console_and_neutral_outcome(phase_ten_scan):
    preview = prepare_query_depth(phase_ten_scan(SDL)[0])
    with HttpClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"data": {"album": None}})
        )
    ) as client:
        result = execute_query_depth(preview, selected_indices=(1,), confirmed=True, client=client)
    output = StringIO()
    console = Console(file=output, width=45, theme=CONSOLE_THEME, color_system=None)
    render_depth_previews(
        console, ((1, preview.candidates[0]),), title="Active Query-Depth candidates"
    )
    render_query_depth(console, result, verbose=True)
    text = output.getvalue()
    assert "ACCEPTED" in text and "HTTP status" in text
    assert all(len(line) <= 45 for line in text.splitlines())
