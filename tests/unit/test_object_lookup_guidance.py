"""Local capability hints reuse runtime eligibility without altering scan observations."""

import html
import json
import re
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO

import pytest
from rich.console import Console
from typer.testing import CliRunner

from gqlsleuth import cli
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application.authorization_policy import evaluate_authorization_policy
from gqlsleuth.application.object_authorization import prepare_object_authorization
from gqlsleuth.application.sequential_discovery import prepare_sequential_discovery
from gqlsleuth.domain.authorization_policy import parse_policy_assertions
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.object_authorization import parse_object_cases
from gqlsleuth.domain.sequential_discovery import parse_discovery_seeds
from gqlsleuth.graphql.object_authorization import object_fields
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.authorization_policy import render_authorization_policy
from gqlsleuth.presentation.console import CONSOLE_THEME, render_scan
from gqlsleuth.presentation.object_lookup import follow_up_commands, object_lookup_follow_ups
from gqlsleuth.presentation.sequential_discovery import render_sequential_discovery
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report

SDL = "type Query { order(id: ID!): Order } type Order { id: ID! }"
JARGON = re.compile(r"\bphase\s*(?:20|21|22)\b", re.I)


def hints_for(scan):
    schemas = scan.query_generation.operation_analysis.schema_scan.schemas
    return object_lookup_follow_ups(
        scan.query_generation.security_review,
        {item.endpoint: item.schema for item in schemas if item.schema},
    )


@pytest.mark.parametrize(
    "name,argument,id_type",
    [
        ("order", "id", "ID!"),
        ("invoice", "invoiceId", "ID!"),
        ("order", "id", "ID"),
    ],
)
def test_compatible_templates_and_both_runtime_gates(
    phase_ten_scan, monkeypatch, name, argument, id_type
):
    sdl = f"type Query {{ {name}({argument}: {id_type}): Item }} type Item {{ id: ID! }}"
    safe = phase_ten_scan(sdl, mode=ScanMode.SAFE)[0]
    active = phase_ten_scan(sdl, mode=ScanMode.ACTIVE)[0]
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Guidance sent HTTP"))
    (hint,) = hints_for(safe)
    assert hint == hints_for(active)[0]
    assert hint.object_authorization_compatible and hint.sequential_discovery_compatible
    assert follow_up_commands(hint) == (
        ("Object authorization", f'--object-auth-case "{name}:{argument}=<ID>"'),
        (
            "Differential object authorization",
            f'--object-auth-case "<CONTEXT>:{name}:{argument}=<ID>"',
        ),
        ("Sequential object discovery", f'--idor-seed "{name}:{argument}=<NUMERIC_ID>"'),
    )
    cases = parse_object_cases([f"{name}:{argument}=4321"])
    schema = safe.query_generation.operation_analysis.schema_scan.schemas[0].schema
    object_fields(schema, cases[0])
    assert prepare_object_authorization(safe, cases=cases).probes
    assert prepare_sequential_discovery(
        active,
        seeds=parse_discovery_seeds([f"{name}:{argument}=4321"]),
        enabled=True,
    ).probes
    assert "4321" not in repr(hint) and "=1" not in repr(hint)


@pytest.mark.parametrize(
    "root,types",
    [
        ("order(id: [ID]): Item", "type Item { id: ID }"),
        ("order(id: [ID!]): Item", "type Item { id: ID }"),
        ("order(id: ID!): [Item]", "type Item { id: ID }"),
        ("order(id: ID!): Item", "type Item { key: ID }"),
        ("order(id: ID!): Item", "type Item { id: String }"),
        ("order(id: ID!): Item", "interface Item { id: ID } type A implements Item { id: ID }"),
        ("order(id: ID!): Item", "union Item = A type A { id: ID }"),
        ("order(filter: Filter): Item", "input Filter { id: ID } type Item { id: ID }"),
        ("order(id: ID!, ownerId: ID!): Item", "type Item { id: ID }"),
        ("removeOrder(id: ID!): Item", "type Item { id: ID }"),
    ],
)
def test_unsupported_or_ambiguous_shapes_have_no_templates(phase_ten_scan, root, types):
    scan = phase_ten_scan(f"type Query {{ {root} }} {types}")[0]
    before = deepcopy(scan)
    assert hints_for(scan) == ()
    report = build_report(scan)
    assert "object_lookup_follow_up" not in json.loads(render_report(report, ReportFormat.JSON))
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        assert "Suggested follow-up" not in render_report(report, format)
    assert scan == before


@pytest.mark.parametrize("mode", list(ScanMode))
def test_candidates_evidence_requests_ai_and_json_are_preserved(phase_ten_scan, monkeypatch, mode):
    scan, requests = phase_ten_scan(SDL, mode=mode)
    before = deepcopy(scan)
    expected_requests = deepcopy(requests)
    context = build_ai_context(scan)
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Rendering requested HTTP"))
    report = build_report(scan, generated_at=datetime(2026, 9, 17, tzinfo=UTC))
    canonical = render_report(report, ReportFormat.JSON)
    assert canonical == render_report(
        build_report(scan, generated_at=report.generated_at), ReportFormat.JSON
    )
    projected = json.loads(canonical)
    old_projection = json.loads(
        render_report(replace(report, object_lookup_follow_up=None), ReportFormat.JSON)
    )
    hints = projected.pop("object_lookup_follow_up")
    assert projected == old_projection
    assert hints[0]["object_auth_case_template"] == "order:id=<ID>"
    assert hints[0]["differential_object_auth_case_template"] == "<CONTEXT>:order:id=<ID>"
    assert hints[0]["sequential_discovery_seed_template"] == "order:id=<NUMERIC_ID>"
    assert not JARGON.search(json.dumps(hints))
    assert scan == before and requests == expected_requests and build_ai_context(scan) == context
    assert human_sections(report)[-1].title == "Safety Notice"
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        text = render_report(report, format)
        assert "Suggested follow-up" in text
        decoded = html.unescape(text)
        for label, command in follow_up_commands(hints_for(scan)[0]):
            assert label in decoded and command in decoded
        assert "Supply a known runtime object identifier" in text
        assert not JARGON.search(text)
        assert text.count("Safety Notice") == 1
        assert not re.search(r"<h[234]>|^#{2,4} ", text.split("Safety Notice")[1], re.M)


@pytest.mark.parametrize("width", [45, 80, 140])
def test_verbose_guidance_compact_output_and_width(phase_ten_scan, width):
    scan = phase_ten_scan(SDL)[0]
    for verbose in (False, True):
        stream = StringIO()
        render_scan(Console(file=stream, width=width, theme=CONSOLE_THEME), scan, verbose=verbose)
        text = stream.getvalue()
        assert ("Suggested follow-up" in text) is verbose
        assert not JARGON.search(text)
        assert max(map(len, text.splitlines())) <= width
        if verbose:
            assert "<ID>" in text and "<NUMERIC_ID>" in text and "<CONTEXT>" in text
        else:
            assert "--object-auth-case" not in text and "--idor-seed" not in text


def test_hints_do_not_use_context_labels_or_auth_data(phase_ten_scan):
    from gqlsleuth.application.differential_review import ContextScanResult, compare_context_scans
    from gqlsleuth.domain.models import Target
    from gqlsleuth.reporting.differential import build_differential_report

    scan = phase_ten_scan(SDL, mode=ScanMode.SAFE)[0]
    differential = compare_context_scans(
        Target.parse("https://example.com/graphql"),
        (
            ContextScanResult("arbitrary-label", scan),
            ContextScanResult("second-label", scan),
        ),
    )
    report = build_differential_report(differential)
    for context in report.contexts:
        assert context.scan.object_lookup_follow_up == hints_for(scan)
        assert context.name not in repr(context.scan.object_lookup_follow_up)
    for format in (ReportFormat.HTML, ReportFormat.MARKDOWN):
        text = html.unescape(render_report(report, format))
        assert text.count('"<CONTEXT>:order:id=<ID>"') == 2
        assert text.count("Safety Notice") == 1


def test_existing_policy_and_discovery_human_text_uses_capabilities(phase_ten_scan, monkeypatch):
    safe = phase_ten_scan(SDL, mode=ScanMode.SAFE)[0]
    active = phase_ten_scan(SDL, mode=ScanMode.ACTIVE)[0]
    cases = parse_object_cases(["order:id=123"])
    policy = evaluate_authorization_policy(
        None,
        assertions=parse_policy_assertions(["1"], cases=cases),
        cases=cases,
        enabled=True,
        object_review_enabled=True,
    )
    discovery = prepare_sequential_discovery(
        active, seeds=parse_discovery_seeds(["order:id=123"]), enabled=True
    )
    assert "Phase 20" in policy.limitations[0]  # Source metadata is intentionally unmodified.
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Human rendering sent HTTP"))
    for verbose in (False, True):
        stream = StringIO()
        console = Console(file=stream, width=140, theme=CONSOLE_THEME)
        render_authorization_policy(console, policy, verbose=verbose)
        render_sequential_discovery(console, discovery, verbose=verbose)
        assert not JARGON.search(stream.getvalue())
    report = replace(
        build_report(safe),
        authorization_policy_validation=policy,
        sequential_object_discovery=discovery,
    )
    for format in (ReportFormat.MARKDOWN, ReportFormat.HTML):
        assert not JARGON.search(render_report(report, format))
    assert "Phase 20" in render_report(report, ReportFormat.JSON)
    help_result = CliRunner().invoke(cli.app, ["scan", "--help"])
    assert help_result.exit_code == 0 and not JARGON.search(help_result.stdout)


def test_absent_schema_or_review_produces_no_hint(phase_ten_scan):
    scan = phase_ten_scan(SDL)[0]
    assert object_lookup_follow_ups(scan.query_generation.security_review, {}) == ()
    assert object_lookup_follow_ups(None, {}) == ()
