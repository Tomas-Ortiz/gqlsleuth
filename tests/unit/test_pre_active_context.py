"""Pre-execution context is a pure, compact view of retained SAFE workflow facts."""

from copy import deepcopy
from dataclasses import replace
from io import StringIO

import pytest
from rich.console import Console

from fixtures.cli_output import plain_cli_output
from gqlsleuth.domain.models import ConfidenceLevel, ScanMode, Target
from gqlsleuth.graphql.introspection import IntrospectionStatus
from gqlsleuth.infrastructure.http import HttpClient
from gqlsleuth.presentation.console import CONSOLE_THEME, render_pre_active_context


def with_schema_scan(safe, schema_scan):
    return replace(
        safe,
        query_generation=replace(
            safe.query_generation,
            operation_analysis=replace(
                safe.query_generation.operation_analysis, schema_scan=schema_scan
            ),
        ),
    )


@pytest.mark.parametrize("width", [40, 80])
def test_pre_active_context_uses_existing_surface_facts_without_work(
    phase_ten_scan, monkeypatch, width
):
    safe, requests = phase_ten_scan("""
        type Query { users: [User] }
        type User { id: ID friends: [User] }
        type Mutation { createUser: User }
        type Subscription { updates: User }
    """)
    before = deepcopy(safe)
    before_requests = deepcopy(requests)
    monkeypatch.setattr(HttpClient, "send", lambda *args: pytest.fail("Presentation sent HTTP"))
    stream = StringIO()
    render_pre_active_context(Console(file=stream, width=width, theme=CONSOLE_THEME), safe)
    text = plain_cli_output(stream.getvalue(), normalize_whitespace=True)
    assert "GraphQL endpoint:" in text
    assert "Queries 1" in text and "Mutations 1" in text and "Subscriptions 1" in text
    assert "Query-Shape, Query-Depth, Mutations" in text
    assert "ACTIVE validation has not run" in text
    assert "GQLSleuth Assessment" not in text
    assert len(stream.getvalue().splitlines()) < 23
    assert safe == before and requests == before_requests


def test_context_lists_only_confirmed_probable_endpoints_in_order(phase_ten_scan):
    safe, _ = phase_ten_scan()
    scan = safe.query_generation.operation_analysis.schema_scan
    introspection = scan.introspection
    first = introspection.detection.detections[0]
    second_url = "https://example.com/second"
    omitted_url = "https://example.com/possible"
    not_detected_url = "https://example.com/not_detected"
    target = "https://example.com/"
    detection = replace(
        introspection.detection,
        discovery=replace(introspection.detection.discovery, target=Target.parse(target)),
        detections=(
            first,
            replace(first, candidate_url=second_url, confidence=ConfidenceLevel.PROBABLE),
            replace(first, candidate_url=omitted_url, confidence=ConfidenceLevel.POSSIBLE),
            replace(first, candidate_url=not_detected_url, confidence=ConfidenceLevel.NOT_DETECTED),
        ),
    )
    safe = with_schema_scan(
        safe, replace(scan, introspection=replace(introspection, detection=detection))
    )
    stream = StringIO()
    render_pre_active_context(Console(file=stream, theme=CONSOLE_THEME), safe)
    text = plain_cli_output(stream.getvalue(), normalize_whitespace=True)
    assert "Target: " + target + " Mode: ACTIVE" in text
    assert text.count("GraphQL endpoint:") == 2
    assert "GraphQL endpoint: " + first.candidate_url in text
    assert "GraphQL endpoint: " + second_url in text
    assert text.index(first.candidate_url) < text.index(second_url)
    assert omitted_url not in text and not_detected_url not in text
    assert "Queries Not available" in text
    assert "Operation counts require a parsed schema" in text


def test_context_does_not_invent_an_endpoint(phase_ten_scan):
    safe, _ = phase_ten_scan()
    scan = safe.query_generation.operation_analysis.schema_scan
    introspection = scan.introspection
    detection = replace(
        introspection.detection,
        detections=tuple(
            replace(item, confidence=ConfidenceLevel.NOT_DETECTED)
            for item in introspection.detection.detections
        ),
    )
    safe = with_schema_scan(
        safe, replace(scan, introspection=replace(introspection, detection=detection))
    )
    stream = StringIO()
    render_pre_active_context(Console(file=stream, theme=CONSOLE_THEME), safe)
    assert "GraphQL endpoint:" not in stream.getvalue()
    assert "No confirmed or probable GraphQL endpoints." in stream.getvalue()


def test_blocked_schema_preserves_enabled_probe_and_unavailable_counts(phase_ten_scan):
    safe, _ = phase_ten_scan()
    scan = safe.query_generation.operation_analysis.schema_scan
    probe = scan.introspection.introspections[0]
    blocked = replace(
        probe,
        status=IntrospectionStatus.ENDPOINT_ERROR,
        full_response=probe.full_response.model_copy(
            update={"body": b'{"errors":[{"message":"Query depth limit exceeded."}]}'}
        ),
    )
    safe = with_schema_scan(
        safe,
        replace(
            scan, schemas=(), introspection=replace(scan.introspection, introspections=(blocked,))
        ),
    )
    stream = StringIO()
    render_pre_active_context(
        Console(file=stream, theme=CONSOLE_THEME),
        safe,
        requested_groups=("IDOR / BOLA",),
        include_standard_stages=False,
    )
    text = plain_cli_output(stream.getvalue(), normalize_whitespace=True)
    assert "Introspection ENABLED" in text and "Schema retrieval BLOCKED" in text
    for label in ("Queries", "Mutations", "Subscriptions"):
        assert label + " Not available" in text
    assert "Requested ACTIVE groups: IDOR / BOLA" in text
    assert "Surface-supported ACTIVE groups" not in text


def test_safe_mode_has_no_pre_active_context(phase_ten_scan):
    safe, _ = phase_ten_scan(mode=ScanMode.SAFE)
    stream = StringIO()
    render_pre_active_context(Console(file=stream), safe)
    assert stream.getvalue() == ""
