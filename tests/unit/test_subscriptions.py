"""Bounded Subscription preparation, protocol state, explicit policy and secret isolation."""

import json
from dataclasses import replace
from io import StringIO

import pytest
from graphql import parse
from rich.console import Console

from fixtures.phase30_target import SDL
from gqlsleuth.ai.context import build_ai_context
from gqlsleuth.application import subscriptions as application
from gqlsleuth.application.abuse_controls import prepare_abuse_controls
from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.exceptions import GQLSleuthError
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.subscriptions import SubscriptionOutcome, SubscriptionProtocol
from gqlsleuth.graphql.subscriptions import parse_subscription_object, websocket_url
from gqlsleuth.infrastructure.http import HttpClientSettings
from gqlsleuth.infrastructure.websocket import WebSocketFailure
from gqlsleuth.presentation.console import CONSOLE_THEME
from gqlsleuth.presentation.subscriptions import render_subscriptions
from gqlsleuth.reporting.builder import build_report
from gqlsleuth.reporting.models import ReportFormat
from gqlsleuth.reporting.presentation import human_sections
from gqlsleuth.reporting.renderers import render_report

ACK = {"type": "connection_ack"}
EVENT = {"type": "next", "id": "1", "payload": {"data": {"notificationCreated": {"id": "fixture"}}}}


@pytest.fixture
def safe(phase_ten_scan):
    return phase_ten_scan(SDL)[0]


@pytest.fixture
def wire(monkeypatch):
    state = {
        "frames": [ACK, EVENT],
        "protocol": "graphql-transport-ws",
        "opens": 0,
        "sent": [],
        "closed": 0,
        "failure": None,
        "after_ack": None,
    }

    class Socket:
        frame_count = 0
        close_code = None

        def __init__(self, url, settings):
            state["url"], state["settings"] = url, settings
            self.protocol = state["protocol"]

        def __enter__(self):
            state["opens"] += 1
            if state["failure"]:
                raise state["failure"]
            return self

        def __exit__(self, *args):
            state["closed"] += 1

        def send(self, value):
            state["sent"].append(json.loads(value))

        def receive(self, timeout):
            assert 0 < timeout <= 10
            if not state["frames"]:
                raise TimeoutError
            value = state["frames"].pop(0)
            if isinstance(value, BaseException):
                raise value
            self.frame_count += 1
            if value == ACK and state["after_ack"]:
                state["after_ack"]()
            return json.dumps(value) if isinstance(value, dict) else value

    monkeypatch.setattr(application, "WebSocketClient", Socket)
    return state


def selected(safe, **kwargs):
    session = application.SubscriptionSecuritySession(safe, enabled=True, **kwargs)
    index = next(
        i
        for i, c in enumerate(session.preview.candidates, 1)
        if c.field.name == "notificationCreated"
    )
    return session, session.select(index)


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        "null",
        "true",
        "bad",
        '{"a":1,"a":2}',
        '{"x":{"a":1,"a":2}}',
        '{"a":NaN}',
        '{"a":Infinity}',
        '{"a":1e999}',
        '{"x":"' + "é" * 2200 + '"}',
        '{"a":"\\ud800"}',
    ],
)
def test_json_configuration_errors_do_not_echo(raw):
    with pytest.raises(GQLSleuthError) as error:
        parse_subscription_object([raw])
    assert raw not in str(error.value)


def test_json_nested_and_single():
    assert parse_subscription_object(['{"x":[true,1,null,{"text":"ok"}]}']) == {
        "x": [True, 1, None, {"text": "ok"}]
    }
    assert parse_subscription_object([]) is None
    with pytest.raises(GQLSleuthError):
        parse_subscription_object(["{}", "{}"])


@pytest.mark.parametrize(
    "http,override,expected",
    [
        ("http://example.com/graphql?a=1", None, "ws://example.com/graphql?a=1"),
        ("https://example.com:9443/graphql", None, "wss://example.com:9443/graphql"),
        (
            "https://example.com/graphql",
            "wss://example.com:443/events?x=y",
            "wss://example.com:443/events?x=y",
        ),
        ("http://[::1]:5555/graphql", None, "ws://[::1]:5555/graphql"),
    ],
)
def test_url_derivation(http, override, expected):
    assert websocket_url(http, override) == expected


@pytest.mark.parametrize(
    "override",
    [
        "ws://example.com/g",
        "wss://other.example/g",
        "wss://example.com:444/g",
        "wss://example.com/g#fragment",
        "wss://a:b@example.com/g",
        "https://example.com/g",
        "/relative",
        "wss://example.com:0/g",
        "wss://example.com/\\g",
        "wss://example.com/ a",
        "wss://example.com/" + "a" * 4096,
    ],
)
def test_url_rejects_cross_origin_and_malformed(override):
    with pytest.raises(GQLSleuthError):
        websocket_url("https://example.com/graphql", override)


def test_preparation_uses_root_and_phase16(safe, wire):
    result = application.prepare_subscriptions(safe, enabled=True)
    assert not wire["opens"]
    assert [c.field.name for c in result.candidates] == ["messageAdded", "notificationCreated"]
    for candidate in result.candidates:
        assert candidate.source in safe.query_generation.security_review.candidates
        assert candidate.source.source_evidence_ids and not candidate.failure
        ast = parse(candidate.query)
        assert len(ast.definitions) == 1
        operation = ast.definitions[0]
        assert operation.operation.value == "subscription" and operation.name is None
        assert len(operation.selection_set.selections) == 1
    assert result.candidates[0].variables == {"conversationId": "1"}
    assert result.candidates[1].variables == {}
    absent = replace(safe, query_generation=replace(safe.query_generation, security_review=None))
    assert not application.prepare_subscriptions(absent, enabled=True).candidates


def test_shared_input_generation_and_failure_isolation(phase_ten_scan):
    sdl = """
      scalar DateTime
      enum Choice { A B }
      input Profile { email: String! names: [String!]! choice: Choice! enabled: Boolean! }
      input Loop { others: [Loop!]! }
      type Item { children: [Item] id: ID }
      type Query { events: String }
      type Mutation { subscribe: String }
      type Subscription {
        a(input: Profile!, count: Int!, stamp: DateTime!, optional: String): Item
        b(input: Loop!): Item
      }
    """
    result = application.prepare_subscriptions(phase_ten_scan(sdl)[0], enabled=True)
    assert len(result.candidates) == 2
    good, bad = result.candidates
    assert good.variables == {
        "input": {"email": "test@example.com", "names": ["test"], "choice": "A", "enabled": False},
        "count": 1,
        "stamp": "test",
    }
    assert good.manual_adjustments and not good.failure and bad.failure
    assert "children" not in good.query


@pytest.mark.parametrize(
    "overrides,success",
    [
        ({"conversationId": "123"}, True),
        ({}, True),
        ({"conversationId": None}, False),
        ({"conversationId": True}, False),
        ({"other": "secret"}, False),
    ],
)
def test_variable_override_validation(safe, overrides, success):
    current = application.SubscriptionSecuritySession(safe, enabled=True, overrides=overrides)
    if success:
        preview = current.select(1)
        assert preview.plan.variables == {"conversationId": overrides.get("conversationId", "1")}
    else:
        with pytest.raises(GQLSleuthError) as error:
            current.select(1)
        assert "secret" not in str(error.value)


@pytest.mark.parametrize("protocol", list(SubscriptionProtocol))
@pytest.mark.parametrize("deny", [False, True])
def test_exact_protocol_sequence_one_event_terminal(safe, wire, protocol, deny):
    wire["protocol"] = protocol.value
    wire["frames"] = [
        ACK,
        {**EVENT, "type": "next" if protocol is SubscriptionProtocol.MODERN else "data"},
        EVENT,
    ]
    current, preview = selected(safe, deny=deny)
    result = current.execute(preview=preview, confirmed=True)
    attempt = result.attempts[0]
    assert attempt.outcome is SubscriptionOutcome.EVENT_RETURNED and len(result.findings) == int(
        deny
    )
    assert (
        attempt.acknowledged and attempt.subscription_sent and attempt.application_event_count == 1
    )
    types = [m["type"] for m in wire["sent"]]
    assert types == (
        ["connection_init", "subscribe", "complete"]
        if protocol is SubscriptionProtocol.MODERN
        else ["connection_init", "start", "stop", "connection_terminate"]
    )
    assert wire["sent"][0] == {"type": "connection_init"}
    assert wire["sent"][1]["id"] == "1"
    assert wire["sent"][1]["payload"] == {"query": preview.plan.candidate.query, "variables": {}}
    assert len(wire["frames"]) == 1 and wire["closed"] == 1
    assert current.execute(preview=preview, confirmed=True) == result and wire["opens"] == 1
    with pytest.raises(GQLSleuthError):
        current.select(1)


@pytest.mark.parametrize(
    "frames,outcome,sent",
    [
        ([], "indeterminate", False),
        ([ACK], "no_event_before_timeout", True),
        ([EVENT], "indeterminate", False),
        ([ACK, ACK], "indeterminate", True),
        ([ACK, {"type": "complete", "id": "1"}], "indeterminate", True),
        ([ACK, {"type": "next", "id": "2", "payload": EVENT["payload"]}], "indeterminate", True),
        (
            [ACK, {"type": "next", "id": "1", "payload": {"data": {"notificationCreated": None}}}],
            "indeterminate",
            True,
        ),
        (
            [ACK, {"type": "next", "id": "1", "payload": {"data": {"other": 1}}}],
            "indeterminate",
            True,
        ),
        (
            [ACK, {"type": "error", "id": "1", "payload": [{"message": "Forbidden"}]}],
            "explicit_denial",
            True,
        ),
        (
            [ACK, {"type": "error", "id": "1", "payload": [{"message": "Invalid business value"}]}],
            "indeterminate",
            True,
        ),
        (
            [
                ACK,
                {
                    "type": "error",
                    "id": "1",
                    "payload": [{"message": "Forbidden", "path": ["other"]}],
                },
            ],
            "indeterminate",
            True,
        ),
        (
            [
                ACK,
                {
                    "type": "next",
                    "id": "1",
                    "payload": {
                        "data": {"notificationCreated": 1},
                        "errors": [{"message": "Business error"}],
                    },
                },
            ],
            "indeterminate",
            True,
        ),
        ([ACK, "invalid json"], "indeterminate", True),
        ([ACK, '{"type":"next","type":"complete","id":"1"}'], "indeterminate", True),
        (
            [ACK, '{"type":"next","id":"1","payload":{"data":{"notificationCreated":NaN}}}'],
            "indeterminate",
            True,
        ),
        ([ACK, b"{}"], "indeterminate", True),
        ([ACK, {"type": "pong", "payload": []}], "indeterminate", True),
        ([ACK, {"type": "ping", "id": "1"}], "indeterminate", True),
        ([ACK, "x" * (1024 * 1024 + 1)], "indeterminate", True),
    ],
)
def test_protocol_outcomes_never_infer_access(safe, wire, frames, outcome, sent):
    wire["frames"] = list(frames)
    current, preview = selected(safe, deny=True)
    result = current.execute(preview=preview, confirmed=True)
    attempt = result.attempts[0]
    assert attempt.outcome.value == outcome and attempt.subscription_sent is sent
    assert not result.findings
    assert attempt.evaluation is (
        PolicyStatus.SATISFIED if outcome == "explicit_denial" else PolicyStatus.UNRESOLVED
    )


@pytest.mark.parametrize(
    "status,code,network,outcome",
    [
        (401, None, False, "explicit_denial"),
        (403, None, False, "explicit_denial"),
        (307, None, False, "indeterminate"),
        (None, 4401, False, "explicit_denial"),
        (None, 4403, False, "explicit_denial"),
        (None, 4408, False, "indeterminate"),
        (None, 1008, False, "indeterminate"),
        (None, None, True, "network_failure"),
    ],
)
def test_handshake_close_and_transport_normalization(safe, wire, status, code, network, outcome):
    failure = WebSocketFailure(status=status, code=code, network=network)
    if status or network:
        wire["failure"] = failure
    else:
        wire["frames"] = [failure]
    current, preview = selected(safe, deny=True)
    result = current.execute(preview=preview, confirmed=True)
    assert (
        result.attempts[0].outcome.value == outcome and not result.findings and wire["opens"] == 1
    )


@pytest.mark.parametrize(
    "protocol,control", [("graphql-transport-ws", {"type": "ping"}), ("graphql-ws", {"type": "ka"})]
)
def test_control_frames_are_bounded(safe, wire, protocol, control):
    wire["protocol"] = protocol
    wire["frames"] = [control] * 30
    current, preview = selected(safe, deny=True)
    result = current.execute(preview=preview, confirmed=True)
    assert result.attempts[0].inbound_frame_count == 20
    assert not result.attempts[0].subscription_sent and not result.findings
    assert len(wire["frames"]) == 10 and wire["opens"] == 1


@pytest.mark.parametrize(
    "change", ["query", "variables", "url", "policy", "source", "settings", "init", "post-ack"]
)
def test_rebuild_before_connect_and_after_ack(safe, wire, change):
    current, preview = selected(safe, deny=True, init_payload={"token": "PHASE30_INIT_SECRET"})
    if change == "query":
        preview = replace(
            preview,
            plan=replace(
                preview.plan, candidate=replace(preview.plan.candidate, query="query { health }")
            ),
        )
    elif change == "variables":
        preview.plan.variables["new"] = "1"
    elif change == "url":
        preview = replace(preview, plan=replace(preview.plan, ws_url="wss://other.example/"))
    elif change == "policy":
        preview = replace(preview, plan=replace(preview.plan, policy="observe"))
    elif change == "source":
        current._safe = replace(
            safe, query_generation=replace(safe.query_generation, security_review=None)
        )
    elif change == "settings":
        current._settings = HttpClientSettings(timeout_seconds=3)
    elif change == "init":
        current._init["token"] = "different"
    else:
        wire["after_ack"] = lambda: current._init.update(token="different")
    result = current.execute(preview=preview, confirmed=True)
    assert wire["opens"] == int(change == "post-ack")
    assert not any(m["type"] in ("subscribe", "start") for m in wire["sent"])
    assert not result.findings


@pytest.mark.parametrize("confirmed", [False, 1, "yes", None])
def test_strict_confirmation(safe, wire, confirmed):
    current, preview = selected(safe)
    assert not current.execute(preview=preview, confirmed=confirmed).attempts
    assert not current.execute(preview=preview, confirmed=True).attempts and not wire["opens"]


def test_safe_disabled_empty_selection(phase_ten_scan, wire):
    safe = phase_ten_scan(SDL, mode=ScanMode.SAFE)[0]
    assert not application.prepare_subscriptions(safe, enabled=True).candidates
    current = application.SubscriptionSecuritySession(safe)
    assert (
        not current.execute(preview=current.preview, confirmed=True).attempts and not wire["opens"]
    )


def test_private_init_header_echo_reports_ai_isolation(safe, wire):
    secret = "PHASE30_INIT_SECRET"
    header = "PHASE30_HEADER_SECRET"
    wire["frames"] = [ACK, {**EVENT, "payload": {"data": {"notificationCreated": {"id": secret}}}}]
    current, preview = selected(
        safe,
        deny=True,
        init_payload={"nested": {"Authorization": "Bearer " + secret}},
        http_settings=HttpClientSettings(custom_headers=(("Authorization", "Bearer " + header),)),
    )
    result = current.execute(preview=preview, confirmed=True)
    assert wire["sent"][0]["payload"]["nested"]["Authorization"] == "Bearer " + secret
    assert wire["settings"].custom_headers == (("Authorization", "Bearer " + header),)
    assert (
        result.attempts[0].response_material_withheld and result.attempts[0].response_body is None
    )
    active = execute_selected_mutations(prepare_active_mutations(safe), confirmed=False)
    combined = replace(active, subscription_security=result)
    assert build_ai_context(active) == build_ai_context(combined)
    assert prepare_abuse_controls(active, enabled=True) == prepare_abuse_controls(
        combined, enabled=True
    )
    assert combined.evidence[: len(active.evidence)] == active.evidence
    assert '"subscription_security"' not in render_report(build_report(active), ReportFormat.JSON)
    report = build_report(combined)
    assert human_sections(report)[-1].title == "Safety Notice"
    texts = [str(result), str(build_ai_context(combined))]
    for format in ReportFormat:
        text = render_report(report, format)
        texts.append(text)
        if format is not ReportFormat.JSON:
            assert "Subscription Security Findings" in text
            assert text.count("Safety Notice") == 1
    stream = StringIO()
    render_subscriptions(Console(file=stream, theme=CONSOLE_THEME), result)
    texts.append(stream.getvalue())
    assert all(secret not in text and header not in text for text in texts)


def test_nested_private_values_do_not_depend_on_recursive_traversal():
    value = "PHASE30_DEEP_SECRET"
    for _ in range(600):
        value = {"x": value}
    assert application._private_values(value) == ("PHASE30_DEEP_SECRET", "PHASE30_DEEP_SECRET")
