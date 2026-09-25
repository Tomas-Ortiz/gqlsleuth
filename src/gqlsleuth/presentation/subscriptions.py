"""Explicit Subscription preview without private handshake/init material."""

import json

from rich.console import Console
from rich.text import Text

from gqlsleuth.domain.subscriptions import SUBSCRIPTION_NOTICE, SubscriptionSecurityResult
from gqlsleuth.presentation.console import _document, _section


def render_subscriptions(console: Console, result: SubscriptionSecurityResult) -> None:
    _section(console, "Subscriptions & GraphQL over WebSocket")
    for index, candidate in enumerate(result.candidates, 1):
        console.print(
            Text(f"[{index}] {candidate.field.name} — {candidate.endpoint}", style="cyan")
        )
        console.print(Text("Return: " + candidate.field.type.render()))
        inputs = ", ".join(
            f"{a.name}: {a.type.render()}"
            for a in candidate.field.arguments
            if a.type.outer_non_null and a.default_value is None
        )
        console.print(Text("Required inputs: " + (inputs or "none")))
        if candidate.failure:
            console.print(Text(candidate.failure))
    if result.plan:
        plan = result.plan
        console.print(Text("WebSocket endpoint: " + plan.ws_url, style="cyan"))
        console.print("Offered protocols: " + ", ".join(plan.offered_protocols))
        console.print(
            f"Handshake headers supplied: {plan.handshake_headers_supplied}; "
            f"init payload supplied: {plan.init_payload_supplied}"
        )
        console.print(
            f"Policy: {plan.policy.value.upper()}; one connection, one Subscription, "
            "at most one event; ACK/event wait at most 10s each."
        )
        _document(console, plan.candidate.query or "")
        console.print(Text(json.dumps(plan.variables, indent=2, sort_keys=True)))
        for note in plan.candidate.manual_adjustments:
            console.print(Text(note))
        console.print(
            "Placeholder values may require manual adjustment. "
            "No application event is triggered automatically."
        )
    for attempt in result.attempts:
        console.print(
            f"{attempt.outcome.value.upper()}; protocol: {attempt.negotiated_protocol}; "
            f"ACK: {attempt.acknowledged}; Subscription sent: {attempt.subscription_sent}; "
            f"frames: {attempt.inbound_frame_count}; events: {attempt.application_event_count}"
        )
        console.print(
            attempt.evaluation.value.upper()
            if attempt.evaluation
            else "OBSERVE: no DENY policy evaluation or Finding."
        )
        if attempt.limitation:
            console.print(Text(attempt.limitation))
    for limitation in result.limitations:
        console.print(Text(limitation))
    if result.findings:
        _section(console, "Subscription Security Findings")
        for finding in result.findings:
            console.print(Text(finding.label + ": " + finding.reason))
    console.print(SUBSCRIPTION_NOTICE)
