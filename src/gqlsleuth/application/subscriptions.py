"""One independently confirmed Subscription, one socket and a bounded terminal exchange."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from time import monotonic

from graphql import GraphQLError, GraphQLSchema
from pydantic import JsonValue

from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.exceptions import GQLSleuthError, HttpConfigurationError
from gqlsleuth.domain.models import EvidenceType, ScanMode
from gqlsleuth.domain.schema import ParsedSchema
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.domain.subscriptions import (
    ACK_TIMEOUT_SECONDS,
    EVENT_TIMEOUT_SECONDS,
    MAX_PHASE30_FRAME_BYTES,
    MAX_PHASE30_INBOUND_FRAMES,
    SubscriptionCandidate,
    SubscriptionEvidence,
    SubscriptionFinding,
    SubscriptionOutcome,
    SubscriptionPlan,
    SubscriptionPolicy,
    SubscriptionProtocol,
    SubscriptionSecurityResult,
)
from gqlsleuth.graphql.authorization_response import explicit_authorization_error
from gqlsleuth.graphql.query_generation import generate_subscription
from gqlsleuth.graphql.schema_parser import load_introspection_schema, parse_introspection_response
from gqlsleuth.graphql.subscriptions import (
    classify_subscription_payload,
    decode_subscription_object,
    parse_subscription_object,
    validate_subscription,
    websocket_url,
)
from gqlsleuth.infrastructure.http import HttpClientSettings
from gqlsleuth.infrastructure.probe_evidence import (
    contains_request_material,
    request_context_material,
)
from gqlsleuth.infrastructure.websocket import (
    WebSocketClient,
    WebSocketFailure,
    validate_websocket_settings,
)
from gqlsleuth.rules.security_review import review_schema


def prepare_subscriptions(
    safe: SafeExecutionScanResult, *, enabled: bool = False
) -> SubscriptionSecurityResult:
    scan = safe.query_generation.operation_analysis.schema_scan
    if enabled is not True or scan.introspection.detection.discovery.mode is not ScanMode.ACTIVE:
        return SubscriptionSecurityResult(
            limitations=("Subscription review requires explicit enablement and ACTIVE mode.",)
        )
    review = safe.query_generation.security_review
    candidates = []
    limitations = []
    for source in review.candidates if review else ():
        if source.candidate_type is not SecurityCandidateType.SUBSCRIPTION_SURFACE:
            continue
        try:
            schema, native = _retained(safe, source.endpoint)
            references = tuple(
                e.evidence_id
                for e in safe.evidence
                if e.endpoint == source.endpoint and e.evidence_type is EvidenceType.SCHEMA_ARTIFACT
            )
            if (
                not references
                or source
                not in review_schema(
                    source.endpoint, schema, source_evidence_ids=references
                ).candidates
            ):
                raise HttpConfigurationError("Subscription source provenance is inconsistent.")
            root = schema.type_named(schema.subscription_root) if schema.subscription_root else None
            if root is None:
                continue
            for field in root.fields:
                candidate = SubscriptionCandidate(source.endpoint, root.name, field, source)
                try:
                    query, variables, notes, _ = generate_subscription(schema, field)
                    candidate = replace(
                        candidate, query=query, variables=variables, manual_adjustments=notes
                    )
                    validate_subscription(schema, native, candidate)
                except (GQLSleuthError, GraphQLError):
                    candidate = replace(
                        candidate, failure="Subscription generation/schema validation failed."
                    )
                candidates.append(candidate)
        except (GQLSleuthError, GraphQLError):
            limitations.append(
                "A retained Subscription schema/source is unavailable or inconsistent."
            )
    return SubscriptionSecurityResult(tuple(candidates), limitations=tuple(limitations))


def _retained(safe: SafeExecutionScanResult, endpoint: str) -> tuple[ParsedSchema, GraphQLSchema]:
    scan = safe.query_generation.operation_analysis.schema_scan
    schemas = tuple(
        s.schema
        for s in scan.schemas
        if s.endpoint == endpoint and s.success and s.schema is not None
    )
    responses = tuple(
        i.full_response
        for i in scan.introspection.introspections
        if i.endpoint == endpoint and i.full_response is not None
    )
    if (
        len(schemas) != 1
        or len(responses) != 1
        or parse_introspection_response(responses[0].body) != schemas[0]
    ):
        raise HttpConfigurationError("Retained Subscription schema is unavailable or inconsistent.")
    return schemas[0], load_introspection_schema(responses[0].body)


def _private_values(value: JsonValue) -> tuple[str, ...]:
    pending = [value]
    parts: list[str] = []
    while pending:
        child = pending.pop()
        if isinstance(child, dict):
            pending.extend(reversed(tuple(child.values())))
        elif isinstance(child, list):
            pending.extend(reversed(child))
        elif isinstance(child, str):
            parts.extend(part for part in (child, *child.split()) if part)
        else:
            parts.append(json.dumps(child))
    return tuple(parts)


class SubscriptionSecuritySession:
    """Private init material/settings never enter previews, reports or evidence."""

    def __init__(
        self,
        safe: SafeExecutionScanResult,
        *,
        enabled: bool = False,
        deny: bool = False,
        overrides: dict[str, JsonValue] | None = None,
        init_payload: dict[str, JsonValue] | None = None,
        ws_url: str | None = None,
        http_settings: HttpClientSettings | None = None,
    ) -> None:
        self._safe, self._enabled, self._deny = safe, enabled, deny
        self._overrides = self._object(overrides)
        self._init = self._object(init_payload)
        self._init_snapshot = exact_variables(self._init)
        self._url = ws_url
        self._settings = http_settings or HttpClientSettings()
        self._settings_snapshot = self._settings.model_dump_json()
        self._index: int | None = None
        self._preview = prepare_subscriptions(safe, enabled=enabled)
        self._result = self._preview
        self._finished = False
        self._connections = 0

    @staticmethod
    def _object(value: dict[str, JsonValue] | None) -> dict[str, JsonValue] | None:
        if value is None:
            return None
        try:
            return parse_subscription_object(
                [json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)]
            )
        except (ValueError, TypeError, RecursionError):
            raise HttpConfigurationError("Invalid bounded Subscription JSON input.") from None

    @property
    def preview(self) -> SubscriptionSecurityResult:
        return deepcopy(self._preview)

    def _prepare_selected(self) -> SubscriptionSecurityResult:
        result = prepare_subscriptions(self._safe, enabled=self._enabled)
        if self._index is None or not 1 <= self._index <= len(result.candidates):
            raise HttpConfigurationError("Select one retained Subscription index.")
        candidate = result.candidates[self._index - 1]
        schema, native = _retained(self._safe, candidate.endpoint)
        variables = validate_subscription(schema, native, candidate, self._overrides)
        validate_websocket_settings(self._settings)
        if type(self._deny) is not bool:
            raise HttpConfigurationError("Subscription DENY policy must be explicit Boolean state.")
        return replace(
            result,
            plan=SubscriptionPlan(
                candidate,
                websocket_url(candidate.endpoint, self._url),
                variables,
                SubscriptionPolicy.DENY if self._deny else SubscriptionPolicy.OBSERVE,
                bool(self._settings.custom_headers),
                self._init is not None,
                len(json.dumps(self._init, separators=(",", ":"), ensure_ascii=False).encode())
                if self._init is not None
                else 0,
            ),
        )

    def select(self, index: int) -> SubscriptionSecurityResult:
        if self._finished or type(index) is not int:
            raise HttpConfigurationError("Select one unused Subscription index.")
        self._index = index
        self._preview = self._prepare_selected()
        return self.preview

    def _valid(self, preview: SubscriptionSecurityResult) -> bool:
        try:
            fresh = self._prepare_selected()
            return (
                type(preview) is SubscriptionSecurityResult
                and preview == fresh
                and self._preview == fresh
                and type(preview.confirmed) is bool
                and preview.plan is not None
                and fresh.plan is not None
                and exact_variables(preview.plan.variables) == exact_variables(fresh.plan.variables)
                and exact_variables(self._init) == self._init_snapshot
                and self._settings.model_dump_json() == self._settings_snapshot
            )
        except (GQLSleuthError, GraphQLError, ValueError, TypeError, RecursionError):
            return False

    def execute(
        self, *, preview: SubscriptionSecurityResult, confirmed: bool = False
    ) -> SubscriptionSecurityResult:
        if self._finished:
            return deepcopy(self._result)
        self._finished = True
        self._result = replace(self._preview, confirmed=confirmed is True)
        if confirmed is not True or self._preview.plan is None:
            return deepcopy(self._result)
        if self._connections or not self._valid(preview):
            self._result = replace(
                self._result,
                limitations=(
                    "Subscription plan, private context or retained source changed; "
                    "no connection opened.",
                ),
            )
            return deepcopy(self._result)
        self._connections += 1
        evidence = self._exchange(preview)
        findings: tuple[SubscriptionFinding, ...] = ()
        plan = self._preview.plan
        if evidence.evaluation is PolicyStatus.VIOLATED and evidence.negotiated_protocol:
            supplied = plan.handshake_headers_supplied or plan.init_payload_supplied
            findings = (
                SubscriptionFinding(
                    plan.candidate.endpoint,
                    plan.candidate.field.name,
                    evidence.negotiated_protocol,
                    supplied,
                    evidence.evidence_id,
                    plan.candidate.source.source_evidence_ids,
                    "The selected Subscription returned application event data "
                    + (
                        "under the current supplied request context"
                        if supplied
                        else "without supplied authentication material"
                    )
                    + ", contrary to the operator-supplied DENY expectation.",
                ),
            )
        self._result = replace(self._result, attempts=(evidence,), findings=findings)
        return deepcopy(self._result)

    def _exchange(self, preview: SubscriptionSecurityResult) -> SubscriptionEvidence:
        plan = self._preview.plan
        assert plan is not None and plan.candidate.query is not None
        timestamp, started = datetime.now(UTC), monotonic()
        connected = acknowledged = sent = withheld = False
        frames = events = 0
        protocol = None
        code = status = None
        body = None
        outcome = SubscriptionOutcome.INDETERMINATE
        limitation = "No supported terminal event was observed."
        material = (
            *request_context_material(self._settings),
            *(_private_values(self._init) if self._init is not None else ()),
        )
        try:
            with WebSocketClient(plan.ws_url, self._settings) as socket:
                connected, status = True, 101
                try:
                    if socket.protocol not in tuple(SubscriptionProtocol):
                        limitation = (
                            "Server did not negotiate a supported GraphQL WebSocket protocol."
                        )
                    else:
                        protocol = SubscriptionProtocol(socket.protocol)
                        init: dict[str, JsonValue] = {"type": "connection_init"}
                        if self._init is not None:
                            init["payload"] = deepcopy(self._init)
                        socket.send(json.dumps(init))
                        deadline = monotonic() + min(
                            ACK_TIMEOUT_SECONDS, self._settings.timeout_seconds
                        )
                        for _ in range(MAX_PHASE30_INBOUND_FRAMES):
                            remaining = deadline - monotonic()
                            if remaining <= 0:
                                raise TimeoutError
                            raw = socket.receive(remaining)
                            frames += 1
                            if (
                                isinstance(raw, bytes)
                                or len(raw.encode("utf-8")) > MAX_PHASE30_FRAME_BYTES
                            ):
                                limitation = (
                                    "Unsupported binary or oversized GraphQL WebSocket message."
                                )
                                break
                            try:
                                message = decode_subscription_object(raw)
                            except (ValueError, UnicodeError, RecursionError):
                                limitation = "Malformed GraphQL WebSocket JSON."
                                break
                            if not isinstance(message, dict) or not isinstance(
                                message.get("type"), str
                            ):
                                limitation = "Malformed GraphQL WebSocket message."
                                break
                            kind = message["type"]
                            if kind in ("ping", "pong") and protocol is SubscriptionProtocol.MODERN:
                                if set(message) - {"type", "payload"} or (
                                    "payload" in message
                                    and not isinstance(message["payload"], dict)
                                ):
                                    break
                                if kind == "ping":
                                    socket.send('{"type":"pong"}')
                                continue
                            if (
                                kind == "ka"
                                and protocol is SubscriptionProtocol.LEGACY
                                and set(message) == {"type"}
                            ):
                                continue
                            if kind == "connection_ack" and not acknowledged:
                                if set(message) - {"type", "payload"} or (
                                    "payload" in message
                                    and not isinstance(message["payload"], dict)
                                ):
                                    break
                                acknowledged = True
                                if not self._valid(preview):
                                    limitation = (
                                        "Canonical Subscription/context changed; no start sent."
                                    )
                                    break
                                socket.send(
                                    json.dumps(
                                        {
                                            "id": "1",
                                            "type": "subscribe"
                                            if protocol is SubscriptionProtocol.MODERN
                                            else "start",
                                            "payload": {
                                                "query": plan.candidate.query,
                                                "variables": plan.variables,
                                            },
                                        }
                                    )
                                )
                                sent = True
                                deadline = monotonic() + min(
                                    EVENT_TIMEOUT_SECONDS, self._settings.timeout_seconds
                                )
                                continue
                            # Keep one terminal frame, never init/ACK.
                            withheld = contains_request_material(raw, material)
                            body = None if withheld else raw.encode("utf-8")
                            if (
                                kind == "connection_error"
                                and protocol is SubscriptionProtocol.LEGACY
                                and not acknowledged
                            ):
                                error = message.get("payload")
                                if explicit_authorization_error(
                                    error, (plan.candidate.field.name,)
                                ):
                                    outcome = SubscriptionOutcome.EXPLICIT_DENIAL
                                break
                            if (
                                not sent
                                or message.get("id") != "1"
                                or set(message) - {"id", "type", "payload"}
                            ):
                                limitation = (
                                    "Unexpected GraphQL WebSocket frame ordering or operation ID."
                                )
                                break
                            if kind == "complete" and "payload" not in message:
                                limitation = "Subscription completed before an application event."
                                break
                            if kind == "error":
                                payload = message.get("payload")
                                errors = payload if isinstance(payload, list) else [payload]
                                if errors and all(
                                    explicit_authorization_error(e, (plan.candidate.field.name,))
                                    for e in errors
                                ):
                                    outcome = SubscriptionOutcome.EXPLICIT_DENIAL
                                break
                            if kind == (
                                "next" if protocol is SubscriptionProtocol.MODERN else "data"
                            ):
                                events = 1
                                outcome = classify_subscription_payload(
                                    message.get("payload"), plan.candidate.field.name
                                )
                                limitation = (
                                    ""
                                    if outcome is SubscriptionOutcome.EVENT_RETURNED
                                    else "First event did not establish non-null access."
                                )
                                break
                            limitation = "Unsupported GraphQL WebSocket message."
                            break
                        else:
                            limitation = "Inbound frame budget reached."
                except TimeoutError:
                    outcome = (
                        SubscriptionOutcome.NO_EVENT_BEFORE_TIMEOUT
                        if sent
                        else SubscriptionOutcome.INDETERMINATE
                    )
                    limitation = (
                        "No event during the bounded wait; denial is not established."
                        if sent
                        else "Connection acknowledgement timed out."
                    )
                finally:
                    frames = max(frames, socket.frame_count)
                    code = socket.close_code
                    if frames > MAX_PHASE30_INBOUND_FRAMES:
                        outcome = SubscriptionOutcome.INDETERMINATE
                        limitation = "Inbound frame budget reached."
                    if sent:
                        try:
                            socket.send(
                                json.dumps(
                                    {
                                        "id": "1",
                                        "type": "complete"
                                        if protocol is SubscriptionProtocol.MODERN
                                        else "stop",
                                    }
                                )
                            )
                            if protocol is SubscriptionProtocol.LEGACY:
                                socket.send('{"type":"connection_terminate"}')
                        except WebSocketFailure:
                            pass  # Cleanup must not replace an already observed terminal outcome.
        except WebSocketFailure as error:
            code, status = error.code or code, error.status or status
            outcome = (
                SubscriptionOutcome.EXPLICIT_DENIAL
                if error.status in (401, 403)
                or (protocol is SubscriptionProtocol.MODERN and code in (4401, 4403))
                else SubscriptionOutcome.NETWORK_FAILURE
                if error.network
                else SubscriptionOutcome.INDETERMINATE
            )
            limitation = "WebSocket transport or protocol ended before event classification."
            if frames > MAX_PHASE30_INBOUND_FRAMES:
                outcome = SubscriptionOutcome.INDETERMINATE
                limitation = "Inbound frame budget reached."
        evaluation = None
        if plan.policy is SubscriptionPolicy.DENY:
            evaluation = (
                PolicyStatus.VIOLATED
                if outcome is SubscriptionOutcome.EVENT_RETURNED
                else PolicyStatus.SATISFIED
                if outcome is SubscriptionOutcome.EXPLICIT_DENIAL
                else PolicyStatus.UNRESOLVED
            )
        scan = self._safe.query_generation.operation_analysis.schema_scan
        return SubscriptionEvidence(
            target=scan.introspection.detection.discovery.target,
            endpoint=plan.candidate.endpoint,
            source="gqlsleuth.application.subscriptions",
            timestamp=timestamp,
            summary=f"Subscription {plan.candidate.field.name}: {outcome.value}.",
            plan=deepcopy(plan),
            source_evidence_ids=plan.candidate.source.source_evidence_ids,
            query=plan.candidate.query,
            variables=deepcopy(plan.variables),
            request_method="GET",
            response_status_code=status,
            response_body=body,
            duration_seconds=monotonic() - started,
            negotiated_protocol=protocol,
            connected=connected,
            acknowledged=acknowledged,
            subscription_sent=sent,
            inbound_frame_count=frames,
            application_event_count=events,
            close_code=code,
            outcome=outcome,
            evaluation=evaluation,
            response_material_withheld=withheld,
            limitation=limitation,
            error_type="WebSocketFailure"
            if outcome is SubscriptionOutcome.NETWORK_FAILURE
            else None,
            error_message="WebSocket transport failed."
            if outcome is SubscriptionOutcome.NETWORK_FAILURE
            else None,
        )
