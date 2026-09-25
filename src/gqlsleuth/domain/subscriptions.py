"""Bounded Subscription observations, separate from operation interest and private auth."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from gqlsleuth.domain.authorization_policy import PolicyProvenance, PolicyStatus
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.schema import SchemaField
from gqlsleuth.domain.security_review import GraphQLSecurityReviewCandidate

MAX_PHASE30_CONNECTIONS = 1
MAX_PHASE30_SUBSCRIPTIONS = 1
MAX_PHASE30_SELECTED_SUBSCRIPTIONS = 1
MAX_PHASE30_APPLICATION_EVENTS = 1
MAX_PHASE30_INBOUND_FRAMES = 20
MAX_PHASE30_FRAME_BYTES = 1024 * 1024
ACK_TIMEOUT_SECONDS = 10.0
EVENT_TIMEOUT_SECONDS = 10.0
SUBSCRIPTION_NOTICE = (
    "The policy is operator supplied. GQLSleuth does not infer event ownership, user identity, "
    "tenancy, role hierarchy or broader Subscription policy. ACK alone is not event access. "
    "A timeout does not establish denial. GQLSleuth never triggers an application event."
)


class SubscriptionProtocol(StrEnum):
    MODERN = "graphql-transport-ws"
    LEGACY = "graphql-ws"


class SubscriptionPolicy(StrEnum):
    OBSERVE = "observe"
    DENY = "deny"


class SubscriptionOutcome(StrEnum):
    EVENT_RETURNED = "event_returned"
    EXPLICIT_DENIAL = "explicit_denial"
    NO_EVENT_BEFORE_TIMEOUT = "no_event_before_timeout"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


@dataclass(frozen=True)
class SubscriptionCandidate:
    endpoint: str
    root: str
    field: SchemaField
    source: GraphQLSecurityReviewCandidate
    query: str | None = None
    variables: dict[str, JsonValue] | None = None
    manual_adjustments: tuple[str, ...] = ()
    failure: str | None = None


@dataclass(frozen=True)
class SubscriptionPlan:
    candidate: SubscriptionCandidate
    ws_url: str
    variables: dict[str, JsonValue]
    policy: SubscriptionPolicy
    handshake_headers_supplied: bool
    init_payload_supplied: bool
    init_payload_bytes: int
    offered_protocols: tuple[SubscriptionProtocol, ...] = tuple(SubscriptionProtocol)


class SubscriptionEvidence(Evidence):
    evidence_type: Literal[EvidenceType.SUBSCRIPTION_SECURITY_PROBE] = (
        EvidenceType.SUBSCRIPTION_SECURITY_PROBE
    )
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    plan: SubscriptionPlan
    source_evidence_ids: tuple[UUID, ...]
    negotiated_protocol: SubscriptionProtocol | None = None
    connected: bool = False
    acknowledged: bool = False
    subscription_sent: bool = False
    inbound_frame_count: int = 0
    application_event_count: int = 0
    close_code: int | None = None
    outcome: SubscriptionOutcome
    evaluation: PolicyStatus | None = None
    response_material_withheld: bool = False
    limitation: str = ""


@dataclass(frozen=True)
class SubscriptionFinding:
    endpoint: str
    subscription: str
    protocol: SubscriptionProtocol
    supplied_context: bool
    evidence_id: UUID
    source_evidence_ids: tuple[UUID, ...]
    reason: str
    finding_type: Literal["SUBSCRIPTION_AUTHORIZATION_FAILURE"] = (
        "SUBSCRIPTION_AUTHORIZATION_FAILURE"
    )
    label: str = "Subscription authorization weakness"
    policy: SubscriptionPolicy = SubscriptionPolicy.DENY
    outcome: SubscriptionOutcome = SubscriptionOutcome.EVENT_RETURNED
    evaluation: PolicyStatus = PolicyStatus.VIOLATED
    provenance: PolicyProvenance = PolicyProvenance.OPERATOR_SUPPLIED
    limitation: str = SUBSCRIPTION_NOTICE


@dataclass(frozen=True)
class SubscriptionSecurityResult:
    candidates: tuple[SubscriptionCandidate, ...] = ()
    plan: SubscriptionPlan | None = None
    confirmed: bool = False
    attempts: tuple[SubscriptionEvidence, ...] = ()
    findings: tuple[SubscriptionFinding, ...] = ()
    limitations: tuple[str, ...] = ()

    @property
    def evidence(self) -> tuple[SubscriptionEvidence, ...]:
        return self.attempts
