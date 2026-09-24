"""Explicit, bounded federation observations and operator-supplied DENY policies."""

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from gqlsleuth.domain.authorization_policy import PolicyProvenance, PolicyStatus
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.security_review import GraphQLSecurityReviewCandidate

MAX_PHASE29_REQUESTS = 2
FEDERATION_LIMITATION = (
    "Policies are operator supplied. Service metadata may be intentionally public; privacy "
    "was not inferred. Entity results establish no ownership, tenant, role hierarchy or "
    "federation-wide security conclusion."
)


class FederationProbe(StrEnum):
    SERVICE = "service"
    ENTITY = "entity"


class FederationPolicy(StrEnum):
    OBSERVE = "observe"
    DENY = "deny"


class FederationOutcome(StrEnum):
    SDL_RETURNED = "sdl_returned"
    ENTITY_RETURNED = "entity_returned"
    EXPLICIT_DENIAL = "explicit_denial"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


def parse_entity_case(values: list[str]) -> dict[str, JsonValue] | None:
    """Accept one small flat representation without echoing invalid input."""
    if not values:
        return None

    def unique(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        if len(values) != 1 or len(values[0].encode("utf-8")) > 1024:
            raise ValueError
        case = json.loads(values[0], object_pairs_hook=unique)
        if (
            type(case) is not dict
            or not 2 <= len(case) <= 4
            or type(case.get("__typename")) is not str
            or not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", case["__typename"])
            or any(
                not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", key)
                or type(value) not in (str, int, bool)
                for key, value in case.items()
            )
        ):
            raise ValueError
        return dict(sorted(case.items()))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise HttpConfigurationError(
            "Supply one federation entity JSON object (maximum 1024 UTF-8 bytes): "
            "__typename and one to three flat string, integer or Boolean keys."
        ) from None


@dataclass(frozen=True)
class FederationPlan:
    probe: FederationProbe
    query: str
    variables: dict[str, JsonValue]
    expected: FederationPolicy
    key_types: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class FederationCandidate:
    endpoint: str
    source: GraphQLSecurityReviewCandidate
    possible_types: tuple[str, ...]
    service_available: bool
    entities_available: bool
    plans: tuple[FederationPlan, ...] = ()
    limitations: tuple[str, ...] = ()


class FederationEvidence(Evidence):
    evidence_type: Literal[EvidenceType.FEDERATION_SECURITY_PROBE] = (
        EvidenceType.FEDERATION_SECURITY_PROBE
    )
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    probe: FederationProbe
    expected: FederationPolicy
    source_candidate: GraphQLSecurityReviewCandidate
    source_evidence_ids: tuple[UUID, ...]
    outcome: FederationOutcome
    evaluation: PolicyStatus | None = None
    sdl_returned: bool = False
    sdl_bytes: int | None = None
    sdl_sha256: str | None = None
    identity_matched: bool = False
    response_material_withheld: bool = False


@dataclass(frozen=True)
class FederationFinding:
    finding_type: Literal[
        "FEDERATION_SDL_POLICY_VIOLATION", "FEDERATION_ENTITY_AUTHORIZATION_FAILURE"
    ]
    label: str
    endpoint: str
    evidence_id: UUID
    source_evidence_ids: tuple[UUID, ...]
    reason: str
    expected: FederationPolicy = FederationPolicy.DENY
    evaluation: PolicyStatus = PolicyStatus.VIOLATED
    provenance: PolicyProvenance = PolicyProvenance.OPERATOR_SUPPLIED
    limitation: str = FEDERATION_LIMITATION


@dataclass(frozen=True)
class FederationSecurityResult:
    candidates: tuple[FederationCandidate, ...] = ()
    selected_endpoint: str | None = None
    selected_probes: tuple[FederationProbe, ...] = ()
    confirmed: bool = False
    attempts: tuple[FederationEvidence, ...] = ()
    findings: tuple[FederationFinding, ...] = ()
    limitations: tuple[str, ...] = ()
    planned_request_count: int = field(init=False)
    attempted_request_count: int = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "planned_request_count", len(self.selected_probes))
        object.__setattr__(self, "attempted_request_count", len(self.attempts))

    @property
    def evidence(self) -> tuple[FederationEvidence, ...]:
        return self.attempts
