"""Bounded ACTIVE seed plans and observations; no inferred ownership or authorization policy."""

import re
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.object_authorization import ObjectOutcome
from gqlsleuth.domain.security_review import GraphQLSecurityReviewCandidate

MAX_PHASE22_SEEDS = 2
MAX_PHASE22_NEIGHBORS_PER_SEED = 2
MAX_PHASE22_REQUESTS = 6
MAX_PHASE22_IDENTIFIER = 2**63 - 1
PHASE22_OFFSETS = (-1, 1)
SEQUENTIAL_NOTICE = (
    "Adjacent numeric identifiers are derived only from the operator-supplied seed. "
    "Returned objects are review candidates, not BOLA/IDOR or vulnerability confirmation. "
    "Ownership and intended policy remain unknown. Any Phase 20/21 follow-up must be "
    "explicitly supplied in a separate scan. No further expansion is performed."
)


@dataclass(frozen=True)
class SequentialDiscoverySeed:
    operation: str
    argument: str
    identifier: str
    index: int


def parse_discovery_seeds(entries: list[str]) -> tuple[SequentialDiscoverySeed, ...]:
    """Accept exact canonical decimals only; validation errors never echo supplied values."""
    if not entries:
        raise HttpConfigurationError("--idor-discovery requires --idor-seed.")
    if len(entries) > MAX_PHASE22_SEEDS:
        raise HttpConfigurationError("At most two idor-seeds are allowed.")
    seeds = []
    for index, entry in enumerate(entries, 1):
        if type(entry) is not str:
            raise HttpConfigurationError(f"idor-seed #{index}: expected textual seed syntax.")
        left, separator, value = entry.partition("=")
        names = left.split(":")
        # ASCII decimal syntax also excludes whitespace, controls and unsafe Unicode.
        valid = (
            bool(separator)
            and len(names) == 2
            and all(re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", name) for name in names)
            and len(value) <= 19
            and re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is not None
        )
        if not valid or int(value) > MAX_PHASE22_IDENTIFIER:
            raise HttpConfigurationError(
                f"idor-seed #{index}: requires OPERATION:ARGUMENT and a canonical unsigned "
                "decimal identifier in the supported 64-bit signed range."
            )
        seeds.append(SequentialDiscoverySeed(names[0], names[1], value, index))
    return tuple(seeds)


@dataclass(frozen=True)
class SequentialDiscoveryProbe:
    seed: SequentialDiscoverySeed
    endpoint: str
    requested_identifier: str
    offset: int
    query: str
    variables: dict[str, JsonValue]
    response_id_path: tuple[str, str]
    structural_source: GraphQLSecurityReviewCandidate
    source_evidence_ids: tuple[UUID, ...]


class SequentialDiscoveryEvidence(Evidence):
    evidence_type: Literal[EvidenceType.SEQUENTIAL_OBJECT_PROBE] = (
        EvidenceType.SEQUENTIAL_OBJECT_PROBE
    )
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    root_operation: str
    identifier_argument: str
    operator_seed: str
    requested_identifier: str
    offset: Literal[-1, 0, 1]
    has_supplied_context_headers: bool
    source_evidence_ids: tuple[UUID, ...]
    outcome: ObjectOutcome
    returned_id_matches: bool | None


@dataclass(frozen=True)
class SequentialDiscoveryExecution:
    probe: SequentialDiscoveryProbe
    attempted: bool
    outcome: ObjectOutcome | None
    returned_id_matches: bool | None
    reason: str
    evidence: SequentialDiscoveryEvidence | None = None


@dataclass(frozen=True)
class SequentialDiscoveryCandidate:
    seed: SequentialDiscoverySeed
    generated_identifier: str
    offset: int
    has_supplied_context_headers: bool
    source_evidence_ids: tuple[UUID, ...]
    reason: str
    kind: Literal["adjacent_object_access"] = "adjacent_object_access"


@dataclass(frozen=True)
class SequentialDiscoveryResult:
    seeds: tuple[SequentialDiscoverySeed, ...]
    probes: tuple[SequentialDiscoveryProbe, ...] = ()
    has_supplied_context_headers: bool = False
    confirmed: bool = False
    executions: tuple[SequentialDiscoveryExecution, ...] = ()
    candidates: tuple[SequentialDiscoveryCandidate, ...] = ()
    limitations: tuple[str, ...] = ()
    attempted_request_count: int = 0
    offsets: tuple[int, int] = PHASE22_OFFSETS

    @property
    def evidence(self) -> tuple[SequentialDiscoveryEvidence, ...]:
        return tuple(item.evidence for item in self.executions if item.evidence is not None)
