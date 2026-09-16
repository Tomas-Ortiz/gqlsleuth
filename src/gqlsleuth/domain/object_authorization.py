"""Exact operator-supplied object cases and bounded SAFE observations."""

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from gqlsleuth.domain.differential import validate_context_names
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.security_review import GraphQLSecurityReviewCandidate

MAX_PHASE20_CASES = 3
MAX_PHASE20_CONTEXTS = 3
MAX_PHASE20_REQUESTS = 9
OBJECT_NOTICE = (
    "Only exact operator-supplied objects are tested. Access may be intended; manual validation "
    "of the application's object-level access policy is required. These are review candidates, "
    "not vulnerability findings. Context names imply no ownership or privilege hierarchy."
)


class ObjectAuthorizationMode(StrEnum):
    ANONYMOUS_ONLY = "anonymous_only"
    DIFFERENTIAL = "differential"


class ObjectOutcome(StrEnum):
    TARGET_RETURNED = "target_returned"
    EXPLICIT_DENIAL = "explicit_denial"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


class ObjectAccessKind(StrEnum):
    CROSS_CONTEXT_OBJECT_ACCESS = "cross_context_object_access"
    UNAUTHENTICATED_OBJECT_ACCESS = "unauthenticated_object_access"


@dataclass(frozen=True)
class ObjectAuthorizationCase:
    mode: ObjectAuthorizationMode
    declared_authorized_context: str | None
    operation: str
    argument: str
    identifier: str
    index: int


def parse_object_cases(
    entries: list[str], context_names: tuple[str, ...] = ()
) -> tuple[ObjectAuthorizationCase, ...]:
    """Partition before parsing labels; never echo supplied identifiers in errors."""
    if context_names:
        validate_context_names(context_names, check_count=len(context_names) != 1)
    mode = (
        ObjectAuthorizationMode.DIFFERENTIAL
        if len(context_names) > 1
        else ObjectAuthorizationMode.ANONYMOUS_ONLY
    )
    result: list[ObjectAuthorizationCase] = []
    for index, entry in enumerate(entries, 1):
        left, separator, value = entry.partition("=")
        parts = left.split(":")
        valid = bool(separator and value)
        try:
            valid &= len(value.encode("utf-8")) <= 256
        except UnicodeEncodeError:
            valid = False
        valid &= not any(unicodedata.category(char).startswith("C") for char in value)
        owner = parts[0] if len(parts) == 3 else None
        valid &= len(parts) in {2, 3}
        valid &= all(re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", name) for name in parts[-2:])
        if mode is ObjectAuthorizationMode.DIFFERENTIAL:
            valid &= owner in context_names
        elif owner is not None:
            valid &= len(context_names) == 1 and owner == context_names[0]
        if not valid:
            raise HttpConfigurationError(
                f"object-auth-case #{index}: invalid case syntax, context or identifier."
            )
        case = ObjectAuthorizationCase(
            mode,
            owner if mode is ObjectAuthorizationMode.DIFFERENTIAL else None,
            parts[-2],
            parts[-1],
            value,
            len(result) + 1,
        )
        if any(
            (item.declared_authorized_context, item.operation, item.argument, item.identifier)
            == (case.declared_authorized_context, case.operation, case.argument, case.identifier)
            for item in result
        ):
            continue
        result.append(case)
        if len(result) > MAX_PHASE20_CASES:
            raise HttpConfigurationError("At most three unique object-auth cases are allowed.")
    if not result:
        raise HttpConfigurationError("--object-auth-review requires --object-auth-case.")
    return tuple(result)


@dataclass(frozen=True)
class ObjectContext:
    name: str
    has_supplied_context_headers: bool


@dataclass(frozen=True)
class PreparedObjectProbe:
    case: ObjectAuthorizationCase
    endpoint: str
    query: str
    variables: dict[str, JsonValue]
    response_id_path: tuple[str, str]
    contexts: tuple[ObjectContext, ...]
    structural_source: GraphQLSecurityReviewCandidate
    source_evidence_ids: tuple[UUID, ...]


class ObjectAuthorizationEvidence(Evidence):
    evidence_type: Literal[EvidenceType.OBJECT_AUTHORIZATION_PROBE] = (
        EvidenceType.OBJECT_AUTHORIZATION_PROBE
    )
    execution_mode: Literal[ScanMode.SAFE] = ScanMode.SAFE
    object_mode: ObjectAuthorizationMode
    context: str
    has_supplied_context_headers: bool
    declared_authorized_context: str | None
    root_operation: str
    identifier_argument: str
    identifier: str
    source_evidence_ids: tuple[UUID, ...]
    outcome: ObjectOutcome
    returned_id_matches: bool | None


@dataclass(frozen=True)
class ObjectExecution:
    case_index: int
    context: ObjectContext
    attempted: bool
    outcome: ObjectOutcome | None
    returned_id_matches: bool | None
    reason: str
    evidence: ObjectAuthorizationEvidence | None = None


@dataclass(frozen=True)
class ObjectAccessCandidate:
    kind: ObjectAccessKind
    case: ObjectAuthorizationCase
    observed_context: str
    source_evidence_ids: tuple[UUID, ...]
    reason: str


@dataclass(frozen=True)
class ObjectAuthorizationResult:
    mode: ObjectAuthorizationMode
    cases: tuple[ObjectAuthorizationCase, ...]
    probes: tuple[PreparedObjectProbe, ...] = ()
    executions: tuple[ObjectExecution, ...] = ()
    candidates: tuple[ObjectAccessCandidate, ...] = ()
    limitations: tuple[str, ...] = ()
    attempted_request_count: int = 0

    @property
    def evidence(self) -> tuple[ObjectAuthorizationEvidence, ...]:
        return tuple(item.evidence for item in self.executions if item.evidence is not None)
