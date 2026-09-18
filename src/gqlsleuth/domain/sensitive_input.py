"""Schema-only input review and exact operator-supplied field/value DENY cases."""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from gqlsleuth.domain.authorization_policy import ExpectedPolicy, PolicyStatus
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode
from gqlsleuth.domain.object_authorization import parse_object_cases

MAX_PHASE24_CASES = 1
MAX_PHASE24_REQUESTS = 1
SENSITIVE_REVIEW_NOTICE = (
    "Schema names are review hints, not findings. Review server-side field authorization. "
    "GQLSleuth does not choose the sensitive value automatically."
)
SENSITIVE_VALIDATION_NOTICE = (
    "The operator asserts DENY for this exact field/value in the current request context. "
    "Response matching does not prove persistence. Persistence and broader business impact "
    "were not verified; manual validation is required."
)


class SensitiveInputCategory(StrEnum):
    PRIVILEGE_CONTROL = "privilege_control"
    OWNERSHIP_CONTROL = "ownership_control"
    TENANCY_CONTROL = "tenancy_control"
    TRUST_STATE = "trust_state"


@dataclass(frozen=True)
class SensitiveInputCandidate:
    endpoint: str
    operation: str
    argument: str
    field: str
    input_type: str
    category: SensitiveInputCategory
    reason: str
    supporting_facts: tuple[str, ...]
    case_template: str | None = None
    target_template: str | None = None
    kind: Literal["sensitive_input_review"] = "sensitive_input_review"


@dataclass(frozen=True)
class SensitiveInputTarget:
    argument: str
    identifier: str


@dataclass(frozen=True)
class SensitiveInputCase:
    operation: str
    argument: str
    field: str
    value: str
    target: SensitiveInputTarget | None = None
    expected: ExpectedPolicy = ExpectedPolicy.DENY


def parse_sensitive_case(entries: list[str], target: str | None = None) -> SensitiveInputCase:
    """Reuse object-ID text bounds/controls; values are typed only against retained schema."""
    if len(entries) != MAX_PHASE24_CASES or type(entries[0]) is not str:
        raise HttpConfigurationError(
            "Sensitive input validation requires exactly one --sensitive-input-case."
        )
    left, separator, value = entries[0].partition("=")
    match = re.fullmatch(
        r"([_A-Za-z][_0-9A-Za-z]*):([_A-Za-z][_0-9A-Za-z]*)\.([_A-Za-z][_0-9A-Za-z]*)", left
    )
    try:
        if not match or not separator:
            raise HttpConfigurationError("Invalid path.")
        operation, argument, field = match.groups()
        parse_object_cases([f"{operation}:{field}={value}"])
        supplied_target = None
        if target is not None:
            if type(target) is not str:
                raise HttpConfigurationError("Invalid target.")
            parsed = parse_object_cases([f"{operation}:{target}"])[0]
            supplied_target = SensitiveInputTarget(parsed.argument, parsed.identifier)
        return SensitiveInputCase(operation, argument, field, value, supplied_target)
    except HttpConfigurationError:
        raise HttpConfigurationError(
            "Invalid sensitive input case/target. Use OPERATION:ARGUMENT.FIELD=VALUE and "
            "optional ARGUMENT=ID; values must be non-empty, control-free "
            "and at most 256 UTF-8 bytes."
        ) from None


class SensitiveInputOutcome(StrEnum):
    TARGET_VALUE_RETURNED = "target_value_returned"
    EXPLICIT_DENIAL = "explicit_denial"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


@dataclass(frozen=True)
class PreparedSensitiveInputProbe:
    case: SensitiveInputCase
    endpoint: str
    query: str
    variables: dict[str, JsonValue]
    typed_value: JsonValue
    value_type: str
    source_evidence_ids: tuple[UUID, ...]
    manual_adjustments: tuple[str, ...] = ()
    provenance: Literal["detected_sensitive_input"] = "detected_sensitive_input"


class SensitiveInputEvidence(Evidence):
    evidence_type: Literal[EvidenceType.SENSITIVE_INPUT_PROBE] = EvidenceType.SENSITIVE_INPUT_PROBE
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    root_operation: str
    input_path: str
    supplied_value: JsonValue
    target_argument: str | None
    target_identifier: str | None
    expected: Literal[ExpectedPolicy.DENY] = ExpectedPolicy.DENY
    outcome: SensitiveInputOutcome
    target_id_matches: bool | None
    value_matches: bool | None
    source_evidence_ids: tuple[UUID, ...]


@dataclass(frozen=True)
class SensitiveInputEvaluation:
    status: PolicyStatus
    observed: SensitiveInputOutcome | None
    reason: str
    source_evidence_ids: tuple[UUID, ...] = ()
    expected: ExpectedPolicy = ExpectedPolicy.DENY


@dataclass(frozen=True)
class SensitiveInputViolation:
    evaluation: SensitiveInputEvaluation
    result_type: Literal["sensitive_input_policy_violation"] = "sensitive_input_policy_violation"


@dataclass(frozen=True)
class SensitiveInputValidationResult:
    case: SensitiveInputCase
    probe: PreparedSensitiveInputProbe | None = None
    has_supplied_context_headers: bool = False
    confirmed: bool = False
    execution: SensitiveInputEvidence | None = None
    evaluation: SensitiveInputEvaluation | None = None
    violation: SensitiveInputViolation | None = None
    limitations: tuple[str, ...] = ()
    attempted_request_count: int = 0

    @property
    def evidence(self) -> tuple[SensitiveInputEvidence, ...]:
        return (self.execution,) if self.execution else ()
