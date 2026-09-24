"""One operator-owned upload baseline and three fixed benign validation variants."""

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import JsonValue

from gqlsleuth.domain.analysis import OperationAnalysis
from gqlsleuth.domain.authorization_policy import PolicyProvenance, PolicyStatus
from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.models import Evidence, EvidenceType, ScanMode

MAX_PHASE28_CASES = 1
MAX_UPLOAD_INPUT_DEPTH = 3
MAX_PHASE28_FILE_BYTES = 1024 * 1024
MAX_PHASE28_REQUESTS = 4
UPLOAD_LIMITATION = (
    "Acceptance means a non-null successful Mutation response only. Persistence, retrieval, "
    "rendering and execution were not verified. DENY policies are operator supplied; "
    "application-specific file acceptance rules were not independently inferred."
)
UPLOAD_WARNING = (
    "These Mutation requests may create files, attachments, records, emails, processing jobs "
    "or other application-side effects. GQLSleuth does not delete or roll back uploaded data."
)


class UploadExpectedPolicy(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class UploadProbe(StrEnum):
    BASELINE = "baseline"
    CONTENT_MISMATCH = "content_mismatch"
    MIME_MISMATCH = "mime_mismatch"
    EXTENSION_MISMATCH = "extension_mismatch"


UPLOAD_VARIANTS = tuple(probe for probe in UploadProbe if probe is not UploadProbe.BASELINE)


class UploadOutcome(StrEnum):
    UPLOAD_ACCEPTED = "upload_accepted"
    EXPLICIT_FILE_REJECTION = "explicit_file_rejection"
    INDETERMINATE = "indeterminate"
    NETWORK_FAILURE = "network_failure"


class UploadBaselineStatus(StrEnum):
    NOT_EXECUTED = "not_executed"
    BASELINE_CONFIRMED = "baseline_confirmed"
    BASELINE_UNUSABLE = "baseline_unusable"


@dataclass(frozen=True)
class FileUploadCase:
    operation: str
    path: tuple[str, ...]


def parse_upload_case(values: list[str]) -> FileUploadCase:
    if len(values) != MAX_PHASE28_CASES or not re.fullmatch(
        r"[_A-Za-z][_0-9A-Za-z]*:[_A-Za-z][_0-9A-Za-z]*(?:\.[_A-Za-z][_0-9A-Za-z]*){0,3}",
        values[0],
    ):
        raise HttpConfigurationError(
            "Supply one --upload-case OPERATION:ARGUMENT[.FIELD...], with at most three fields."
        )
    operation, path = values[0].split(":")
    return FileUploadCase(operation, tuple(path.split(".")))


@dataclass(frozen=True)
class UploadFileMetadata:
    filename: str
    size: int
    sha256: str
    content_type: str


@dataclass(frozen=True)
class UploadPlan:
    case: FileUploadCase
    operation: OperationAnalysis
    query: str
    variables: dict[str, JsonValue]
    variable_path: str
    multipart_map: dict[str, list[str]]
    source_evidence_ids: tuple[UUID, ...]
    baseline: UploadFileMetadata
    manual_adjustments: tuple[str, ...] = ()

    @property
    def operations(self) -> dict[str, JsonValue]:
        return {"query": self.query, "variables": self.variables}


class UploadEvidence(Evidence):
    evidence_type: Literal[EvidenceType.FILE_UPLOAD_PROBE] = EvidenceType.FILE_UPLOAD_PROBE
    execution_mode: Literal[ScanMode.ACTIVE] = ScanMode.ACTIVE
    case: FileUploadCase
    probe: UploadProbe
    expected: UploadExpectedPolicy
    file: UploadFileMetadata
    operations: dict[str, JsonValue]
    multipart_map: dict[str, list[str]]
    variable_path: str
    source_evidence_ids: tuple[UUID, ...]
    outcome: UploadOutcome
    evaluation: PolicyStatus | UploadBaselineStatus
    response_material_withheld: bool = False


@dataclass(frozen=True)
class UploadFinding:
    case: FileUploadCase
    operation: OperationAnalysis
    probe: UploadProbe
    baseline_evidence_id: UUID
    variant_evidence_id: UUID
    reason: str
    finding_type: Literal["file_upload_validation_policy_violation"] = (
        "file_upload_validation_policy_violation"
    )
    expected: UploadExpectedPolicy = UploadExpectedPolicy.DENY
    observed: UploadOutcome = UploadOutcome.UPLOAD_ACCEPTED
    evaluation: PolicyStatus = PolicyStatus.VIOLATED
    provenance: PolicyProvenance = PolicyProvenance.OPERATOR_SUPPLIED
    limitation: str = UPLOAD_LIMITATION


@dataclass(frozen=True)
class FileUploadSecurityResult:
    case: FileUploadCase
    plan: UploadPlan | None = None
    selected_variants: tuple[UploadProbe, ...] = ()
    confirmed: bool = False
    attempts: tuple[UploadEvidence, ...] = ()
    baseline_status: UploadBaselineStatus = UploadBaselineStatus.NOT_EXECUTED
    findings: tuple[UploadFinding, ...] = ()
    limitations: tuple[str, ...] = ()
    planned_request_count: int = field(init=False)
    attempted_request_count: int = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "planned_request_count", 1 + len(self.selected_variants) if self.plan else 0
        )
        object.__setattr__(self, "attempted_request_count", len(self.attempts))

    @property
    def evidence(self) -> tuple[UploadEvidence, ...]:
        return self.attempts
