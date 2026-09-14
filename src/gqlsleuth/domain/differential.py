"""Named request contexts and local observations, never authorization findings."""

import re
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID

from gqlsleuth.domain.analysis import OperationKind
from gqlsleuth.domain.exceptions import HttpConfigurationError


@dataclass(frozen=True)
class NamedAuthContext:
    """An opaque, case-sensitive tester label; headers are configuration, not results."""

    name: str
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        validate_context_names((self.name,), check_count=False)


def validate_context_names(names: tuple[str, ...], *, check_count: bool = True) -> None:
    if any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) is None for name in names):
        raise HttpConfigurationError(
            "Context names must be 1–64 ASCII letters, digits, dots, underscores, or hyphens, "
            "starting with a letter or digit."
        )
    if len(set(names)) != len(names) or (check_count and not 2 <= len(names) <= 3):
        raise HttpConfigurationError("Differential scans require 2–3 unique context names.")


class DifferenceKind(StrEnum):
    ENDPOINT_ACCESS_DIFFERENCE = "endpoint_access_difference"
    INTROSPECTION_DIFFERENCE = "introspection_difference"
    OPERATION_VISIBILITY_DIFFERENCE = "operation_visibility_difference"
    EXECUTION_OUTCOME_DIFFERENCE = "execution_outcome_difference"


@dataclass(frozen=True)
class ContextObservation:
    """A normalized observed state and links into the corresponding context's evidence."""

    state: str
    http_status: int | None = None
    attempted: bool | None = None
    evidence_ids: tuple[UUID, ...] = ()


@dataclass(frozen=True)
class DifferentialReviewCandidate:
    kind: DifferenceKind
    endpoint: str
    left: ContextObservation
    right: ContextObservation
    operation_kind: OperationKind | None = None
    operation_name: str | None = None


@dataclass(frozen=True)
class ComparisonLimitation:
    endpoint: str | None
    stage: str
    reason: str


@dataclass(frozen=True)
class ContextPairReview:
    context_a: str
    context_b: str
    candidates: tuple[DifferentialReviewCandidate, ...]
    limitations: tuple[ComparisonLimitation, ...]


DIFFERENTIAL_NOTICE = (
    "Differences are authorization review candidates, not vulnerabilities. "
    "Context names are tester-defined labels with no inferred privilege order. "
    "Legitimate application behavior may differ; manual validation is required. "
    "GRAPHQL_ERROR is an observed outcome, not proof of an authorization weakness; "
    "placeholders, business input, validation, or other server logic may account for it."
)
