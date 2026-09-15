"""Derived structural review results, separate from HTTP evidence and Phase 7 scores."""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from gqlsleuth.domain.analysis import OperationAnalysis

SECURITY_REVIEW_NOTICE = (
    "These are schema-derived structural review candidates, not confirmed vulnerabilities. "
    "Manual validation is required. Absence of an obvious schema control does not prove "
    "absence of a runtime control. This analysis adds no requests or operations."
)


class SecurityCandidateType(StrEnum):
    FILE_UPLOAD_SURFACE = "file_upload_surface"
    FEDERATION_SURFACE = "federation_surface"
    SUBSCRIPTION_SURFACE = "subscription_surface"
    OBJECT_LOOKUP_REVIEW = "object_lookup_review"
    LIST_BOUNDING_REVIEW = "list_bounding_review"
    RECURSIVE_GRAPH_REVIEW = "recursive_graph_review"
    FLEXIBLE_SCALAR_INPUT_REVIEW = "flexible_scalar_input_review"
    COMPLEX_INPUT_REVIEW = "complex_input_review"
    DEPRECATED_SECURITY_RELEVANT_OPERATION = "deprecated_security_relevant_operation"


@dataclass(frozen=True)
class GraphQLSecurityReviewCandidate:
    candidate_type: SecurityCandidateType
    endpoint: str
    subject: str
    deterministic_reason: str
    supporting_facts: tuple[str, ...]
    review_guidance: str
    related_operation: OperationAnalysis | None = None
    source_evidence_ids: tuple[UUID, ...] = ()


@dataclass(frozen=True)
class SecurityReviewLimitation:
    endpoint: str
    reason: str


@dataclass(frozen=True)
class GraphQLSecurityReviewResult:
    candidates: tuple[GraphQLSecurityReviewCandidate, ...] = ()
    limitations: tuple[SecurityReviewLimitation, ...] = ()
    analyzed_endpoints: tuple[str, ...] = ()
