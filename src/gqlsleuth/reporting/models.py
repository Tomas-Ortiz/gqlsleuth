"""Report-facing projections; retain facts without copying the complete scan graph."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from gqlsleuth.ai.models import AIInterpretationResult
from gqlsleuth.domain.analysis import OperationAnalysis
from gqlsleuth.domain.authorization_policy import AuthorizationPolicyResult
from gqlsleuth.domain.differential import ContextPairReview
from gqlsleuth.domain.models import ConfidenceLevel, Evidence, ScanMode, Target
from gqlsleuth.domain.multiplicity import MultiplicityValidationResult
from gqlsleuth.domain.nested_authorization import NestedAuthorizationResult
from gqlsleuth.domain.object_authorization import ObjectAuthorizationResult
from gqlsleuth.domain.query_depth import QueryDepthValidationResult
from gqlsleuth.domain.query_generation import OperationGenerationResult
from gqlsleuth.domain.schema import SchemaSummary
from gqlsleuth.domain.security_review import GraphQLSecurityReviewResult
from gqlsleuth.domain.sequential_discovery import SequentialDiscoveryResult
from gqlsleuth.infrastructure.http import HttpResponse
from gqlsleuth.presentation.object_lookup import ObjectLookupFollowUpHint


class ReportFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"


@dataclass(frozen=True)
class EndpointReport:
    endpoint: str
    confidence: ConfidenceLevel | None
    detection_reason: str | None
    get_signals: tuple[str, ...]
    post_signals: tuple[str, ...]
    introspection_status: str | None
    introspection_reason: str | None
    schema_summary: SchemaSummary | None
    analyzed_operation_count: int | None


@dataclass(frozen=True)
class ExecutionReport:
    """Recorded result plus evidence links; only evidence establishes an attempted request."""

    status: str | None
    decision: str | None
    attempted: bool
    recorded_attempted: bool
    reason: str
    response: HttpResponse | None
    error_type: str | None
    error_message: str | None
    evidence_ids: tuple[UUID, ...]


@dataclass(frozen=True)
class OperationReport:
    """Store the generated artifact once alongside its preview and execution decisions."""

    generated: OperationGenerationResult
    execution: ExecutionReport | None
    candidate_index: int | None = None
    preview_decision: str | None = None
    preview_reason: str | None = None
    selected: bool = False


@dataclass(frozen=True)
class ActiveReport:
    candidates: tuple[OperationReport, ...]
    selected_indices: tuple[int, ...]
    confirmed: bool


@dataclass(frozen=True)
class ReportIssue:
    """An existing error, limitation, or missing evidence association; never a finding."""

    stage: str
    endpoint: str
    operation_name: str | None
    code: str
    message: str


@dataclass(frozen=True)
class ReportContext:
    report_schema_version: int
    gqlsleuth_version: str
    generated_at: datetime
    target: Target
    mode: ScanMode
    summary: dict[str, int]
    endpoints: tuple[EndpointReport, ...]
    review_candidates: tuple[OperationAnalysis, ...]
    queries: tuple[OperationReport, ...]
    active: ActiveReport | None
    evidence: tuple[Evidence, ...]
    evidence_counts: dict[str, int]
    errors_and_limitations: tuple[ReportIssue, ...]
    recommendations: tuple[str, ...]
    safety_notice: str
    ai_interpretation: AIInterpretationResult | None = None
    graphql_security_review: GraphQLSecurityReviewResult | None = None
    multiplicity: MultiplicityValidationResult | None = None
    query_depth: QueryDepthValidationResult | None = None
    sequential_object_discovery: SequentialDiscoveryResult | None = None
    object_authorization_review: ObjectAuthorizationResult | None = None
    authorization_policy_validation: AuthorizationPolicyResult | None = None
    object_lookup_follow_up: tuple[ObjectLookupFollowUpHint, ...] | None = None


@dataclass(frozen=True)
class NamedContextReport:
    name: str
    scan: ReportContext | None
    error_code: str | None


@dataclass(frozen=True)
class DifferentialReportContext:
    report_schema_version: int
    gqlsleuth_version: str
    generated_at: datetime
    target: Target
    mode: ScanMode
    contexts: tuple[NamedContextReport, ...]
    pairs: tuple[ContextPairReview, ...]
    safety_notice: str
    nested_authorization_review: NestedAuthorizationResult | None = None
    object_authorization_review: ObjectAuthorizationResult | None = None
    authorization_policy_validation: AuthorizationPolicyResult | None = None
