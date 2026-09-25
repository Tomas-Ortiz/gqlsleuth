"""Allowlisted AI input and bounded interpretation models, separate from Evidence."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from gqlsleuth.domain.abuse_controls import AbuseControlKind, AbuseControlOutcome
from gqlsleuth.domain.active import MutationDecision
from gqlsleuth.domain.analysis import InterestPriority, OperationCategory, OperationKind
from gqlsleuth.domain.authentication import AuthenticationFindingKind, AuthenticationProbe
from gqlsleuth.domain.authorization_policy import PolicyProvenance, PolicyStatus
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.federation import FederationOutcome, FederationProbe
from gqlsleuth.domain.file_upload import UploadBaselineStatus, UploadOutcome, UploadProbe
from gqlsleuth.domain.idor import IdorPolicyResult
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.multiplicity import MultiplicityObservation, MultiplicityProbeType
from gqlsleuth.domain.mutation_authorization import MutationAuthorizationOutcome
from gqlsleuth.domain.nested_authorization import NestedOutcome
from gqlsleuth.domain.object_authorization import ObjectOutcome
from gqlsleuth.domain.query_depth import QueryDepthObservation
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.domain.sensitive_input import SensitiveInputCategory, SensitiveInputOutcome
from gqlsleuth.domain.subscriptions import SubscriptionOutcome, SubscriptionProtocol

MAX_AI_OPERATIONS = 12
MAX_CONTEXT_BYTES = 12_000
DEFAULT_AI_MODEL = "qwen3:8b"
AI_NOTICE = "Model-generated interpretation — not evidence or vulnerability confirmation."


class AIAnalysisStatus(StrEnum):
    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    HTTP_ERROR = "http_error"
    INVALID_RESPONSE = "invalid_response"


class AIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AICapability(StrEnum):
    STRUCTURAL_REVIEW = "structural_review"
    MULTIPLICITY = "multiplicity"
    QUERY_DEPTH = "query_depth"
    OBJECT_AUTHORIZATION = "object_authorization"
    AUTHORIZATION_POLICY = "authorization_policy"
    SEQUENTIAL_DISCOVERY = "sequential_discovery"
    MUTATION_AUTHORIZATION = "mutation_authorization"
    SENSITIVE_INPUT_REVIEW = "sensitive_input_review"
    SENSITIVE_INPUT_VALIDATION = "sensitive_input_validation"
    IDOR_BOLA = "idor_bola"
    AUTHENTICATION = "authentication"
    ABUSE_CONTROLS = "abuse_controls"
    FILE_UPLOAD = "file_upload"
    FEDERATION = "federation"
    SUBSCRIPTIONS = "subscriptions"


class AIFactCategory(StrEnum):
    FINDING = "finding"
    POLICY_VIOLATION = "policy_violation"
    POLICY_SATISFIED = "policy_satisfied"
    UNRESOLVED = "unresolved"
    SECURITY_OBSERVATION = "security_observation"
    REVIEW_CANDIDATE = "review_candidate"


GraphQLName = Annotated[str, Field(pattern=r"^[_A-Za-z][_0-9A-Za-z]{0,127}$", strict=True)]
FactReference = Annotated[str, Field(pattern=r"^SF[1-9][0-9]*$", max_length=24, strict=True)]
Count = Annotated[int, Field(ge=0, le=2**63 - 1, strict=True)]
TemporalState = Literal[
    "absent",
    "malformed / unsupported",
    "expired",
    "not yet valid",
    "future issuance",
    "currently valid",
    "numeric issuance metadata",
]


class AITokenMetadata(AIModel):
    token_type: Literal["jwt", "opaque"]
    algorithm: (
        Literal[
            "none",
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
            "EdDSA",
            "unrecognized",
        ]
        | None
    ) = None
    header_presence: tuple[tuple[Literal["typ", "kid", "jku", "jwk", "x5u"], bool], ...] = ()
    claim_presence: tuple[
        tuple[Literal["exp", "nbf", "iat", "iss", "aud", "jti", "sub"], bool], ...
    ] = ()
    temporal_states: tuple[tuple[Literal["exp", "nbf", "iat"], TemporalState], ...] = ()


class AISecurityFact(AIModel):
    """Explicit semantic fields only: no free-form target text or Evidence containers."""

    security_fact_ref: FactReference = "SF1"
    capability: AICapability
    category: AIFactCategory
    kind: Literal["query", "mutation", "subscription"] | None = None
    name: GraphQLName | None = None
    argument: GraphQLName | None = None
    path: tuple[GraphQLName, ...] = Field(default=(), max_length=8)
    type_name: GraphQLName | None = None
    candidate_type: SecurityCandidateType | SensitiveInputCategory | None = None
    finding_type: (
        AuthenticationFindingKind
        | Literal[
            "object_level_authorization_failure",
            "abuse_control_policy_violation",
            "file_upload_validation_policy_violation",
            "FEDERATION_SDL_POLICY_VIOLATION",
            "FEDERATION_ENTITY_AUTHORIZATION_FAILURE",
            "SUBSCRIPTION_AUTHORIZATION_FAILURE",
        ]
        | None
    ) = None
    outcome: (
        MultiplicityObservation
        | QueryDepthObservation
        | ObjectOutcome
        | NestedOutcome
        | MutationAuthorizationOutcome
        | SensitiveInputOutcome
        | AbuseControlOutcome
        | UploadOutcome
        | FederationOutcome
        | SubscriptionOutcome
        | None
    ) = None
    expected: Literal["allow", "deny", "observe", "control_required"] | None = None
    evaluation: PolicyStatus | IdorPolicyResult | UploadBaselineStatus | None = None
    provenance: PolicyProvenance | None = None
    probe: MultiplicityProbeType | AuthenticationProbe | UploadProbe | FederationProbe | None = None
    control_observed: bool = False
    control_kind: AbuseControlKind | None = None
    baseline_status: QueryExecutionStatus | UploadBaselineStatus | None = None
    context_mode: Literal["anonymous", "supplied_context"] | None = None
    multiplicity: Count | None = None
    baseline_depth: Count | None = None
    probe_depth: Count | None = None
    list_edges: Count | None = None
    seed_count: Count | None = None
    attempts: Count | None = None
    planned_attempts: Count | None = None
    review_candidate_count: Count | None = None
    token: AITokenMetadata | None = None
    sdl_returned: bool | None = None
    protocol: SubscriptionProtocol | None = None
    handshake_headers_supplied: bool | None = None
    init_payload_supplied: bool | None = None
    acknowledged: bool | None = None
    subscription_sent: bool | None = None
    application_event_count: Count | None = None


class AICapabilityCoverage(AIModel):
    capability: AICapability
    state: Literal["not_enabled", "not_present", "prepared", "executed", "partial", "local_only"]
    attempts: Count = 0


class AIOperation(AIModel):
    """Only structural identifiers, deterministic rankings, and normalized states."""

    operation: str
    kind: OperationKind
    name: str
    return_type: str | None
    priority: InterestPriority
    interest_score: int
    categories: tuple[OperationCategory, ...]
    generated: bool
    manual_adjustment_required: bool
    execution_status: QueryExecutionStatus | None
    http_status: int | None
    attempted: bool
    mutation_safety: MutationDecision | None
    selectable: bool
    selected: bool
    mutation_decision: MutationDecision | None


class AISchemaSummary(AIModel):
    endpoint: str
    query_root: str | None
    mutation_root: str | None
    total_types: int
    queries: int
    mutations: int
    subscriptions: int


class AIContextMetadata(AIModel):
    operations_total: int
    operations_included: int
    operations_omitted: int
    schemas_total: int
    schemas_included: int
    context_truncated: bool
    security_facts_total: int = 0
    security_facts_included: int = 0
    security_facts_omitted: int = 0
    serialized_bytes: int = 0
    differential_ai_supported: Literal[False] = False
    deterministic_findings: int = 0
    policy_violations: int = 0
    policy_satisfied: int = 0
    policy_unresolved: int = 0


class AIContext(AIModel):
    mode: ScanMode
    final_batch_confirmed: bool | None
    metadata: AIContextMetadata
    operations: tuple[AIOperation, ...]
    schemas: tuple[AISchemaSummary, ...]
    counts: dict[str, int]
    capability_coverage: tuple[AICapabilityCoverage, ...] = ()
    security_facts: tuple[AISecurityFact, ...] = ()


AIText = Annotated[str, Field(strict=True, min_length=1, max_length=600)]
OperationReference = Annotated[str, Field(strict=True, min_length=1, max_length=180)]


class AIStatement(AIModel):
    """References live in explicit fields, including summary and limitations."""

    text: AIText
    operations: tuple[OperationReference, ...] = Field(max_length=MAX_AI_OPERATIONS)
    security_facts: tuple[FactReference, ...] = Field(default=(), max_length=8)


class AIOperationExplanation(AIModel):
    operation: OperationReference
    explanation: AIText


class AILimitation(AIStatement):
    text: Annotated[str, Field(strict=True, min_length=1, max_length=500)]


class AISecuritySummary(AIModel):
    text: Annotated[str, Field(strict=True, min_length=1, max_length=800)]
    security_facts: tuple[FactReference, ...] = Field(max_length=8)


class AISecurityFactReview(AIModel):
    security_fact_ref: FactReference
    interpretation: Annotated[str, Field(strict=True, min_length=1, max_length=450)]
    manual_follow_up: Annotated[str, Field(strict=True, min_length=1, max_length=350)]


class AIControlObservation(AIModel):
    security_fact_ref: FactReference
    text: Annotated[str, Field(strict=True, min_length=1, max_length=400)]


class AICrossCapabilityInsight(AIModel):
    security_facts: tuple[FactReference, ...] = Field(min_length=2, max_length=4)
    text: Annotated[str, Field(strict=True, min_length=1, max_length=500)]


class AIInterpretation(AIModel):
    scan_summary: AIStatement
    security_summary: AISecuritySummary
    security_fact_reviews: tuple[AISecurityFactReview, ...] = Field(max_length=8)
    control_observations: tuple[AIControlObservation, ...] = Field(max_length=6)
    cross_capability_insights: tuple[AICrossCapabilityInsight, ...] = Field(max_length=4)
    operation_review: tuple[AIOperationExplanation, ...] = Field(max_length=8)
    limitations: tuple[AILimitation, ...] = Field(max_length=8)


@dataclass(frozen=True)
class AIInterpretationResult:
    status: AIAnalysisStatus
    model: str
    generated_at: datetime
    duration_seconds: float
    context_metadata: AIContextMetadata
    interpretation: AIInterpretation | None = None
    error_code: str | None = None
    error_message: str | None = None


class AIServiceError(Exception):
    """Normalized AI-only failure; never carries a raw response or exception dump."""

    def __init__(self, status: AIAnalysisStatus, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
