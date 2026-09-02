"""Project-owned models for deterministic operation review prioritization."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gqlsleuth.domain.schema import TypeReference


class OperationKind(StrEnum):
    """Root operation kind established from the parsed schema roots."""

    QUERY = "query"
    MUTATION = "mutation"


class OperationCategory(StrEnum):
    """Deterministic semantic categories available to Phase 7 rules."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    USER_MANAGEMENT = "user_management"
    ADMINISTRATIVE_FUNCTIONALITY = "administrative_functionality"
    TOKENS_AND_SESSIONS = "tokens_and_sessions"
    PASSWORD_MANAGEMENT = "password_management"
    ACCOUNT_RECOVERY = "account_recovery"
    IDENTITY_PROVIDERS = "identity_providers"
    FILES_AND_UPLOADS = "files_and_uploads"
    INTEGRATIONS = "integrations"
    BILLING_AND_PAYMENTS = "billing_and_payments"
    PERSONAL_INFORMATION = "personal_information"
    SECRETS_AND_CREDENTIALS = "secrets_and_credentials"
    CONFIGURATION = "configuration"
    DEBUGGING = "debugging"
    INTERNAL_FUNCTIONALITY = "internal_functionality"
    SEARCH = "search"
    REPORTING = "reporting"
    READ_ONLY_BUSINESS_DATA = "read_only_business_data"
    STATE_CHANGING_BUSINESS_OPERATION = "state_changing_business_operation"


class InterestPriority(StrEnum):
    """Review-interest level derived from a deterministic numeric score."""

    CRITICAL_INTEREST = "critical_interest"
    HIGH_INTEREST = "high_interest"
    MEDIUM_INTEREST = "medium_interest"
    LOW_INTEREST = "low_interest"
    INFORMATIONAL = "informational"


PRIORITY_RANK: dict[InterestPriority, int] = {
    InterestPriority.CRITICAL_INTEREST: 0,
    InterestPriority.HIGH_INTEREST: 1,
    InterestPriority.MEDIUM_INTEREST: 2,
    InterestPriority.LOW_INTEREST: 3,
    InterestPriority.INFORMATIONAL: 4,
}
OPERATION_KIND_RANK: dict[OperationKind, int] = {
    OperationKind.QUERY: 0,
    OperationKind.MUTATION: 1,
}


class PriorityThresholds(BaseModel):
    """Ordered score thresholds loaded from the Phase 7 rule file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    critical: int = Field(gt=0)
    high: int = Field(gt=0)
    medium: int = Field(gt=0)
    low: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if not self.critical > self.high > self.medium > self.low:
            raise ValueError("thresholds must satisfy critical > high > medium > low")
        return self

    def priority_for(self, score: int) -> InterestPriority:
        """Map a non-negative interest score using these configured thresholds."""
        if score >= self.critical:
            return InterestPriority.CRITICAL_INTEREST
        if score >= self.high:
            return InterestPriority.HIGH_INTEREST
        if score >= self.medium:
            return InterestPriority.MEDIUM_INTEREST
        if score >= self.low:
            return InterestPriority.LOW_INTEREST
        return InterestPriority.INFORMATIONAL


class OperationRule(BaseModel):
    """One auditable semantic rule loaded from YAML."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    category: OperationCategory
    keywords: tuple[str, ...] = Field(min_length=1)
    weight: int = Field(gt=0)
    reason: str

    @field_validator("id", "reason")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value

    @field_validator("keywords")
    @classmethod
    def validate_keywords(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)
        if any(not value for value in normalized):
            raise ValueError("keywords must not contain empty values")
        return normalized


class RuleSet(BaseModel):
    """Validated thresholds and deterministic ordered operation rules."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    thresholds: PriorityThresholds
    rules: tuple[OperationRule, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_rule_ids(self) -> Self:
        rule_ids = [rule.id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule IDs must be unique")
        return self


@dataclass(frozen=True)
class RuleMatch:
    """One rule's once-per-operation contribution and supporting matches."""

    rule_id: str
    category: OperationCategory
    weight: int
    matched_keywords: tuple[str, ...]
    locations: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class OperationAnalysis:
    """Deterministic classification and review priority for one root field."""

    endpoint: str
    kind: OperationKind
    name: str
    return_type: TypeReference
    categories: tuple[OperationCategory, ...]
    interest_score: int
    priority: InterestPriority
    matched_rules: tuple[RuleMatch, ...]
    reasons: tuple[str, ...]
