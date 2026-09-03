"""Project-owned models for deterministic read-only query generation."""

from dataclasses import dataclass

from pydantic import JsonValue

from gqlsleuth.domain.analysis import OperationAnalysis, OperationKind


@dataclass(frozen=True)
class QueryGenerationResult:
    """Generation outcome associated with one Phase 7 Query operation."""

    operation: OperationAnalysis
    query_text: str | None
    variables: dict[str, JsonValue]
    manual_adjustments: tuple[str, ...]
    failure_reason: str | None

    @property
    def success(self) -> bool:
        """Whether a syntactically valid query artifact was generated."""
        return self.query_text is not None

    @property
    def endpoint(self) -> str:
        """Return the endpoint inherited from the analyzed operation."""
        return self.operation.endpoint

    @property
    def operation_name(self) -> str:
        """Return the generated root Query field name."""
        return self.operation.name

    @property
    def operation_kind(self) -> OperationKind:
        """Return the schema-derived operation kind."""
        return self.operation.kind
