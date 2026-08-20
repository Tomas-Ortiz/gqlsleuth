"""Typed configuration-independent domain data available through Phase 3."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Self
from urllib.parse import SplitResult, urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from gqlsleuth.domain.exceptions import InvalidUrlError, UnsupportedSchemeError


class ScanMode(StrEnum):
    """Selected scan mode; ACTIVE has no distinct behavior through Phase 3."""

    SAFE = "safe"
    ACTIVE = "active"


class EvidenceType(StrEnum):
    """Deterministic evidence categories planned for the scanning workflow."""

    ENDPOINT_CANDIDATE = "endpoint_candidate"
    GRAPHQL_CONFIRMATION = "graphql_confirmation"
    INTROSPECTION_RESULT = "introspection_result"
    SCHEMA_ARTIFACT = "schema_artifact"
    INTERESTING_OPERATION = "interesting_operation"
    GENERATED_QUERY = "generated_query"
    QUERY_EXECUTION = "query_execution"
    MUTATION_EXECUTION = "mutation_execution"
    HTTP_ERROR = "http_error"
    PARSER_ERROR = "parser_error"


class ConfidenceLevel(StrEnum):
    """Confidence attached to evidence when a producing phase can justify it."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    NOT_DETECTED = "not_detected"


class Target(BaseModel):
    """A validated HTTP(S) target with its original URL components preserved."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    original_url: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str

    @classmethod
    def parse(cls, value: str) -> Self:
        """Parse a target without normalizing or contacting it."""
        parsed = _parse_url(value)
        return cls(
            original_url=value,
            scheme=parsed.scheme,
            host=_preserved_host(parsed),
            port=parsed.port,
            path=parsed.path,
            query=parsed.query,
        )


class Evidence(BaseModel):
    """A directly observed technical fact produced by a deterministic phase."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: UUID = Field(default_factory=uuid4)
    evidence_type: EvidenceType
    target: Target
    endpoint: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    summary: str
    source: str
    confidence: ConfidenceLevel | None = None
    notes: tuple[str, ...] = ()


class ResultError(BaseModel):
    """A concise expected error retained in a scan result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str


class ScanResult(BaseModel):
    """Minimal Phase 1 container for scan data produced in later phases."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target: Target
    mode: ScanMode = ScanMode.SAFE
    evidence: tuple[Evidence, ...] = ()
    errors: tuple[ResultError, ...] = ()
    limitations: tuple[str, ...] = ()


def _parse_url(value: str) -> SplitResult:
    if not value or value != value.strip():
        raise InvalidUrlError("Target must be a non-empty URL without surrounding whitespace.")

    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise InvalidUrlError(f"Invalid target URL: {error}.") from None

    if not parsed.scheme:
        raise InvalidUrlError("Target URL must include an HTTP or HTTPS scheme.")
    if parsed.scheme not in {"http", "https"}:
        raise UnsupportedSchemeError(
            f"Unsupported target scheme '{parsed.scheme}'; use http or https."
        )
    if not parsed.netloc or parsed.hostname is None:
        raise InvalidUrlError("Target URL must include a host.")

    try:
        _ = parsed.port
    except ValueError as error:
        raise InvalidUrlError(f"Invalid target URL: {error}.") from None

    return parsed


def _preserved_host(parsed: SplitResult) -> str:
    host_and_port = parsed.netloc.rsplit("@", maxsplit=1)[-1]
    if host_and_port.startswith("["):
        closing_bracket = host_and_port.find("]")
        if closing_bracket == -1:
            raise InvalidUrlError("Invalid target URL: unmatched IPv6 bracket.")
        return host_and_port[1:closing_bracket]
    return host_and_port.rsplit(":", maxsplit=1)[0] if ":" in host_and_port else host_and_port
