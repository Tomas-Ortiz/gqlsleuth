"""Focused tests for Phase 1 domain models."""

import pytest

from gqlsleuth.domain.exceptions import InvalidUrlError, UnsupportedSchemeError
from gqlsleuth.domain.models import (
    ConfidenceLevel,
    Evidence,
    EvidenceType,
    ResultError,
    ScanMode,
    ScanResult,
    Target,
)


def test_scan_mode_contains_safe_and_active_values() -> None:
    assert list(ScanMode) == [ScanMode.SAFE, ScanMode.ACTIVE]
    assert ScanMode.SAFE.value == "safe"
    assert ScanMode.ACTIVE.value == "active"


@pytest.mark.parametrize("url", ["http://example.com", "https://example.com"])
def test_target_accepts_http_and_https(url: str) -> None:
    target = Target.parse(url)

    assert target.original_url == url
    assert target.host == "example.com"


def test_target_preserves_port_path_and_query_without_normalization() -> None:
    target = Target.parse("https://Example.COM:8443/base/?x=1&x=2")

    assert target.original_url == "https://Example.COM:8443/base/?x=1&x=2"
    assert target.scheme == "https"
    assert target.host == "Example.COM"
    assert target.port == 8443
    assert target.path == "/base/"
    assert target.query == "x=1&x=2"


@pytest.mark.parametrize(
    "url",
    ["", "example.com", "https:///graphql", " https://example.com", "https://example.com:no"],
)
def test_target_rejects_invalid_urls(url: str) -> None:
    with pytest.raises(InvalidUrlError):
        Target.parse(url)


def test_target_rejects_unsupported_schemes() -> None:
    with pytest.raises(UnsupportedSchemeError):
        Target.parse("ftp://example.com")


def test_evidence_supports_basic_structured_data() -> None:
    target = Target.parse("https://example.com")
    evidence = Evidence(
        evidence_type=EvidenceType.ENDPOINT_CANDIDATE,
        target=target,
        summary="Target accepted for a future discovery phase.",
        source="test_domain_models",
        confidence=ConfidenceLevel.POSSIBLE,
    )

    assert evidence.target == target
    assert evidence.notes == ()


def test_scan_result_has_safe_defaults_and_current_phase_fields() -> None:
    target = Target.parse("https://example.com")
    error = ResultError(code="not_implemented", message="Scanning is not implemented.")
    result = ScanResult(
        target=target,
        errors=(error,),
        limitations=("No network request was performed.",),
    )

    assert result.target == target
    assert result.mode is ScanMode.SAFE
    assert result.evidence == ()
    assert result.errors == (error,)
