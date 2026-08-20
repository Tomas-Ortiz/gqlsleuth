"""Tests for deterministic endpoint URL normalization and generation."""

import pytest

from gqlsleuth.discovery.endpoint_candidates import (
    BUNDLED_ENDPOINT_PATHS,
    generate_endpoint_candidates,
    normalize_discovery_url,
)
from gqlsleuth.domain.models import Target


def test_normalization_lowercases_origin_and_handles_trailing_slashes() -> None:
    assert normalize_discovery_url("HTTPS://Example.COM/") == "https://example.com"
    assert (
        normalize_discovery_url("https://Example.COM/custom/?x=1")
        == "https://example.com/custom?x=1"
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://example.com:80", "http://example.com"),
        ("https://example.com:443", "https://example.com"),
        ("https://example.com:8443/", "https://example.com:8443"),
    ],
)
def test_normalization_removes_only_default_ports(url: str, expected: str) -> None:
    assert normalize_discovery_url(url) == expected


def test_base_target_generates_the_bundled_candidates_in_order() -> None:
    target = Target.parse("https://Example.COM/")

    candidates = generate_endpoint_candidates(target)

    assert candidates == tuple(f"https://example.com{path}" for path in BUNDLED_ENDPOINT_PATHS)


def test_supplied_endpoint_is_first_and_duplicate_candidates_are_removed() -> None:
    custom_target = Target.parse("https://example.com/custom/?operation=list")
    bundled_target = Target.parse("https://example.com/graphql/")

    custom_candidates = generate_endpoint_candidates(custom_target)
    bundled_candidates = generate_endpoint_candidates(bundled_target)

    assert custom_candidates[0] == "https://example.com/custom?operation=list"
    assert custom_candidates[1] == "https://example.com/graphql"
    assert bundled_candidates[0] == "https://example.com/graphql"
    assert bundled_candidates.count("https://example.com/graphql") == 1
    assert len(bundled_candidates) == len(BUNDLED_ENDPOINT_PATHS)
