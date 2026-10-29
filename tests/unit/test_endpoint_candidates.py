"""Tests for deterministic endpoint URL normalization and generation."""

import pytest

from gqlsleuth.discovery.endpoint_candidates import (
    BUNDLED_ENDPOINT_PATHS,
    CORE_ENDPOINT_PATHS,
    EXTENDED_ENDPOINT_PATHS,
    generate_endpoint_candidate_stages,
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


def test_curated_inventory_is_exact_and_core_priority_is_preserved():
    assert CORE_ENDPOINT_PATHS == (
        "/graphql",
        "/api/graphql",
        "/gql",
        "/api/gql",
        "/v1/graphql",
        "/v2/graphql",
        "/graphql/v1",
        "/graphql/v2",
        "/query",
        "/api/query",
    )
    assert EXTENDED_ENDPOINT_PATHS == (
        "/___graphql",
        "/api",
        "/graphql/api",
        "/graphql/graphql",
        "/server/api/graphql",
        "/je/graphql",
        "/graph",
        "/v1/api/graphql",
        "/v1/graph",
        "/v2/api/graphql",
        "/v2/graph",
        "/v3/graphql",
        "/v3/api/graphql",
        "/v3/graph",
        "/v4/graphql",
        "/v4/api/graphql",
        "/v4/graph",
    )
    assert BUNDLED_ENDPOINT_PATHS == CORE_ENDPOINT_PATHS + EXTENDED_ENDPOINT_PATHS
    assert len(BUNDLED_ENDPOINT_PATHS) == len(set(BUNDLED_ENDPOINT_PATHS)) == 27
    assert all(path.startswith("/") for path in BUNDLED_ENDPOINT_PATHS)


@pytest.mark.parametrize("path", ["/v3/api/graphql/", "/graphql", "/custom?x=1", "/api?x=1"])
def test_candidate_stages_are_stable_and_deduplicate_supplied_urls(path):
    target = Target.parse("https://EXAMPLE.com:443" + path)
    core, extended = generate_endpoint_candidate_stages(target)
    assert core[0] == normalize_discovery_url(target.original_url)
    assert not set(core) & set(extended)
    assert core + extended == generate_endpoint_candidates(target)
    assert len(core + extended) == len(set(core + extended))
    assert (core, extended) == generate_endpoint_candidate_stages(target)


@pytest.mark.parametrize("path", ["/graphql.php", "/schema.json", "/playground", "/subscriptions"])
def test_inventory_exclusions_do_not_reject_explicit_targets(path):
    assert path not in BUNDLED_ENDPOINT_PATHS
    assert generate_endpoint_candidates(Target.parse("https://example.com" + path))[0] == (
        "https://example.com" + path
    )
