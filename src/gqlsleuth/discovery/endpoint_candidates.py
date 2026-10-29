"""Normalize targets and generate conservative endpoint candidate URLs."""

from urllib.parse import urlunsplit

from gqlsleuth.domain.models import Target

CORE_ENDPOINT_PATHS: tuple[str, ...] = (
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
EXTENDED_ENDPOINT_PATHS: tuple[str, ...] = (
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
BUNDLED_ENDPOINT_PATHS = CORE_ENDPOINT_PATHS + EXTENDED_ENDPOINT_PATHS


def normalize_discovery_url(value: str) -> str:
    """Return a stable HTTP(S) URL without changing its discovery semantics."""
    return _normalized_target_url(Target.parse(value))


def generate_endpoint_candidates(target: Target) -> tuple[str, ...]:
    """Generate ordered, unique candidate URLs from one validated target."""
    core, extended = generate_endpoint_candidate_stages(target)
    return core + extended


def generate_endpoint_candidate_stages(target: Target) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Keep the supplied endpoint first, then core paths, then unattempted extended paths."""
    origin = _normalized_origin(target)
    candidates: list[str] = []

    if target.path.rstrip("/"):
        candidates.append(_normalized_target_url(target))

    candidates.extend(f"{origin}{path}" for path in CORE_ENDPOINT_PATHS)
    core = tuple(dict.fromkeys(candidates))
    extended = tuple(
        f"{origin}{path}" for path in EXTENDED_ENDPOINT_PATHS if f"{origin}{path}" not in core
    )
    return core, extended


def _normalized_target_url(target: Target) -> str:
    path = target.path.rstrip("/")
    return urlunsplit(
        (
            target.scheme.lower(),
            _normalized_netloc(target),
            path,
            target.query,
            "",
        )
    )


def _normalized_origin(target: Target) -> str:
    return urlunsplit(
        (
            target.scheme.lower(),
            _normalized_netloc(target),
            "",
            "",
            "",
        )
    )


def _normalized_netloc(target: Target) -> str:
    host = target.host.lower()
    if ":" in host:
        host = f"[{host}]"

    default_port = (target.scheme.lower(), target.port) in {
        ("http", 80),
        ("https", 443),
    }
    if target.port is None or default_port:
        return host
    return f"{host}:{target.port}"
