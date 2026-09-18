"""Bounded unverified JWT inspection. Decoded claims and variants never enter review models."""

import base64
import binascii
import json
import math
import re
from datetime import UTC, datetime

from gqlsleuth.domain.authentication import (
    JWT_CLOCK_SKEW_SECONDS,
    AuthenticationProbe,
    TokenSecurityReview,
)

_ALGORITHMS = frozenset(
    {
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
    }
)
_HEADERS = ("typ", "kid", "jku", "jwk", "x5u")
_CLAIMS = ("exp", "nbf", "iat", "iss", "aud", "jti", "sub")
MAX_JWT_INSPECTION_BYTES = 16384


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if _encode(decoded) != value:
        raise ValueError
    return decoded


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("Non-JSON numeric constant.")


def _jwt(token: str) -> tuple[dict[str, object], dict[str, object], list[str]] | None:
    try:
        if len(token) > MAX_JWT_INSPECTION_BYTES:
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(
            _decode(parts[0]).decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
        payload = json.loads(
            _decode(parts[1]).decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        json.dumps(header, allow_nan=False)  # Only safely reconstructable headers are supported.
        if not isinstance(header.get("alg"), str) or not header["alg"]:
            return None
        if "crit" in header or "b64" in header:
            return None  # Unsupported JWS extensions; do not guess their signing semantics.
        if parts[2]:
            _decode(parts[2])
        elif header["alg"] != "none":
            return None
        return header, payload, parts
    except (ValueError, UnicodeDecodeError, binascii.Error, RecursionError):
        return None


def _temporal(name: str, payload: dict[str, object], at: datetime) -> str:
    if name not in payload:
        return "absent"
    value = payload[name]
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "malformed / unsupported"
    try:
        if not math.isfinite(value):
            return "malformed / unsupported"
        datetime.fromtimestamp(value, UTC)
        if name == "exp" and value < at.timestamp() - JWT_CLOCK_SKEW_SECONDS:
            return "expired"
        if name in {"nbf", "iat"} and value > at.timestamp() + JWT_CLOCK_SKEW_SECONDS:
            return "not yet valid" if name == "nbf" else "future issuance"
    except (OverflowError, OSError, ValueError):
        return "malformed / unsupported"
    return "currently valid" if name != "iat" else "numeric issuance metadata"


def inspect_bearer(
    token: str, at: datetime, *, completed_at: datetime | None = None
) -> TokenSecurityReview:
    decoded = _jwt(token)
    if decoded is None:
        return TokenSecurityReview(
            "opaque", observations=("Opaque/unsupported Bearer token; JWT probes unavailable.",)
        )
    header, payload, parts = decoded
    algorithm = header["alg"]
    # Arbitrary alg text is untrusted claim material, not safe metadata.
    safe_algorithm = (
        algorithm if isinstance(algorithm, str) and algorithm in _ALGORITHMS else "unrecognized"
    )
    observations = ["Unverified structural inspection; signature validity was not checked."]
    if algorithm == "none":
        observations.append(
            "Unsigned algorithm declared: manual review interest, not server acceptance evidence."
        )
    if any(name in header for name in ("kid", "jku", "jwk", "x5u")):
        observations.append("Key-reference/header material is present; manual review only.")
    if any(name not in payload for name in ("exp", "iss", "aud", "jti")):
        observations.append(
            "Some expected claims are absent; missing claims alone are not vulnerabilities."
        )
    return TokenSecurityReview(
        "jwt",
        safe_algorithm,
        tuple((name, name in header) for name in _HEADERS),
        tuple((name, name in payload) for name in _CLAIMS),
        tuple(
            (name, _temporal(name, payload, completed_at or at if name == "nbf" else at))
            for name in ("exp", "nbf", "iat")
        ),
        tuple(observations),
        algorithm == "none" and not parts[2],
    )


def available_jwt_probes(token: str) -> tuple[AuthenticationProbe, ...]:
    decoded = _jwt(token)
    if decoded is None:
        return ()
    header, _, parts = decoded
    # An already unsigned token needs no equivalent replay.
    return (
        (AuthenticationProbe.JWT_SIGNATURE_TAMPERED,)
        if parts[2] and header["alg"] != "none"
        else ()
    ) + (
        (AuthenticationProbe.JWT_ALG_NONE,)
        if not (header["alg"] == "none" and not parts[2])
        else ()
    )


def token_variant(token: str, probe: AuthenticationProbe) -> str:
    """Return transient request material; caller must never put it in a result or message."""
    decoded = _jwt(token)
    if decoded is None or probe not in available_jwt_probes(token):
        raise ValueError("Unsupported JWT probe.")
    header, _, parts = decoded
    if probe is AuthenticationProbe.JWT_SIGNATURE_TAMPERED:
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    else:
        header = {**header, "alg": "none"}
        parts[0] = _encode(
            json.dumps(header, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()
        )
        parts[2] = ""
    return ".".join(parts)
