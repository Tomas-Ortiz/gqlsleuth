"""Unverified, privacy-preserving local inspection and exact deterministic variants."""

import base64
import json
from datetime import UTC, datetime

import pytest

from fixtures.phase26_target import CLAIM_CANARY, encode, fake_token
from gqlsleuth.domain.authentication import AuthenticationProbe as Probe
from gqlsleuth.rules.token_security import available_jwt_probes, inspect_bearer, token_variant

NOW = datetime(2026, 9, 18, tzinfo=UTC)


@pytest.mark.parametrize(
    "token",
    [
        "opaque",
        "a.b",
        "a.b.c.d",
        "!.e30.c2ln",
        "e30.!.c2ln",
        "bm90LWpzb24.e30.c2ln",
        "e30.bm90LWpzb24.c2ln",
        "W10.e30.c2ln",
        "e30.W10.c2ln",
        "e30.e30.c2ln",
        "x" * 16385,
        fake_token(header={"alg": "HS256", "crit": []}),
        fake_token(header={"alg": "HS256", "b64": False}),
        fake_token(header={"alg": "HS256", "value": float("inf")}),
        encode(b'{"alg":"HS256","alg":"none"}') + ".e30.c2ln",
    ],
)
def test_unsupported_tokens_are_opaque(token):
    assert inspect_bearer(token, NOW).token_type == "opaque"
    assert available_jwt_probes(token) == ()


@pytest.mark.parametrize("algorithm", ["HS256", "RS256", "ES256", "none", CLAIM_CANARY])
def test_presence_only_metadata_and_no_algorithm_vulnerability(algorithm):
    token = fake_token(
        {key: CLAIM_CANARY for key in ("sub", "iss", "aud", "jti")},
        {key: CLAIM_CANARY for key in ("typ", "kid", "jku", "jwk", "x5u")} | {"alg": algorithm},
    )
    review = inspect_bearer(token, NOW)
    assert review.algorithm == ("unrecognized" if algorithm == CLAIM_CANARY else algorithm)
    assert all(value for _, value in review.header_presence)
    assert dict(review.claim_presence)["sub"]
    assert token not in repr(review) and CLAIM_CANARY not in repr(review)
    assert "Unverified" in review.observations[0]
    assert not hasattr(review, "findings")


@pytest.mark.parametrize(
    "name,offset,expected",
    [
        ("exp", -61, "expired"),
        ("exp", -60, "currently valid"),
        ("nbf", 61, "not yet valid"),
        ("nbf", 60, "currently valid"),
        ("iat", 61, "future issuance"),
        ("iat", -61, "numeric issuance metadata"),
    ],
)
def test_numeric_dates_and_conservative_skew(name, offset, expected):
    assert (
        dict(inspect_bearer(fake_token({name: NOW.timestamp() + offset}), NOW).temporal_states)[
            name
        ]
        == expected
    )


@pytest.mark.parametrize("value", ["123", True, None, [], {}, 10**100, -(10**100)])
def test_malformed_numeric_dates(value):
    review = inspect_bearer(fake_token({"exp": value}), NOW)
    assert dict(review.temporal_states)["exp"] == "malformed / unsupported"


def test_exact_signature_and_none_variants():
    token = fake_token()
    parts = token.split(".")
    tampered = token_variant(token, Probe.JWT_SIGNATURE_TAMPERED)
    changed = tampered.split(".")
    assert changed[:2] == parts[:2]
    assert sum(a != b for a, b in zip(parts[2], changed[2], strict=True)) == 1
    assert base64.urlsafe_b64decode(changed[2] + "=")
    unsigned = token_variant(token, Probe.JWT_ALG_NONE).split(".")
    assert unsigned[1] == parts[1] and unsigned[2] == ""
    header = json.loads(base64.urlsafe_b64decode(unsigned[0] + "=" * (-len(unsigned[0]) % 4)))
    assert header == {"alg": "none", "typ": "JWT", "kid": CLAIM_CANARY}
    assert token_variant(token, Probe.JWT_SIGNATURE_TAMPERED) == tampered
    assert available_jwt_probes(fake_token(header={"alg": "none"})) == ()
