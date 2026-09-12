from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import cast

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from xcia.domain import (
    ConfirmationClaim,
    CustomerAuthAssertionClaims,
    RelyingPartyTrustPolicy,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class UnknownKidError(ValueError):
    pass


class EphemeralEs256Harness:
    def __init__(self, kid: str = "test-kid-01") -> None:
        self._private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP256R1()
        )
        self.kid = kid
        self._public_jwk = self._build_public_jwk()
        self.jkt = self._thumbprint(self._public_jwk)

    def _build_public_jwk(self) -> dict[str, object]:
        numbers: ec.EllipticCurvePublicNumbers = self._private_key.public_key().public_numbers()
        size = (self._private_key.curve.key_size + 7) // 8
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(size, "big")),
            "y": _b64url(numbers.y.to_bytes(size, "big")),
            "use": "sig",
            "alg": "ES256",
            "kid": self.kid,
        }

    @staticmethod
    def _thumbprint(jwk: Mapping[str, object]) -> str:
        canonical = {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        }
        encoded = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return _b64url(hashlib.sha256(encoded).digest())

    def public_jwks(self) -> Sequence[Mapping[str, object]]:
        return (dict(self._public_jwk),)

    def sign(self, claims: CustomerAuthAssertionClaims) -> str:
        payload = claims.model_dump(mode="json")
        token = jwt.encode(  # pyright: ignore[reportUnknownMemberType]
            payload,
            self._private_key,
            algorithm="ES256",
            headers={"kid": self.kid, "typ": "JWT"},
        )
        return token

    def verify(
        self,
        token: str,
        policy: RelyingPartyTrustPolicy,
    ) -> CustomerAuthAssertionClaims:
        header = cast(dict[str, object], jwt.get_unverified_header(token))
        kid = header.get("kid")
        if kid != self.kid:
            raise UnknownKidError("unknown kid")

        decoded = cast(
            dict[str, object],
            jwt.decode(  # pyright: ignore[reportUnknownMemberType]
                token,
                self._private_key.public_key(),
                algorithms=[policy.allowed_algorithm],
                issuer=policy.issuer,
                audience=policy.audience,
                leeway=policy.clock_skew_seconds,
                options={
                    "require": [
                        "iss",
                        "sub",
                        "aud",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                        "sid",
                        "auth_time",
                        "cnf",
                    ],
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_exp": True,
                },
            ),
        )
        return CustomerAuthAssertionClaims.model_validate(decoded)

    def claims_with_binding(
        self,
        *,
        now: int,
        issuer: str = "urn:xafpay:customer-auth:test",
        audience: str = "urn:xafpay:wallet-api:test",
        **overrides: object,
    ) -> CustomerAuthAssertionClaims:
        data: dict[str, object] = {
            "iss": issuer,
            "sub": "sub_01JTESTOPAQUE000000000001",
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": "jti_01JTESTASSERTION00000001",
            "sid": "sid_01JTESTSESSION000000001",
            "auth_time": now - 10,
            "cnf": ConfirmationClaim(jkt=self.jkt),
        }
        data.update(overrides)
        return CustomerAuthAssertionClaims.model_validate(data)
