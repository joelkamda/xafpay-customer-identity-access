from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select, update

from xcia.domain import (
    CustomerAuthAssertionClaims,
    RelyingPartyTrustPolicy,
    SigningKeyReference,
    SigningKeyState,
)
from xcia.persistence import XciaDatabase
from xcia.persistence.schema import SigningKeyRow


class UnknownSigningKeyError(ValueError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _public_jwk(
    *,
    kid: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> dict[str, Any]:
    numbers = private_key.public_key().public_numbers()
    size = (private_key.curve.key_size + 7) // 8
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(size, "big")),
        "y": _b64url(numbers.y.to_bytes(size, "big")),
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
    }


def _thumbprint(jwk: Mapping[str, object]) -> str:
    canonical = {
        "crv": jwk["crv"],
        "kty": jwk["kty"],
        "x": jwk["x"],
        "y": jwk["y"],
    }
    encoded = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    return _b64url(hashlib.sha256(encoded).digest())


def load_es256_private_key_from_environment(
    environment_variable: str,
) -> ec.EllipticCurvePrivateKey:
    raw = os.environ.get(environment_variable)
    if raw is None or not raw.strip():
        raise ValueError("staging signing authority is not injected")
    loaded = serialization.load_pem_private_key(raw.encode("utf-8"), password=None)
    if not isinstance(loaded, ec.EllipticCurvePrivateKey):
        raise ValueError("injected signing key must be an EC private key")
    if not isinstance(loaded.curve, ec.SECP256R1):
        raise ValueError("injected signing key must use P-256 for ES256")
    return loaded


class StagingEs256KeyProvider:
    def __init__(
        self,
        database: XciaDatabase,
        *,
        issuer: str,
        environment: str,
        injected_private_keys: Mapping[str, ec.EllipticCurvePrivateKey],
    ) -> None:
        self._database = database
        self._issuer = issuer
        self._environment = environment
        self._private_keys = dict(injected_private_keys)

    @classmethod
    def from_environment(
        cls,
        database: XciaDatabase,
        *,
        issuer: str,
        environment: str,
        kid: str,
        private_key_environment_variable: str,
    ) -> StagingEs256KeyProvider:
        private_key = load_es256_private_key_from_environment(
            private_key_environment_variable
        )
        return cls(
            database,
            issuer=issuer,
            environment=environment,
            injected_private_keys={kid: private_key},
        )

    def register_key(
        self,
        *,
        kid: str,
        private_key: ec.EllipticCurvePrivateKey,
        state: SigningKeyState,
        not_before: datetime,
        not_after: datetime | None = None,
    ) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("XCIA2 signing keys must use P-256")
        if not_before.tzinfo is None:
            raise ValueError("not_before must be timezone aware")
        if not_after is not None and not_after.tzinfo is None:
            raise ValueError("not_after must be timezone aware")

        public_jwk = _public_jwk(kid=kid, private_key=private_key)
        now = datetime.now(UTC)
        with self._database.session() as session:
            with session.begin():
                existing = session.get(SigningKeyRow, kid)
                if existing is not None:
                    raise ValueError("kid already exists")
                if state is SigningKeyState.ACTIVE_SIGNING:
                    session.execute(
                        update(SigningKeyRow)
                        .where(
                            SigningKeyRow.environment == self._environment,
                            SigningKeyRow.issuer == self._issuer,
                            SigningKeyRow.state == SigningKeyState.ACTIVE_SIGNING.value,
                        )
                        .values(state=SigningKeyState.VERIFY_ONLY_OVERLAP.value)
                    )
                session.add(
                    SigningKeyRow(
                        kid=kid,
                        environment=self._environment,
                        issuer=self._issuer,
                        algorithm="ES256",
                        state=state.value,
                        public_jwk=public_jwk,
                        not_before=not_before,
                        not_after=not_after,
                        created_at=now,
                    )
                )
        self._private_keys[kid] = private_key

    def activate_key(self, kid: str) -> None:
        with self._database.session() as session:
            with session.begin():
                target = session.get(SigningKeyRow, kid)
                if target is None:
                    raise UnknownSigningKeyError(kid)
                if target.environment != self._environment or target.issuer != self._issuer:
                    raise ValueError("key trust context mismatch")
                session.execute(
                    update(SigningKeyRow)
                    .where(
                        SigningKeyRow.environment == self._environment,
                        SigningKeyRow.issuer == self._issuer,
                        SigningKeyRow.state == SigningKeyState.ACTIVE_SIGNING.value,
                    )
                    .values(state=SigningKeyState.VERIFY_ONLY_OVERLAP.value)
                )
                target.state = SigningKeyState.ACTIVE_SIGNING.value

    def retire_key(self, kid: str) -> None:
        with self._database.session() as session:
            with session.begin():
                target = session.get(SigningKeyRow, kid)
                if target is None:
                    raise UnknownSigningKeyError(kid)
                target.state = SigningKeyState.RETIRED.value

    def active_signing_key(self) -> SigningKeyReference:
        now = datetime.now(UTC)
        with self._database.session() as session:
            rows = list(
                session.scalars(
                    select(SigningKeyRow).where(
                        SigningKeyRow.environment == self._environment,
                        SigningKeyRow.issuer == self._issuer,
                        SigningKeyRow.state == SigningKeyState.ACTIVE_SIGNING.value,
                        SigningKeyRow.not_before <= now,
                    )
                )
            )
        rows = [
            row
            for row in rows
            if row.not_after is None or now < row.not_after
        ]
        if len(rows) != 1:
            raise ValueError("exactly one valid active signing key is required")
        row = rows[0]
        if row.kid not in self._private_keys:
            raise ValueError("active signing key has no externally injected private material")
        return SigningKeyReference(
            kid=row.kid,
            algorithm=row.algorithm,
            state=SigningKeyState(row.state),
        )

    def sign(self, claims: CustomerAuthAssertionClaims) -> str:
        reference = self.active_signing_key()
        private_key = self._private_keys.get(reference.kid)
        if private_key is None:
            raise ValueError("active private key material is unavailable")
        token = jwt.encode(  # pyright: ignore[reportUnknownMemberType]
            claims.model_dump(mode="json"),
            private_key,
            algorithm="ES256",
            headers={"kid": reference.kid, "typ": "JWT"},
        )
        return token

    def verify(
        self,
        token: str,
        policy: RelyingPartyTrustPolicy,
    ) -> CustomerAuthAssertionClaims:
        header = cast(dict[str, object], jwt.get_unverified_header(token))
        kid_value = header.get("kid")
        if not isinstance(kid_value, str):
            raise UnknownSigningKeyError("missing kid")

        now = datetime.now(UTC)
        with self._database.session() as session:
            row = session.get(SigningKeyRow, kid_value)
            if row is None:
                raise UnknownSigningKeyError(kid_value)
            if row.issuer != policy.issuer or row.environment != self._environment:
                raise UnknownSigningKeyError(kid_value)
            allowed_states = {
                SigningKeyState.ACTIVE_SIGNING.value,
                SigningKeyState.VERIFY_ONLY_OVERLAP.value,
            }
            if row.state not in allowed_states:
                raise UnknownSigningKeyError(kid_value)
            if now < row.not_before or (row.not_after is not None and now >= row.not_after):
                raise UnknownSigningKeyError(kid_value)
            jwk = dict(row.public_jwk)

        if jwk.get("alg") != "ES256" or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            raise ValueError("stored public key metadata is invalid")

        x_value = jwk.get("x")
        y_value = jwk.get("y")
        if not isinstance(x_value, str) or not isinstance(y_value, str):
            raise ValueError("stored public JWK coordinates are invalid")
        x = int.from_bytes(_b64url_decode(x_value), "big")
        y = int.from_bytes(_b64url_decode(y_value), "big")
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

        decoded = cast(
            dict[str, object],
            jwt.decode(  # pyright: ignore[reportUnknownMemberType]
                token,
                public_key,
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

    def public_jwks(self) -> Sequence[Mapping[str, object]]:
        now = datetime.now(UTC)
        with self._database.session() as session:
            rows = list(
                session.scalars(
                    select(SigningKeyRow).where(
                        SigningKeyRow.environment == self._environment,
                        SigningKeyRow.issuer == self._issuer,
                        SigningKeyRow.state.in_(
                            [
                                SigningKeyState.ACTIVE_SIGNING.value,
                                SigningKeyState.VERIFY_ONLY_OVERLAP.value,
                            ]
                        ),
                        SigningKeyRow.not_before <= now,
                    )
                )
            )
        public: list[Mapping[str, object]] = []
        for row in rows:
            if row.not_after is not None and now >= row.not_after:
                continue
            jwk = dict(row.public_jwk)
            jwk.pop("d", None)
            public.append(jwk)
        return tuple(public)

    def active_jkt(self) -> str:
        reference = self.active_signing_key()
        for jwk in self.public_jwks():
            if jwk.get("kid") == reference.kid:
                return _thumbprint(jwk)
        raise ValueError("active public key projection is unavailable")
