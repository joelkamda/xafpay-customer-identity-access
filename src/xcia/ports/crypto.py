from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from xcia.domain import CustomerAuthAssertionClaims, RelyingPartyTrustPolicy, SigningKeyReference


class SigningKeyProvider(Protocol):
    def active_signing_key(self) -> SigningKeyReference: ...


class AssertionSigner(Protocol):
    def sign(self, claims: CustomerAuthAssertionClaims) -> str: ...


class AssertionVerifier(Protocol):
    def verify(
        self,
        token: str,
        policy: RelyingPartyTrustPolicy,
    ) -> CustomerAuthAssertionClaims: ...


class JwksProvider(Protocol):
    def public_jwks(self) -> Sequence[Mapping[str, object]]: ...
