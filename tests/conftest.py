from __future__ import annotations

from collections.abc import Callable

import pytest

from xcia.config import RuntimeEnvironment, XciaSettings
from xcia.domain import ConfirmationClaim, CustomerAuthAssertionClaims, RelyingPartyTrustPolicy


@pytest.fixture
def settings() -> XciaSettings:
    return XciaSettings(
        environment=RuntimeEnvironment.TEST,
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
        trusted_origins=("https://wallet.test",),
    )


@pytest.fixture
def policy() -> RelyingPartyTrustPolicy:
    return RelyingPartyTrustPolicy(
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
    )


@pytest.fixture
def claim_factory() -> Callable[..., CustomerAuthAssertionClaims]:
    def make(**overrides: object) -> CustomerAuthAssertionClaims:
        data: dict[str, object] = {
            "iss": "urn:xafpay:customer-auth:test",
            "sub": "sub_01JTESTOPAQUE000000000001",
            "aud": "urn:xafpay:wallet-api:test",
            "iat": 1_800_000_000,
            "nbf": 1_800_000_000,
            "exp": 1_800_000_300,
            "jti": "jti_01JTESTASSERTION00000001",
            "sid": "sid_01JTESTSESSION000000001",
            "auth_time": 1_799_999_990,
            "cnf": ConfirmationClaim(jkt="thumbprint_01JTESTKEY000000001"),
        }
        data.update(overrides)
        return CustomerAuthAssertionClaims.model_validate(data)

    return make
