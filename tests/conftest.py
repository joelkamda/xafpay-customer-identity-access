from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import pytest
from sqlalchemy import text

from xcia.config import RuntimeEnvironment, XciaSettings
from xcia.domain import ConfirmationClaim, CustomerAuthAssertionClaims, RelyingPartyTrustPolicy
from xcia.persistence import XciaDatabase


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


@pytest.fixture(scope="session")
def xcia2_database_url() -> str:
    value = os.environ.get("XCIA2_TEST_DATABASE_URL")
    if value is None or not value.startswith("postgresql+psycopg://"):
        pytest.fail("XCIA2_TEST_DATABASE_URL must point to disposable PostgreSQL")
    return value


@pytest.fixture
def database(xcia2_database_url: str) -> Iterator[XciaDatabase]:
    database = XciaDatabase(xcia2_database_url)
    table_order = (
        "xcia_trusted_devices",
        "xcia_authentication_buckets",
        "xcia_customer_pin_credentials",
        "xcia_security_events",
        "xcia_replay_jtis",
        "xcia_refresh_families",
        "xcia_sessions",
        "xcia_signing_keys",
        "xcia_customer_subjects",
    )
    with database.engine.begin() as connection:
        for table_name in table_order:
            connection.execute(text(f"DELETE FROM {table_name}"))
    try:
        yield database
    finally:
        database.dispose()
