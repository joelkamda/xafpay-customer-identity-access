from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select

from tests.support.crypto_harness import EphemeralEs256Harness
from xcia.crypto import (
    StagingEs256KeyProvider,
    UnknownSigningKeyError,
    load_es256_private_key_from_environment,
)
from xcia.domain import RelyingPartyTrustPolicy, SigningKeyState
from xcia.persistence import XciaDatabase
from xcia.persistence.schema import SigningKeyRow
from xcia.services import JwksPresenter


def _provider(database: XciaDatabase) -> StagingEs256KeyProvider:
    return StagingEs256KeyProvider(
        database,
        issuer="urn:xafpay:customer-auth:test",
        environment="test",
        injected_private_keys={},
    )


def test_staging_signing_provider_and_public_jwks(database: XciaDatabase) -> None:
    provider = _provider(database)
    key = ec.generate_private_key(ec.SECP256R1())
    provider.register_key(
        kid="kid-test-0001",
        private_key=key,
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=datetime.now(UTC) - timedelta(seconds=1),
    )

    reference = provider.active_signing_key()
    jwks = tuple(provider.public_jwks())
    document = JwksPresenter(provider).document()

    assert reference.kid == "kid-test-0001"
    assert len(jwks) == 1
    assert document["keys"][0]["kid"] == reference.kid
    assert jwks[0]["kid"] == reference.kid
    assert jwks[0]["alg"] == "ES256"
    assert "d" not in jwks[0]


def test_signing_key_database_contains_public_material_only(database: XciaDatabase) -> None:
    provider = _provider(database)
    key = ec.generate_private_key(ec.SECP256R1())
    provider.register_key(
        kid="kid-test-0002",
        private_key=key,
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=datetime.now(UTC) - timedelta(seconds=1),
    )
    with database.session() as session:
        row = session.scalar(select(SigningKeyRow).where(SigningKeyRow.kid == "kid-test-0002"))
        assert row is not None
        assert "d" not in row.public_jwk
        assert "private" not in " ".join(row.public_jwk.keys()).lower()


def test_key_rotation_keeps_verification_overlap(database: XciaDatabase) -> None:
    provider = _provider(database)
    first_key = ec.generate_private_key(ec.SECP256R1())
    second_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)

    provider.register_key(
        kid="kid-rotation-0001",
        private_key=first_key,
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=now - timedelta(seconds=1),
    )

    harness = EphemeralEs256Harness()
    claims = harness.claims_with_binding(now=int(now.timestamp()))
    first_token = provider.sign(claims)

    provider.register_key(
        kid="kid-rotation-0002",
        private_key=second_key,
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=now - timedelta(seconds=1),
    )
    policy = RelyingPartyTrustPolicy(
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
    )

    verified = provider.verify(first_token, policy)
    assert verified.jti == claims.jti
    assert provider.active_signing_key().kid == "kid-rotation-0002"

    provider.retire_key("kid-rotation-0001")
    with pytest.raises(UnknownSigningKeyError):
        provider.verify(first_token, policy)


def test_unknown_kid_denied(database: XciaDatabase) -> None:
    provider = _provider(database)
    harness = EphemeralEs256Harness(kid="unknown-kid")
    claims = harness.claims_with_binding(now=int(datetime.now(UTC).timestamp()))
    policy = RelyingPartyTrustPolicy(
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
    )
    with pytest.raises(UnknownSigningKeyError):
        provider.verify(harness.sign(claims), policy)
def test_signing_secret_injection_fails_closed_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XCIA2_TEST_SIGNING_KEY", raising=False)
    with pytest.raises(ValueError):
        load_es256_private_key_from_environment("XCIA2_TEST_SIGNING_KEY")


def test_signing_secret_can_be_injected_without_database_persistence(
    database: XciaDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    monkeypatch.setenv("XCIA2_TEST_SIGNING_KEY", pem)
    provider = StagingEs256KeyProvider.from_environment(
        database,
        issuer="urn:xafpay:customer-auth:test",
        environment="test",
        kid="kid-env-0001",
        private_key_environment_variable="XCIA2_TEST_SIGNING_KEY",
    )
    provider.register_key(
        kid="kid-env-0001",
        private_key=load_es256_private_key_from_environment("XCIA2_TEST_SIGNING_KEY"),
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert provider.active_signing_key().kid == "kid-env-0001"
    with database.session() as session:
        row = session.get(SigningKeyRow, "kid-env-0001")
        assert row is not None
        assert "d" not in row.public_jwk
