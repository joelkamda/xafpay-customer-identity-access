from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from xcia.adapters import DurableSessionStore, DurableSubjectStore
from xcia.config import RuntimeEnvironment, XciaSettings
from xcia.crypto import StagingEs256KeyProvider
from xcia.domain import (
    DurableSessionSnapshot,
    RelyingPartyTrustPolicy,
    SigningKeyState,
    TrustedAuthenticationContext,
)
from xcia.persistence import XciaDatabase
from xcia.services import DurableAssertionIssuer, SenderConstraintError, UntrustedSessionError


def _setup(
    database: XciaDatabase,
) -> tuple[DurableSessionSnapshot, str, StagingEs256KeyProvider, DurableAssertionIssuer]:
    subject = DurableSubjectStore(database).create_or_lookup(
        authentication_handle="authref_11223344556677889900aabbccddeeff",
        relying_party="wallet",
        environment="test",
    )
    sender_jkt = "senderthumbprint_0123456789abcdef"
    context = TrustedAuthenticationContext(
        subject=subject,
        auth_time=datetime.now(UTC) - timedelta(seconds=5),
        sender_jkt=sender_jkt,
        trust_source="trusted-test-harness",
    )
    sessions = DurableSessionStore(database)
    snapshot = sessions.create_authenticated_session(context)

    provider = StagingEs256KeyProvider(
        database,
        issuer="urn:xafpay:customer-auth:test",
        environment="test",
        injected_private_keys={},
    )
    provider.register_key(
        kid="kid-issuance-0001",
        private_key=ec.generate_private_key(ec.SECP256R1()),
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=datetime.now(UTC) - timedelta(seconds=1),
    )
    settings = XciaSettings(
        environment=RuntimeEnvironment.TEST,
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
        trusted_origins=("https://wallet.test",),
    )
    issuer = DurableAssertionIssuer(settings, sessions, provider)
    return snapshot, sender_jkt, provider, issuer


def test_durable_assertion_issuance_has_required_claims(database: XciaDatabase) -> None:
    snapshot, sender_jkt, provider, issuer = _setup(database)
    token = issuer.issue(sid=snapshot.sid, sender_jkt=sender_jkt)
    policy = RelyingPartyTrustPolicy(
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
    )
    claims = provider.verify(token, policy)

    assert claims.sub == snapshot.sub
    assert claims.sid == snapshot.sid
    assert claims.cnf.jkt == sender_jkt
    assert claims.exp - claims.iat == 300
    assert claims.jti.startswith("jti_")


def test_assertion_issuance_rejects_sender_mismatch(database: XciaDatabase) -> None:
    snapshot, _, _, issuer = _setup(database)
    with pytest.raises(SenderConstraintError):
        issuer.issue(
            sid=snapshot.sid,
            sender_jkt="wrong_sender_thumbprint_01234567",
        )


def test_revoked_session_cannot_mint_assertion(database: XciaDatabase) -> None:
    snapshot, sender_jkt, _, issuer = _setup(database)
    issuer.sessions.revoke_session(snapshot.sid)
    with pytest.raises(UntrustedSessionError):
        issuer.issue(sid=snapshot.sid, sender_jkt=sender_jkt)
def test_assertion_jti_is_unique_per_issuance(database: XciaDatabase) -> None:
    snapshot, sender_jkt, provider, issuer = _setup(database)
    policy = RelyingPartyTrustPolicy(
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
    )
    first = provider.verify(
        issuer.issue(sid=snapshot.sid, sender_jkt=sender_jkt),
        policy,
    )
    second = provider.verify(
        issuer.issue(sid=snapshot.sid, sender_jkt=sender_jkt),
        policy,
    )
    assert first.jti != second.jti


def test_assertion_issuance_rejects_missing_sender_constraint(
    database: XciaDatabase,
) -> None:
    snapshot, _, _, issuer = _setup(database)
    with pytest.raises(SenderConstraintError):
        issuer.issue(sid=snapshot.sid, sender_jkt="")
