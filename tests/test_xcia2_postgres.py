from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from xcia.adapters import (
    DurableRefreshFamilyStore,
    DurableSessionStore,
    DurableSubjectStore,
    PostgresReplayDefense,
    PostgresRevocationAuthority,
    RefreshReuseDetected,
)
from xcia.domain import (
    DurableSessionSnapshot,
    ExternalCustomerSubject,
    ReplayDecision,
    RevocationDecision,
    TrustedAuthenticationContext,
)
from xcia.persistence import XciaDatabase
from xcia.persistence.schema import RefreshFamilyRow


def _subject(database: XciaDatabase) -> ExternalCustomerSubject:
    return DurableSubjectStore(database).create_or_lookup(
        authentication_handle="authref_0123456789abcdef0123456789abcdef",
        relying_party="wallet",
        environment="test",
        now=datetime.now(UTC),
    )


def _session(database: XciaDatabase) -> DurableSessionSnapshot:
    subject = _subject(database)
    moment = datetime.now(UTC)
    context = TrustedAuthenticationContext(
        subject=subject,
        auth_time=moment,
        sender_jkt="thumbprint_0123456789abcdef",
        trust_source="trusted-test-harness",
    )
    return DurableSessionStore(database).create_authenticated_session(
        context,
        now=moment,
    )


def test_durable_subject_create_lookup_and_pairwise_scope(database: XciaDatabase) -> None:
    store = DurableSubjectStore(database)
    first = store.create_or_lookup(
        authentication_handle="authref_0123456789abcdef0123456789abcdef",
        relying_party="wallet",
        environment="test",
    )
    second = store.create_or_lookup(
        authentication_handle="authref_0123456789abcdef0123456789abcdef",
        relying_party="wallet",
        environment="test",
    )
    other_rp = store.create_or_lookup(
        authentication_handle="authref_0123456789abcdef0123456789abcdef",
        relying_party="another-rp",
        environment="test",
    )

    assert first == second
    assert first.value != other_rp.value
    assert "@" not in first.value


@pytest.mark.parametrize(
    "handle",
    [
        "customer@example.com",
        "+237600000000",
        "John Doe",
        "authref_short",
    ],
)
def test_subject_mapping_rejects_pii_shaped_or_weak_handle(
    database: XciaDatabase,
    handle: str,
) -> None:
    with pytest.raises(ValueError):
        DurableSubjectStore(database).create_or_lookup(
            authentication_handle=handle,
            relying_party="wallet",
            environment="test",
        )


def test_session_idle_and_absolute_expiry(database: XciaDatabase) -> None:
    snapshot = _session(database)
    store = DurableSessionStore(database)
    assert store.require_active_session(
        snapshot.sid,
        at=snapshot.created_at + timedelta(minutes=14),
    ).sid == snapshot.sid

    with pytest.raises(ValueError):
        store.require_active_session(
            snapshot.sid,
            at=snapshot.created_at + timedelta(minutes=16),
        )

    second = _session_with_unique_subject(database)
    with pytest.raises(ValueError):
        store.require_active_session(
            second.sid,
            at=second.created_at + timedelta(hours=8, seconds=1),
        )


def _session_with_unique_subject(database: XciaDatabase) -> DurableSessionSnapshot:
    subject = DurableSubjectStore(database).create_or_lookup(
        authentication_handle="authref_abcdef0123456789abcdef0123456789",
        relying_party="wallet",
        environment="test",
    )
    moment = datetime.now(UTC)
    context = TrustedAuthenticationContext(
        subject=subject,
        auth_time=moment,
        sender_jkt="thumbprint_abcdef0123456789",
        trust_source="trusted-test-harness",
    )
    return DurableSessionStore(database).create_authenticated_session(
        context,
        now=moment,
    )


def test_session_touch_extends_idle_but_not_absolute(database: XciaDatabase) -> None:
    snapshot = _session(database)
    touched_at = snapshot.created_at + timedelta(minutes=10)
    touched = DurableSessionStore(database).touch(snapshot.sid, at=touched_at)

    assert touched.last_activity == touched_at
    assert touched.idle_expires_at == touched_at + timedelta(minutes=15)
    assert touched.absolute_expires_at == snapshot.absolute_expires_at


def test_session_restart_and_revocation_durability(
    database: XciaDatabase,
    xcia2_database_url: str,
) -> None:
    snapshot = _session(database)
    database.dispose()

    restarted = XciaDatabase(xcia2_database_url)
    store = DurableSessionStore(restarted)
    assert store.get_session(snapshot.sid) is not None
    store.revoke_session(snapshot.sid, at=snapshot.created_at + timedelta(minutes=1))
    restarted.dispose()

    restarted_again = XciaDatabase(xcia2_database_url)
    decision = PostgresRevocationAuthority(restarted_again).session_decision(snapshot.sid)
    restarted_again.dispose()
    assert decision is RevocationDecision.DENY_REVOKED


def test_refresh_rotation_reuse_revokes_family_and_session(
    database: XciaDatabase,
) -> None:
    snapshot = _session(database)
    store = DurableRefreshFamilyStore(database)
    first = store.issue(snapshot, now=snapshot.created_at + timedelta(minutes=1))
    second = store.rotate(first, now=snapshot.created_at + timedelta(minutes=2))

    assert second.family_id == first.family_id
    assert second.generation == 1
    assert second.secret != first.secret

    with pytest.raises(RefreshReuseDetected):
        store.rotate(first, now=snapshot.created_at + timedelta(minutes=3))

    authority = PostgresRevocationAuthority(database)
    assert authority.refresh_family_decision(first.family_id) is RevocationDecision.DENY_REVOKED
    assert authority.session_decision(snapshot.sid) is RevocationDecision.DENY_REVOKED



def test_explicit_refresh_family_revocation_terminates_session(
    database: XciaDatabase,
) -> None:
    snapshot = _session(database)
    store = DurableRefreshFamilyStore(database)
    material = store.issue(snapshot)
    store.revoke(material.family_id)

    authority = PostgresRevocationAuthority(database)
    assert authority.refresh_family_decision(material.family_id) is RevocationDecision.DENY_REVOKED
    assert authority.session_decision(snapshot.sid) is RevocationDecision.DENY_REVOKED


def test_refresh_family_restart_durability(
    database: XciaDatabase,
    xcia2_database_url: str,
) -> None:
    snapshot = _session(database)
    material = DurableRefreshFamilyStore(database).issue(snapshot)
    database.dispose()

    restarted = XciaDatabase(xcia2_database_url)
    try:
        rotated = DurableRefreshFamilyStore(restarted).rotate(material)
        assert rotated.family_id == material.family_id
        assert rotated.generation == material.generation + 1
    finally:
        restarted.dispose()


def test_refresh_secret_is_not_persisted(database: XciaDatabase) -> None:
    snapshot = _session(database)
    material = DurableRefreshFamilyStore(database).issue(snapshot)
    with database.session() as session:
        row = session.get(RefreshFamilyRow, material.family_id)
        assert row is not None
        assert row.verifier_digest != material.secret
        assert len(row.verifier_digest) == 64


def test_replay_first_use_duplicate_and_restart(
    database: XciaDatabase,
    xcia2_database_url: str,
) -> None:
    first = PostgresReplayDefense(
        database,
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
    )
    assert first.evaluate_jti("jti_0123456789abcdef0123456789abcdef") is ReplayDecision.ALLOW
    assert (
        first.evaluate_jti("jti_0123456789abcdef0123456789abcdef")
        is ReplayDecision.DENY_REPLAY
    )

    database.dispose()
    restarted = XciaDatabase(xcia2_database_url)
    second = PostgresReplayDefense(
        restarted,
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
    )
    assert (
        second.evaluate_jti("jti_0123456789abcdef0123456789abcdef")
        is ReplayDecision.DENY_REPLAY
    )
    restarted.dispose()


def test_multi_process_shared_state(
    database: XciaDatabase,
    xcia2_database_url: str,
) -> None:
    snapshot = _session(database)
    second_process = XciaDatabase(xcia2_database_url)
    try:
        visible = DurableSessionStore(second_process).get_session(snapshot.sid)
        assert visible is not None
        assert visible.sub == snapshot.sub
    finally:
        second_process.dispose()


def test_only_nonreversible_refresh_verifier_column_exists(database: XciaDatabase) -> None:
    columns = RefreshFamilyRow.__table__.columns.keys()
    assert "verifier_digest" in columns
    assert "secret" not in columns
    assert "raw_secret" not in columns


def test_replay_identity_is_issuer_audience_scoped(database: XciaDatabase) -> None:
    jti = "jti_scope_0123456789abcdef01234567"
    wallet = PostgresReplayDefense(
        database,
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
    )
    other = PostgresReplayDefense(
        database,
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:another-api:test",
    )
    assert wallet.evaluate_jti(jti) is ReplayDecision.ALLOW
    assert other.evaluate_jti(jti) is ReplayDecision.ALLOW
def test_replay_cleanup_allows_bounded_retention(database: XciaDatabase) -> None:
    replay = PostgresReplayDefense(
        database,
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
        retention_seconds=1,
    )
    jti = "jti_cleanup_0123456789abcdef012345"
    assert replay.evaluate_jti(jti) is ReplayDecision.ALLOW
    assert replay.purge_expired(at=datetime.now(UTC) + timedelta(seconds=2)) == 1
    assert replay.evaluate_jti(jti) is ReplayDecision.ALLOW
