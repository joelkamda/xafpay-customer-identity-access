from __future__ import annotations

import hashlib
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import DataError, IntegrityError

from xcia.adapters.postgres import (
    DurablePhoneVerificationChallengeStore,
    DurablePinCredentialStore,
    PhoneVerificationChallengeError,
)
from xcia.persistence import XciaDatabase
from xcia.persistence.schema import (
    CustomerPinCredentialRow,
    CustomerSubjectRow,
    PhoneVerificationChallengeRow,
    SessionRow,
    TrustedDeviceRow,
)

DATABASE_URL = os.environ.get("XCIA2_TEST_DATABASE_URL")
RP = "urn:xafpay:wallet-api:test"
ENV = "test"


@pytest.fixture()
def database() -> XciaDatabase:
    if DATABASE_URL is None or not DATABASE_URL.startswith("postgresql+psycopg://"):
        pytest.fail("XCIA2_TEST_DATABASE_URL must point to disposable PostgreSQL")
    database = XciaDatabase(DATABASE_URL)
    with database.engine.begin() as connection:
        for table in (
            "xcia_trusted_devices",
            "xcia_customer_pin_credentials",
            "xcia_sessions",
            "xcia_customer_subjects",
            "xcia_phone_verification_challenges",
        ):
            connection.exec_driver_sql(f'TRUNCATE "{table}" CASCADE')
    try:
        yield database
    finally:
        database.dispose()


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()

def counts(database: XciaDatabase) -> dict[str, int]:
    with database.session() as session:
        return {
            "subjects": session.scalar(select(func.count()).select_from(CustomerSubjectRow)) or 0,
            "pins": session.scalar(select(func.count()).select_from(CustomerPinCredentialRow)) or 0,
            "devices": session.scalar(select(func.count()).select_from(TrustedDeviceRow)) or 0,
            "sessions": session.scalar(select(func.count()).select_from(SessionRow)) or 0,
        }


def seed_subject(database: XciaDatabase, mapping_digest: str) -> str:
    subject_id = str(uuid.uuid4())
    with database.session() as session:
        with session.begin():
            session.add(
                CustomerSubjectRow(
                    id=subject_id,
                    subject_value=f"sub_test_{uuid.uuid4().hex}",
                    environment=ENV,
                    relying_party=RP,
                    mapping_digest=mapping_digest,
                    created_at=datetime.now(UTC),
                )
            )
    return subject_id

def seed_pin(database: XciaDatabase, subject_id: str, phone_digest: str) -> str:
    credential_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    with database.session() as session:
        with session.begin():
            session.add(
                CustomerPinCredentialRow(
                    credential_id=credential_id,
                    customer_subject_id=subject_id,
                    credential_type="XAFPAY_PIN",
                    phone_lookup_digest=phone_digest,
                    credential_verifier="existing-verifier",
                    credential_version=1,
                    status="active",
                    created_at=now,
                    updated_at=now,
                    failed_attempt_count=0,
                    locked_until=None,
                    last_success_at=None,
                )
            )
    return credential_id

def register_verified(database: XciaDatabase, challenge_id: str, phone_digest: str) -> None:
    now = datetime.now(UTC)
    store = DurablePhoneVerificationChallengeStore(database)
    store.register(
        challenge_id=challenge_id,
        provider="R3ProofProvider",
        bound_phone_digest=phone_digest,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    store.verify(
        challenge_id=challenge_id,
        bound_phone_digest=phone_digest,
        proof="proof",
        now=now + timedelta(seconds=1),
        provider_verify=lambda *_args, **_kwargs: True,
    )
def complete(
    database: XciaDatabase,
    challenge_id: str,
    phone_digest: str,
    mapping_digest: str,
    *,
    sender_jkt: str = "jkt-r3-proof-000001",
    sender_jkt_digest: str | None = None,
    device_digest: str | None = None,
    origin: str = "https://wallet.test",
):
    return DurablePhoneVerificationChallengeStore(database).complete_new_customer(
        challenge_id=challenge_id,
        bound_phone_digest=phone_digest,
        mapping_digest=mapping_digest,
        relying_party=RP,
        environment=ENV,

        verifier="proof-verifier",
        sender_jkt=sender_jkt,
        sender_jkt_digest=sender_jkt_digest or digest("sender-r3"),
        device_digest=device_digest or digest("device-r3"),
        completion_origin=origin,
        now=datetime.now(UTC),
    )


def challenge_row(database: XciaDatabase, challenge_id: str) -> PhoneVerificationChallengeRow:
    with database.session() as session:
        row = session.scalar(
            select(PhoneVerificationChallengeRow).where(
                PhoneVerificationChallengeRow.challenge_id == challenge_id
            )
        )
        assert row is not None
        session.expunge(row)
        return row

def test_fresh_new_customer_completion_preserves_subject_before_dependents(
    database: XciaDatabase,
) -> None:
    phone_digest = digest("fresh-phone")
    mapping_digest = digest("fresh-mapping")
    register_verified(database, "r3_fresh_completion_0001", phone_digest)

    before = counts(database)
    result = complete(database, "r3_fresh_completion_0001", phone_digest, mapping_digest)
    after = counts(database)
    row = challenge_row(database, "r3_fresh_completion_0001")

    assert result.outcome == "new_account_created"
    assert result.subject_id is not None
    assert result.session is not None
    assert after["subjects"] - before["subjects"] == 1
    assert after["pins"] - before["pins"] == 1
    assert after["devices"] - before["devices"] == 1
    assert after["sessions"] - before["sessions"] == 1
    with database.session() as session:
        pin = session.scalar(
            select(CustomerPinCredentialRow).where(
                CustomerPinCredentialRow.customer_subject_id == result.subject_id,
                CustomerPinCredentialRow.status == "active",
            )
        )
        subject = session.get(CustomerSubjectRow, result.subject_id)
        assert pin is not None
        assert subject is not None
        assert pin.customer_subject_id == subject.id

    assert row.state == "consumed"
    assert row.completion_outcome == "new_account_created"
    assert row.completed_subject_id == result.subject_id
    assert row.completed_session_sid == result.session.sid


def test_atomic_rollback_after_subject_flush(database: XciaDatabase) -> None:
    phone_digest = digest("rollback-phone")
    mapping_digest = digest("rollback-mapping")
    register_verified(database, "r3_rollback_0001", phone_digest)
    before = counts(database)

    with pytest.raises(DataError):
        complete(
            database,
            "r3_rollback_0001",

            phone_digest,
            mapping_digest,
            sender_jkt="j" * 300,
        )

    assert counts(database) == before
    row = challenge_row(database, "r3_rollback_0001")
    assert row.state == "verified"
    assert row.consumed_at is None
    assert row.completion_outcome is None
    assert row.completed_subject_id is None
    assert row.completed_session_sid is None

def test_same_context_replay_reuses_completion(database: XciaDatabase) -> None:
    pd, md, cid = digest("same-phone"), digest("same-map"), "r3_same_0001"
    register_verified(database, cid, pd)
    kwargs = dict(
        sender_jkt="jkt-same-proof-0001",
        sender_jkt_digest=digest("sender-same"),
        device_digest=digest("device-same"),
        origin="https://wallet.test/same",
    )
    first = complete(database, cid, pd, md, **kwargs)
    before = counts(database)
    second = complete(database, cid, pd, md, **kwargs)
    assert first.subject_id == second.subject_id
    assert first.session is not None and second.session is not None
    assert first.session.sid == second.session.sid
    assert counts(database) == before

def test_different_context_replay_is_consumed(database: XciaDatabase) -> None:
    pd, md, cid = digest("diff-phone"), digest("diff-map"), "r3_diff_0001"
    register_verified(database, cid, pd)
    complete(
        database, cid, pd, md,
        sender_jkt="jkt-diff-proof-0001",
        sender_jkt_digest=digest("sender-diff"),
        device_digest=digest("device-diff"),
        origin="https://wallet.test/original",
    )
    before = counts(database)
    with pytest.raises(PhoneVerificationChallengeError, match="challenge_consumed"):
        complete(
            database, cid, pd, md,
            sender_jkt="jkt-diff-proof-0001",
            sender_jkt_digest=digest("sender-diff"),
            device_digest=digest("device-diff"),
            origin="https://wallet.test/other",
        )
    assert counts(database) == before

def test_phone_mismatch_never_calls_provider(database: XciaDatabase) -> None:
    store = DurablePhoneVerificationChallengeStore(database)
    good, bad = digest("binding-good"), digest("binding-bad")
    now = datetime.now(UTC)
    store.register(
        challenge_id="r3_mismatch_0001",
        provider="R3ProofProvider",
        bound_phone_digest=good,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    calls = 0
    def provider(*_args, **_kwargs) -> bool:
        nonlocal calls
        calls += 1
        return True
    with pytest.raises(PhoneVerificationChallengeError, match="challenge_phone_mismatch"):
        store.verify(
            challenge_id="r3_mismatch_0001",
            bound_phone_digest=bad,
            proof="proof",
            now=now + timedelta(seconds=1),
            provider_verify=provider,
        )
    assert calls == 0

def test_existing_active_pin_is_not_replaced(database: XciaDatabase) -> None:
    pd = digest("existing-phone")
    sid = seed_subject(database, digest("existing-subject"))
    cid = seed_pin(database, sid, pd)
    register_verified(database, "r3_existing_0001", pd)
    before = counts(database)
    result = complete(database, "r3_existing_0001", pd, digest("other-map"))
    assert result.outcome == "account_already_exists"
    assert counts(database) == before
    with database.session() as session:
        pin = session.get(CustomerPinCredentialRow, cid)
        assert pin is not None
        assert pin.status == "active"
        assert pin.credential_verifier == "existing-verifier"
        assert pin.credential_version == 1

def test_partial_identity_requires_recovery(database: XciaDatabase) -> None:
    pd, md = digest("partial-phone"), digest("partial-map")
    seed_subject(database, md)
    register_verified(database, "r3_partial_0001", pd)
    result = complete(database, "r3_partial_0001", pd, md)
    assert result.outcome == "recovery_required"
    current = counts(database)
    assert current["subjects"] == 1
    assert current["pins"] == current["devices"] == current["sessions"] == 0

def test_active_pin_uniqueness(database: XciaDatabase) -> None:
    pd = digest("unique-pin")
    s1 = seed_subject(database, digest("unique-subject-1"))
    s2 = seed_subject(database, digest("unique-subject-2"))
    store = DurablePinCredentialStore(database)
    store.create_initial(
        subject_id=s1,
        phone_lookup_digest=pd,
        verifier="v1",
        now=datetime.now(UTC),
    )
    with pytest.raises(ValueError, match="active credential already exists"):
        store.create_initial(
            subject_id=s2,
            phone_lookup_digest=pd,
            verifier="v2",
            now=datetime.now(UTC),
        )
def test_concurrent_initial_pin_allows_one(database: XciaDatabase) -> None:
    pd = digest("concurrent-pin")
    subjects = [
        seed_subject(database, digest("concurrent-pin-subject-1")),
        seed_subject(database, digest("concurrent-pin-subject-2")),
    ]
    barrier = threading.Barrier(2)
    def worker(subject_id: str) -> str:
        barrier.wait()
        try:
            DurablePinCredentialStore(database).create_initial(
                subject_id=subject_id,
                phone_lookup_digest=pd,
                verifier=f"v-{subject_id[:8]}",
                now=datetime.now(UTC),
            )
            return "success"
        except (ValueError, IntegrityError):
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, subjects))
    assert sorted(results) == ["rejected", "success"]
    with database.session() as session:
        active = session.scalar(
            select(func.count())
            .select_from(CustomerPinCredentialRow)
            .where(
                CustomerPinCredentialRow.phone_lookup_digest == pd,
                CustomerPinCredentialRow.status == "active",
            )
        )
    assert active == 1


def test_concurrent_challenge_allows_one_active(database: XciaDatabase) -> None:
    pd = digest("concurrent-challenge")
    barrier = threading.Barrier(2)
    ids = ["r3_concurrent_challenge_1", "r3_concurrent_challenge_2"]

    def worker(challenge_id: str) -> str:
        barrier.wait()
        try:
            now = datetime.now(UTC)
            DurablePhoneVerificationChallengeStore(database).register(
                challenge_id=challenge_id,
                provider="R3ProofProvider",
                bound_phone_digest=pd,
                created_at=now,
                expires_at=now + timedelta(minutes=5),
            )
            return "success"
        except IntegrityError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, ids))
    assert results.count("success") >= 1

    with database.session() as session:
        active = session.scalar(
            select(func.count())
            .select_from(PhoneVerificationChallengeRow)
            .where(
                PhoneVerificationChallengeRow.bound_phone_digest == pd,
                PhoneVerificationChallengeRow.state.in_(("issued", "verified")),
            )
        )
    assert active == 1


def test_concurrent_completion_is_one_logical_completion(database: XciaDatabase) -> None:
    pd, md = digest("concurrent-completion"), digest("concurrent-completion-map")
    cid = "r3_concurrent_completion_0001"
    register_verified(database, cid, pd)
    barrier = threading.Barrier(2)
    def worker(_index: int):
        barrier.wait()
        return complete(

            database,
            cid,
            pd,
            md,
            sender_jkt="jkt-concurrent-0001",
            sender_jkt_digest=digest("sender-concurrent"),
            device_digest=digest("device-concurrent"),
            origin="https://wallet.test/concurrent",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, [1, 2]))

    assert all(result.outcome == "new_account_created" for result in results)
    assert results[0].subject_id == results[1].subject_id
    assert results[0].session is not None and results[1].session is not None
    assert results[0].session.sid == results[1].session.sid
    assert counts(database) == {"subjects": 1, "pins": 1, "devices": 1, "sessions": 1}

    row = challenge_row(database, cid)
    assert row.state == "consumed"
    assert row.completion_outcome == "new_account_created"

