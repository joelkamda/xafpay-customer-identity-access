from __future__ import annotations

from datetime import UTC, datetime

from xcia.adapters import DurablePinCredentialStore, DurableSubjectStore
from xcia.crypto import CredentialSecrets, create_verifier
from xcia.persistence import XciaDatabase


def test_credential_is_verifier_only_and_recovery_versions_it(database: XciaDatabase) -> None:
    now = datetime.now(UTC)
    subject_store = DurableSubjectStore(database)
    subject = subject_store.create_or_lookup(
        authentication_handle="authref_" + "a" * 64,
        relying_party="urn:xafpay:wallet-api:test",
        environment="test",
        now=now,
    )
    secrets = CredentialSecrets(b"xcia3 deterministic test credential root secret")
    store = DurablePinCredentialStore(database)
    phone_digest = secrets.opaque_digest("xcia3/phone-lookup", "+2348012345678")
    first = store.replace(
        subject_id=subject_store.subject_id(subject),
        phone_lookup_digest=phone_digest,
        verifier=create_verifier("123456", secrets),
        now=now,
    )
    second = store.replace(
        subject_id=subject_store.subject_id(subject),
        phone_lookup_digest=phone_digest,
        verifier=create_verifier("654321", secrets),
        now=now,
    )
    assert first.credential_version == 1
    assert second.credential_version == 2
    assert "+2348012345678" not in second.phone_lookup_digest
    assert "654321" not in second.credential_verifier
