from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from xcia.adapters import (
    DeterministicFakePhoneVerificationAdapter,
    DurableAuthenticationControlStore,
    DurablePinCredentialStore,
    DurableSessionStore,
    DurableSubjectStore,
    SecurityEventStore,
)
from xcia.config import RuntimeEnvironment, Xcia3RuntimeSettings, XciaSettings
from xcia.crypto import CredentialSecrets
from xcia.persistence import XciaDatabase
from xcia.services import AuthenticationDenied, CustomerPinAuthenticationService, PhoneProofRequired


def make_service(
    database: XciaDatabase,
    settings: XciaSettings,
) -> tuple[CustomerPinAuthenticationService, DeterministicFakePhoneVerificationAdapter]:
    secret = b"xcia3 deterministic test credential root secret"
    provider = DeterministicFakePhoneVerificationAdapter(
        environment=RuntimeEnvironment.TEST,
        secret=secret,
    )
    return (
        CustomerPinAuthenticationService(
            settings=settings,
            xcia3=Xcia3RuntimeSettings(credential_secret_env="XCIA3_TEST_SECRET"),
            secrets=CredentialSecrets(secret),
            phone_provider=provider,
            subjects=DurableSubjectStore(database),
            sessions=DurableSessionStore(database),
            credentials=DurablePinCredentialStore(database),
            controls=DurableAuthenticationControlStore(database),
            events=SecurityEventStore(database),
        ),
        provider,
    )


def enroll(
    service: CustomerPinAuthenticationService,
    provider: DeterministicFakePhoneVerificationAdapter,
    *,
    now: datetime,
) -> None:
    challenge = service.start_phone_verification("+2348012345678", now=now)
    service.enroll(
        phone="+2348012345678",
        challenge_id=challenge,
        proof=provider.expected_proof(challenge),
        pin="123456",
        sender_jkt="thumbprint_01JTESTKEY000000001",
        device_id="test-device-one",
        now=now,
    )


def test_enrollment_login_step_up_and_recovery(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    service, provider = make_service(database, settings)
    now = datetime.now(UTC)
    enroll(service, provider, now=now)
    result = service.login(
        phone="+2348012345678",
        pin="123456",
        sender_jkt="thumbprint_01JTESTKEY000000001",
        device_id="test-device-one",
        ip_address="127.0.0.1",
        now=now,
    )
    assert result.session.sender_jkt == "thumbprint_01JTESTKEY000000001"
    with pytest.raises(PhoneProofRequired):
        service.login(
            phone="+2348012345678",
            pin="123456",
            sender_jkt="thumbprint_01JTESTKEY000000001",
            device_id="new-device",
            ip_address="127.0.0.1",
            now=now,
        )
    recovery = service.start_phone_verification("+2348012345678", now=now)
    service.recover(
        phone="+2348012345678",
        challenge_id=recovery,
        proof=provider.expected_proof(recovery),
        new_pin="654321",
        sender_jkt="thumbprint_01JTESTKEY000000001",
        device_id="test-device-one",
        now=now,
    )
    with pytest.raises(AuthenticationDenied):
        service.login(
            phone="+2348012345678",
            pin="123456",
            sender_jkt="thumbprint_01JTESTKEY000000001",
            device_id="test-device-one",
            ip_address="127.0.0.1",
            now=now,
        )
    assert service.login(
        phone="+2348012345678",
        pin="654321",
        sender_jkt="thumbprint_01JTESTKEY000000001",
        device_id="test-device-one",
        ip_address="127.0.0.1",
        now=now,
    ).session.sid.startswith("sid_")


def test_fake_provider_expiry_replay_and_production_denial() -> None:
    secret = b"xcia3 deterministic test credential root secret"
    now = datetime.now(UTC)
    provider = DeterministicFakePhoneVerificationAdapter(
        environment=RuntimeEnvironment.TEST,
        secret=secret,
        ttl_seconds=30,
    )
    challenge = provider.begin("+2348012345678", now=now)
    proof = provider.expected_proof(challenge.challenge_id)
    assert provider.verify(challenge.challenge_id, proof, now=now)
    assert not provider.verify(challenge.challenge_id, proof, now=now)
    expired = provider.begin("+2348012345678", now=now)
    assert not provider.verify(
        expired.challenge_id,
        provider.expected_proof(expired.challenge_id),
        now=now + timedelta(seconds=30),
    )
    with pytest.raises(ValueError, match="forbidden"):
        DeterministicFakePhoneVerificationAdapter(
            environment=RuntimeEnvironment.PRODUCTION,
            secret=secret,
        )
