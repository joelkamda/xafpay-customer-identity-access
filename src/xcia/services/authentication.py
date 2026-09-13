from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from xcia.adapters import (
    DurableAuthenticationControlStore,
    DurablePinCredentialStore,
    DurableSessionStore,
    DurableSubjectStore,
    SecurityEventStore,
)
from xcia.config import Xcia3RuntimeSettings, XciaSettings
from xcia.crypto import CredentialSecrets, create_verifier, normalize_phone, verify_pin
from xcia.domain import (
    DurableSessionSnapshot,
    ExternalCustomerSubject,
    TrustedAuthenticationContext,
)
from xcia.persistence.schema import CustomerPinCredentialRow
from xcia.ports import PhoneVerificationProviderPort


class AuthenticationDenied(ValueError):
    """Enumeration-safe authentication denial for public BFF composition."""


class PhoneProofRequired(AuthenticationDenied):
    """A valid phone-possession proof is required before trust is established."""


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    session: DurableSessionSnapshot
    subject_id: str


@dataclass(frozen=True, slots=True)
class CustomerPinAuthenticationService:
    settings: XciaSettings
    xcia3: Xcia3RuntimeSettings
    secrets: CredentialSecrets
    phone_provider: PhoneVerificationProviderPort
    subjects: DurableSubjectStore
    sessions: DurableSessionStore
    credentials: DurablePinCredentialStore
    controls: DurableAuthenticationControlStore
    events: SecurityEventStore

    def start_phone_verification(self, phone: str, *, now: datetime) -> str:
        normalized_phone = normalize_phone(phone)
        return self.phone_provider.begin(normalized_phone, now=now).challenge_id

    def verify_phone_proof(self, challenge_id: str, proof: str, *, now: datetime) -> None:
        self._require_phone_proof(challenge_id, proof, now)

    def enroll(
        self,
        *,
        phone: str,
        challenge_id: str,
        proof: str,
        pin: str,
        sender_jkt: str,
        device_id: str,
        now: datetime | None = None,
    ) -> AuthenticationResult:
        moment = self._moment(now)
        normalized_phone = normalize_phone(phone)
        self._require_phone_proof(challenge_id, proof, moment)
        subject = self.subjects.create_or_lookup(
            authentication_handle=self._authref(normalized_phone),
            relying_party=self.settings.audience,
            environment=self.settings.environment.value,
            now=moment,
        )
        subject_id = self.subjects.subject_id(subject)
        self.credentials.replace(
            subject_id=subject_id,
            phone_lookup_digest=self._phone_digest(normalized_phone),
            verifier=create_verifier(pin, self.secrets),
            now=moment,
        )
        self.controls.trust_device(subject_id, self._device_digest(device_id), now=moment)
        result = self._establish_session(
            subject,
            subject_id,
            sender_jkt,
            moment,
            "xcia3_pin_enrollment",
        )
        self.events.record(
            event_type="xcia3_pin_enrollment_succeeded",
            detail="verifier-only credential enrolled after phone proof",
            subject_value=subject.value,
            sid=result.session.sid,
            occurred_at=moment,
        )
        return result

    def login(
        self,
        *,
        phone: str,
        pin: str,
        sender_jkt: str,
        device_id: str,
        ip_address: str,
        step_up_challenge_id: str | None = None,
        step_up_proof: str | None = None,
        now: datetime | None = None,
    ) -> AuthenticationResult:
        moment = self._moment(now)
        normalized_phone = normalize_phone(phone)
        phone_digest = self._phone_digest(normalized_phone)
        scopes = self._scopes(phone_digest, device_id, ip_address)
        credential = self.credentials.find_by_phone_digest(phone_digest)
        if credential is None or self._is_locked(credential, scopes, moment):
            self._record_failure(credential, scopes, moment)
            raise AuthenticationDenied("authentication_failed")
        if not verify_pin(pin, credential.credential_verifier, self.secrets):
            self._record_failure(credential, scopes, moment)
            raise AuthenticationDenied("authentication_failed")

        subject = self.subjects.get_by_id(credential.customer_subject_id)
        if subject is None:
            self._record_failure(credential, scopes, moment)
            raise AuthenticationDenied("authentication_failed")
        device_digest = self._device_digest(device_id)
        if not self.controls.is_trusted_device(credential.customer_subject_id, device_digest):
            if step_up_challenge_id is None or step_up_proof is None:
                raise PhoneProofRequired("authentication_failed")
            self._require_phone_proof(step_up_challenge_id, step_up_proof, moment)
            self.controls.trust_device(credential.customer_subject_id, device_digest, now=moment)

        self.credentials.record_success(credential, now=moment)
        for scope_type, scope_digest in scopes:
            self.controls.clear_failures(scope_type, scope_digest, now=moment)
        result = self._establish_session(
            subject,
            credential.customer_subject_id,
            sender_jkt,
            moment,
            "xcia3_pin_login",
        )
        self.events.record(
            event_type="xcia3_pin_login_succeeded",
            detail="PIN authentication completed without credential or identifier disclosure",
            subject_value=subject.value,
            sid=result.session.sid,
            occurred_at=moment,
        )
        return result

    def recover(
        self,
        *,
        phone: str,
        challenge_id: str,
        proof: str,
        new_pin: str,
        sender_jkt: str,
        device_id: str,
        now: datetime | None = None,
    ) -> AuthenticationResult:
        moment = self._moment(now)
        normalized_phone = normalize_phone(phone)
        phone_digest = self._phone_digest(normalized_phone)
        credential = self.credentials.find_by_phone_digest(phone_digest)
        self._require_phone_proof(challenge_id, proof, moment)
        if credential is None:
            raise AuthenticationDenied("authentication_failed")
        subject = self.subjects.get_by_id(credential.customer_subject_id)
        if subject is None:
            raise AuthenticationDenied("authentication_failed")
        self.sessions.revoke_subject_sessions(subject.value, at=moment)
        self.credentials.replace(
            subject_id=credential.customer_subject_id,
            phone_lookup_digest=phone_digest,
            verifier=create_verifier(new_pin, self.secrets),
            now=moment,
        )
        self.controls.trust_device(
            credential.customer_subject_id,
            self._device_digest(device_id),
            now=moment,
        )
        result = self._establish_session(
            subject,
            credential.customer_subject_id,
            sender_jkt,
            moment,
            "xcia3_pin_recovery",
        )
        self.events.record(
            event_type="xcia3_pin_recovery_succeeded",
            detail="verified phone recovery replaced credential and reestablished session",
            subject_value=subject.value,
            sid=result.session.sid,
            occurred_at=moment,
        )
        return result

    def _establish_session(
        self,
        subject: ExternalCustomerSubject,
        subject_id: str,
        sender_jkt: str,
        moment: datetime,
        trust_source: str,
    ) -> AuthenticationResult:
        context = TrustedAuthenticationContext(
            subject=subject,
            auth_time=moment,
            sender_jkt=sender_jkt,
            trust_source=trust_source,
        )
        return AuthenticationResult(
            session=self.sessions.create_authenticated_session(context, now=moment),
            subject_id=subject_id,
        )

    def _is_locked(
        self,
        credential: CustomerPinCredentialRow,
        scopes: tuple[tuple[str, str], ...],
        now: datetime,
    ) -> bool:
        if credential.locked_until is not None and now < credential.locked_until:
            return True
        return any(self.controls.is_locked(kind, digest, now=now) for kind, digest in scopes)

    def _record_failure(
        self,
        credential: CustomerPinCredentialRow | None,
        scopes: tuple[tuple[str, str], ...],
        now: datetime,
    ) -> None:
        if credential is not None:
            self.credentials.record_failure(
                credential,
                now=now,
                lockout_after_failures=self.xcia3.lockout_after_failures,
                lockout_seconds=self.xcia3.lockout_seconds,
            )
        for scope_type, scope_digest in scopes:
            self.controls.record_failure(
                scope_type,
                scope_digest,
                now=now,
                lockout_after_failures=self.xcia3.lockout_after_failures,
                lockout_seconds=self.xcia3.lockout_seconds,
            )
        self.events.record(
            event_type="xcia3_pin_login_denied",
            detail="authentication denied without credential or identifier disclosure",
            occurred_at=now,
        )

    def _require_phone_proof(self, challenge_id: str, proof: str, now: datetime) -> None:
        if not self.phone_provider.verify(challenge_id, proof, now=now):
            raise AuthenticationDenied("authentication_failed")

    def _phone_digest(self, phone: str) -> str:
        return self.secrets.opaque_digest("xcia3/phone-lookup", phone)

    def _authref(self, phone: str) -> str:
        return f"authref_{self.secrets.opaque_digest('xcia3/phone-authref', phone)}"

    def _device_digest(self, device_id: str) -> str:
        if not device_id or len(device_id) > 512:
            raise AuthenticationDenied("authentication_failed")
        return self.secrets.opaque_digest("xcia3/device-scope", device_id)

    def _scopes(self, account: str, device_id: str, ip_address: str) -> tuple[tuple[str, str], ...]:
        if not ip_address or len(ip_address) > 128:
            raise AuthenticationDenied("authentication_failed")
        return (
            ("account", account),
            ("device", self._device_digest(device_id)),
            ("ip", self.secrets.opaque_digest("xcia3/ip-scope", ip_address)),
        )

    @staticmethod
    def _moment(now: datetime | None) -> datetime:
        moment = now if now is not None else datetime.now(UTC)
        if moment.tzinfo is None:
            raise ValueError("authentication time must be timezone aware")
        return moment
