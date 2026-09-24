from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from xcia.domain import (
    DurableSessionSnapshot,
    ExternalCustomerSubject,
    RefreshTokenMaterial,
    ReplayDecision,
    RevocationDecision,
    SigningKeyState,
    TrustedAuthenticationContext,
)
from xcia.persistence import XciaDatabase
from xcia.persistence.schema import (
    AuthenticationBucketRow,
    CustomerPinCredentialRow,
    CustomerSubjectRow,
    RefreshFamilyRow,
    ReplayJtiRow,
    SecurityEventRow,
    SessionRow,
    SigningKeyRow,
    TrustedDeviceRow,
    WalletSessionHandoffRow,
)
from xcia.policies import SubjectPolicy

SESSION_IDLE_DEFAULT_SECONDS = 15 * 60
SESSION_ABSOLUTE_DEFAULT_SECONDS = 8 * 60 * 60
REFRESH_DEFAULT_SECONDS = 30 * 24 * 60 * 60


class RefreshReuseDetected(ValueError):
    pass


class DurableSubjectStore:
    def __init__(self, database: XciaDatabase) -> None:
        self._database = database

    @staticmethod
    def _mapping_digest(authentication_handle: str) -> str:
        if not authentication_handle.startswith("authref_"):
            raise ValueError("trusted authentication handle must be opaque and authref_-scoped")
        if len(authentication_handle) < 24:
            raise ValueError("trusted authentication handle is too short")
        if "@" in authentication_handle or any(ch.isspace() for ch in authentication_handle):
            raise ValueError("PII-shaped authentication handles are forbidden")
        return hashlib.sha256(authentication_handle.encode("utf-8")).hexdigest()

    def create_or_lookup(
        self,
        *,
        authentication_handle: str,
        relying_party: str,
        environment: str,
        now: datetime | None = None,
    ) -> ExternalCustomerSubject:
        mapping_digest = self._mapping_digest(authentication_handle)
        created_at = now if now is not None else datetime.now(UTC)
        if created_at.tzinfo is None:
            raise ValueError("subject creation time must be timezone aware")

        with self._database.session() as session:
            with session.begin():
                existing = session.scalar(
                    select(CustomerSubjectRow).where(
                        CustomerSubjectRow.environment == environment,
                        CustomerSubjectRow.relying_party == relying_party,
                        CustomerSubjectRow.mapping_digest == mapping_digest,
                    )
                )
                if existing is not None:
                    return ExternalCustomerSubject(
                        value=existing.subject_value,
                        relying_party=existing.relying_party,
                        environment=existing.environment,
                    )

                subject_value = f"sub_{secrets.token_urlsafe(24)}"
                subject = SubjectPolicy.create_server_issued_subject(
                    value=subject_value,
                    relying_party=relying_party,
                    environment=environment,
                )
                session.add(
                    CustomerSubjectRow(
                        id=str(uuid.uuid4()),
                        subject_value=subject.value,
                        environment=subject.environment,
                        relying_party=subject.relying_party,
                        mapping_digest=mapping_digest,
                        created_at=created_at,
                    )
                )
                return subject

    def lookup(
        self,
        *,
        subject_value: str,
        relying_party: str,
        environment: str,
    ) -> ExternalCustomerSubject | None:
        with self._database.session() as session:
            row = session.scalar(
                select(CustomerSubjectRow).where(
                    CustomerSubjectRow.subject_value == subject_value,
                    CustomerSubjectRow.relying_party == relying_party,
                    CustomerSubjectRow.environment == environment,
                )
            )
            if row is None:
                return None
            return ExternalCustomerSubject(
                value=row.subject_value,
                relying_party=row.relying_party,
                environment=row.environment,
            )

    def subject_id(self, subject: ExternalCustomerSubject) -> str:
        with self._database.session() as session:
            row = session.scalar(
                select(CustomerSubjectRow).where(
                    CustomerSubjectRow.subject_value == subject.value,
                    CustomerSubjectRow.relying_party == subject.relying_party,
                    CustomerSubjectRow.environment == subject.environment,
                )
            )
            if row is None:
                raise ValueError("durable subject must exist")
            return row.id

    def get_by_id(self, subject_id: str) -> ExternalCustomerSubject | None:
        with self._database.session() as session:
            row = session.get(CustomerSubjectRow, subject_id)
            if row is None:
                return None
            return ExternalCustomerSubject(
                value=row.subject_value,
                relying_party=row.relying_party,
                environment=row.environment,
            )


class DurableSessionStore:
    def __init__(self, database: XciaDatabase) -> None:
        self._database = database

    @staticmethod
    def snapshot_from_row(row: SessionRow) -> DurableSessionSnapshot:
        return DurableSessionSnapshot(
            sid=row.sid,
            sub=row.subject_value,
            sender_jkt=row.sender_jkt,
            created_at=row.created_at,
            auth_time=row.auth_time,
            last_activity=row.last_activity,
            idle_expires_at=row.idle_expires_at,
            absolute_expires_at=row.absolute_expires_at,
            revoked_at=row.revoked_at,
            refresh_family_id=row.refresh_family_id,
            security_version=row.security_version,
        )

    def create_authenticated_session(
        self,
        context: TrustedAuthenticationContext,
        *,
        now: datetime | None = None,
    ) -> DurableSessionSnapshot:
        created_at = now if now is not None else datetime.now(UTC)
        if created_at.tzinfo is None:
            raise ValueError("session creation time must be timezone aware")
        if context.auth_time > created_at:
            raise ValueError("authentication time cannot be in the future")

        with self._database.session() as session:
            with session.begin():
                subject_row = session.scalar(
                    select(CustomerSubjectRow).where(
                        CustomerSubjectRow.subject_value == context.subject.value,
                        CustomerSubjectRow.relying_party == context.subject.relying_party,
                        CustomerSubjectRow.environment == context.subject.environment,
                    )
                )
                if subject_row is None:
                    raise ValueError("durable subject must exist before session creation")

                row = SessionRow(
                    sid=f"sid_{uuid.uuid4().hex}",
                    subject_id=subject_row.id,
                    subject_value=context.subject.value,
                    sender_jkt=context.sender_jkt,
                    created_at=created_at,
                    auth_time=context.auth_time,
                    last_activity=created_at,
                    idle_expires_at=created_at
                    + timedelta(seconds=SESSION_IDLE_DEFAULT_SECONDS),
                    absolute_expires_at=created_at
                    + timedelta(seconds=SESSION_ABSOLUTE_DEFAULT_SECONDS),
                    revoked_at=None,
                    refresh_family_id=None,
                    security_version=1,
                )
                session.add(row)
                session.flush()
                return self.snapshot_from_row(row)

    def get_session(self, sid: str) -> DurableSessionSnapshot | None:
        with self._database.session() as session:
            row = session.get(SessionRow, sid)
            return None if row is None else self.snapshot_from_row(row)

    def require_active_session(
        self,
        sid: str,
        *,
        at: datetime | None = None,
    ) -> DurableSessionSnapshot:
        moment = at if at is not None else datetime.now(UTC)
        snapshot = self.get_session(sid)
        if snapshot is None or not snapshot.is_active(moment):
            raise ValueError("authoritative session is missing, revoked, or expired")
        return snapshot

    def touch(self, sid: str, *, at: datetime | None = None) -> DurableSessionSnapshot:
        moment = at if at is not None else datetime.now(UTC)
        if moment.tzinfo is None:
            raise ValueError("session touch time must be timezone aware")
        with self._database.session() as session:
            with session.begin():
                row = session.scalar(
                    select(SessionRow).where(SessionRow.sid == sid).with_for_update()
                )
                if row is None:
                    raise ValueError("session not found")
                snapshot = self.snapshot_from_row(row)
                if not snapshot.is_active(moment):
                    raise ValueError("session is revoked or expired")
                row.last_activity = moment
                row.idle_expires_at = min(
                    moment + timedelta(seconds=SESSION_IDLE_DEFAULT_SECONDS),
                    row.absolute_expires_at,
                )
                session.flush()
                return self.snapshot_from_row(row)

    def revoke_session(self, sid: str, *, at: datetime | None = None) -> None:
        moment = at if at is not None else datetime.now(UTC)
        with self._database.session() as session:
            with session.begin():
                session.execute(
                    update(SessionRow)
                    .where(SessionRow.sid == sid, SessionRow.revoked_at.is_(None))
                    .values(revoked_at=moment)
                )

    def revoke_subject_sessions(self, subject_value: str, *, at: datetime) -> None:
        with self._database.session() as session:
            with session.begin():
                session.execute(
                    update(SessionRow)
                    .where(
                        SessionRow.subject_value == subject_value,
                        SessionRow.revoked_at.is_(None),
                    )
                    .values(revoked_at=at)
                )

    def is_sid_revoked(self, sid: str, *, at: datetime | None = None) -> bool:
        moment = at if at is not None else datetime.now(UTC)
        snapshot = self.get_session(sid)
        return snapshot is None or not snapshot.is_active(moment)


@dataclass(frozen=True, slots=True)
class WalletSessionHandoffMaterial:
    auth_completion_id: str
    handoff_code: str
    handoff_expires_at: datetime


@dataclass(frozen=True, slots=True)
class WalletSessionHandoffContext:
    auth_completion_id: str
    session_sid: str
    auth_time: datetime
    sender_jkt: str
    security_version: int
    idle_expires_at: datetime
    absolute_expires_at: datetime


class DurableWalletSessionHandoffStore:
    HANDOFF_TTL_SECONDS = 60
    RECONCILIATION_WINDOW_SECONDS = 120

    def __init__(self, database: XciaDatabase) -> None:
        self._database = database

    @staticmethod
    def _moment(now: datetime | None) -> datetime:
        moment = now if now is not None else datetime.now(UTC)
        if moment.tzinfo is None:
            raise ValueError("handoff time must be timezone aware")
        return moment

    @staticmethod
    def _code_digest(handoff_code: str) -> bytes:
        if not handoff_code:
            raise ValueError("handoff code is required")
        return hashlib.sha256(handoff_code.encode("utf-8")).digest()

    @staticmethod
    def _context(
        row: WalletSessionHandoffRow,
        session_row: SessionRow,
    ) -> WalletSessionHandoffContext:
        return WalletSessionHandoffContext(
            auth_completion_id=row.auth_completion_id,
            session_sid=session_row.sid,
            auth_time=session_row.auth_time,
            sender_jkt=session_row.sender_jkt,
            security_version=session_row.security_version,
            idle_expires_at=session_row.idle_expires_at,
            absolute_expires_at=session_row.absolute_expires_at,
        )

    @staticmethod
    def _require_binding(
        row: WalletSessionHandoffRow,
        session_row: SessionRow,
        *,
        relying_party: str,
        sender_jkt: str,
        trusted_origin: str,
        moment: datetime,
    ) -> None:
        snapshot = DurableSessionStore.snapshot_from_row(session_row)
        if not snapshot.is_active(moment):
            raise ValueError("XCIA session is not active")
        if row.relying_party != relying_party:
            raise ValueError("handoff relying party mismatch")
        if row.trusted_origin != trusted_origin:
            raise ValueError("handoff trusted origin mismatch")
        if row.sender_jkt != sender_jkt or session_row.sender_jkt != sender_jkt:
            raise ValueError("handoff sender binding mismatch")
        if session_row.security_version != row.security_version:
            raise ValueError("handoff security version mismatch")

    def issue(
        self,
        *,
        session_sid: str,
        relying_party: str,
        sender_jkt: str,
        security_version: int,
        trusted_origin: str,
        now: datetime | None = None,
    ) -> WalletSessionHandoffMaterial:
        moment = self._moment(now)
        auth_completion_id = f"ac_{secrets.token_urlsafe(16)}"
        handoff_code = secrets.token_urlsafe(32)
        expires_at = moment + timedelta(seconds=self.HANDOFF_TTL_SECONDS)

        with self._database.session() as session:
            with session.begin():
                session_row = session.scalar(
                    select(SessionRow)
                    .where(SessionRow.sid == session_sid)
                    .with_for_update()
                )
                if session_row is None:
                    raise ValueError("XCIA session is missing")
                snapshot = DurableSessionStore.snapshot_from_row(session_row)
                if not snapshot.is_active(moment):
                    raise ValueError("XCIA session is not active")
                if session_row.sender_jkt != sender_jkt:
                    raise ValueError("XCIA session sender binding mismatch")
                if session_row.security_version != security_version:
                    raise ValueError("XCIA session security version mismatch")
                session.add(
                    WalletSessionHandoffRow(
                        auth_completion_id=auth_completion_id,
                        code_digest=self._code_digest(handoff_code),
                        session_sid=session_sid,
                        relying_party=relying_party,
                        sender_jkt=sender_jkt,
                        security_version=security_version,
                        trusted_origin=trusted_origin,
                        issued_at=moment,
                        expires_at=expires_at,
                        redeemed_at=None,
                        reconcile_expires_at=None,
                    )
                )
                session.flush()

        return WalletSessionHandoffMaterial(
            auth_completion_id=auth_completion_id,
            handoff_code=handoff_code,
            handoff_expires_at=expires_at,
        )

    def redeem(
        self,
        *,
        handoff_code: str,
        relying_party: str,
        sender_jkt: str,
        trusted_origin: str,
        now: datetime | None = None,
    ) -> WalletSessionHandoffContext:
        moment = self._moment(now)
        code_digest = self._code_digest(handoff_code)

        with self._database.session() as session:
            with session.begin():
                row = session.scalar(
                    select(WalletSessionHandoffRow)
                    .where(WalletSessionHandoffRow.code_digest == code_digest)
                    .with_for_update()
                )
                if row is None:
                    raise ValueError("handoff is missing")
                if row.redeemed_at is not None:
                    raise ValueError("handoff is already redeemed")
                if moment >= row.expires_at:
                    raise ValueError("handoff is expired")

                session_row = session.scalar(
                    select(SessionRow)
                    .where(SessionRow.sid == row.session_sid)
                    .with_for_update()
                )
                if session_row is None:
                    raise ValueError("XCIA session is missing")
                self._require_binding(
                    row,
                    session_row,
                    relying_party=relying_party,
                    sender_jkt=sender_jkt,
                    trusted_origin=trusted_origin,
                    moment=moment,
                )
                row.redeemed_at = moment
                row.reconcile_expires_at = min(
                    moment + timedelta(seconds=self.RECONCILIATION_WINDOW_SECONDS),
                    session_row.idle_expires_at,
                    session_row.absolute_expires_at,
                )
                session.flush()
                return self._context(row, session_row)

    def reconcile(
        self,
        *,
        auth_completion_id: str,
        relying_party: str,
        sender_jkt: str,
        trusted_origin: str,
        now: datetime | None = None,
    ) -> WalletSessionHandoffContext:
        moment = self._moment(now)
        if not auth_completion_id.startswith("ac_"):
            raise ValueError("authentication completion id is invalid")

        with self._database.session() as session:
            with session.begin():
                row = session.scalar(
                    select(WalletSessionHandoffRow)
                    .where(
                        WalletSessionHandoffRow.auth_completion_id == auth_completion_id
                    )
                    .with_for_update()
                )
                if row is None or row.redeemed_at is None:
                    raise ValueError("redeemed handoff is missing")
                if (
                    row.reconcile_expires_at is None
                    or moment >= row.reconcile_expires_at
                ):
                    raise ValueError("handoff reconciliation window is expired")

                session_row = session.scalar(
                    select(SessionRow)
                    .where(SessionRow.sid == row.session_sid)
                    .with_for_update()
                )
                if session_row is None:
                    raise ValueError("XCIA session is missing")
                self._require_binding(
                    row,
                    session_row,
                    relying_party=relying_party,
                    sender_jkt=sender_jkt,
                    trusted_origin=trusted_origin,
                    moment=moment,
                )
                return self._context(row, session_row)


class DurableRefreshFamilyStore:
    def __init__(self, database: XciaDatabase) -> None:
        self._database = database

    @staticmethod
    def _digest(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def issue(
        self,
        session_snapshot: DurableSessionSnapshot,
        *,
        now: datetime | None = None,
    ) -> RefreshTokenMaterial:
        moment = now if now is not None else datetime.now(UTC)
        if not session_snapshot.is_active(moment):
            raise ValueError("cannot issue refresh material from inactive session")

        family_id = f"rf_{uuid.uuid4().hex}"
        secret = secrets.token_urlsafe(48)
        expires_at = min(
            moment + timedelta(seconds=REFRESH_DEFAULT_SECONDS),
            session_snapshot.absolute_expires_at,
        )
        with self._database.session() as session:
            with session.begin():
                row = session.scalar(
                    select(SessionRow)
                    .where(SessionRow.sid == session_snapshot.sid)
                    .with_for_update()
                )
                if row is None or row.revoked_at is not None:
                    raise ValueError("session is not refresh-authoritative")
                if row.refresh_family_id is not None:
                    raise ValueError("session already has a refresh family")
                session.add(
                    RefreshFamilyRow(
                        family_id=family_id,
                        sid=row.sid,
                        generation=0,
                        verifier_digest=self._digest(secret),
                        created_at=moment,
                        expires_at=expires_at,
                        rotated_at=None,
                        reused_at=None,
                        revoked_at=None,
                    )
                )
                row.refresh_family_id = family_id

        return RefreshTokenMaterial(
            family_id=family_id,
            generation=0,
            secret=secret,
            expires_at=expires_at,
        )

    def rotate(
        self,
        presented: RefreshTokenMaterial,
        *,
        now: datetime | None = None,
    ) -> RefreshTokenMaterial:
        moment = now if now is not None else datetime.now(UTC)
        reuse_detected = False
        result: RefreshTokenMaterial | None = None

        with self._database.session() as session:
            with session.begin():
                row = session.scalar(
                    select(RefreshFamilyRow)
                    .where(RefreshFamilyRow.family_id == presented.family_id)
                    .with_for_update()
                )
                if row is None or row.revoked_at is not None or moment >= row.expires_at:
                    raise ValueError("refresh family is missing, revoked, or expired")

                digest_matches = secrets.compare_digest(
                    row.verifier_digest,
                    self._digest(presented.secret),
                )
                generation_matches = row.generation == presented.generation
                if not digest_matches or not generation_matches:
                    reuse_detected = True
                    row.reused_at = moment
                    row.revoked_at = moment
                    session.execute(
                        update(SessionRow)
                        .where(SessionRow.sid == row.sid, SessionRow.revoked_at.is_(None))
                        .values(revoked_at=moment)
                    )
                    session.add(
                        SecurityEventRow(
                            id=str(uuid.uuid4()),
                            event_type="refresh_reuse_detected",
                            subject_value=None,
                            sid=row.sid,
                            detail="refresh family revoked after verifier/generation mismatch",
                            occurred_at=moment,
                        )
                    )
                else:
                    new_secret = secrets.token_urlsafe(48)
                    row.generation += 1
                    row.verifier_digest = self._digest(new_secret)
                    row.rotated_at = moment
                    result = RefreshTokenMaterial(
                        family_id=row.family_id,
                        generation=row.generation,
                        secret=new_secret,
                        expires_at=row.expires_at,
                    )

        if reuse_detected:
            raise RefreshReuseDetected("refresh reuse detected; family and session revoked")
        if result is None:
            raise RuntimeError("refresh rotation failed closed")
        return result

    def revoke(self, family_id: str, *, at: datetime | None = None) -> None:
        moment = at if at is not None else datetime.now(UTC)
        with self._database.session() as session:
            with session.begin():
                row = session.scalar(
                    select(RefreshFamilyRow)
                    .where(RefreshFamilyRow.family_id == family_id)
                    .with_for_update()
                )
                if row is None:
                    return
                if row.revoked_at is None:
                    row.revoked_at = moment
                session.execute(
                    update(SessionRow)
                    .where(SessionRow.sid == row.sid, SessionRow.revoked_at.is_(None))
                    .values(revoked_at=moment)
                )


class PostgresRevocationAuthority:
    def __init__(self, database: XciaDatabase) -> None:
        self._database = database

    def session_decision(self, sid: str) -> RevocationDecision:
        snapshot = DurableSessionStore(self._database).get_session(sid)
        if snapshot is None or not snapshot.is_active():
            return RevocationDecision.DENY_REVOKED
        return RevocationDecision.ALLOW

    def refresh_family_decision(self, family_id: str) -> RevocationDecision:
        with self._database.session() as session:
            row = session.get(RefreshFamilyRow, family_id)
            if row is None or row.revoked_at is not None or datetime.now(UTC) >= row.expires_at:
                return RevocationDecision.DENY_REVOKED
            session_row = session.get(SessionRow, row.sid)
            if session_row is None:
                return RevocationDecision.DENY_REVOKED
            snapshot = DurableSessionStore.snapshot_from_row(session_row)
            if not snapshot.is_active():
                return RevocationDecision.DENY_REVOKED
            return RevocationDecision.ALLOW

    def signing_key_decision(self, kid: str) -> RevocationDecision:
        with self._database.session() as session:
            row = session.get(SigningKeyRow, kid)
            if row is None:
                return RevocationDecision.DENY_REVOKED
            allowed_states = {
                SigningKeyState.ACTIVE_SIGNING.value,
                SigningKeyState.VERIFY_ONLY_OVERLAP.value,
            }
            if row.state not in allowed_states:
                return RevocationDecision.DENY_REVOKED
            now = datetime.now(UTC)
            if now < row.not_before or (row.not_after is not None and now >= row.not_after):
                return RevocationDecision.DENY_REVOKED
            return RevocationDecision.ALLOW


class PostgresReplayDefense:
    def __init__(
        self,
        database: XciaDatabase,
        *,
        issuer: str,
        audience: str,
        retention_seconds: int = 360,
    ) -> None:
        self._database = database
        self._issuer = issuer
        self._audience = audience
        self._retention_seconds = retention_seconds

    def evaluate_jti(self, jti: str) -> ReplayDecision:
        now = datetime.now(UTC)
        statement = (
            pg_insert(ReplayJtiRow)
            .values(
                id=str(uuid.uuid4()),
                issuer=self._issuer,
                audience=self._audience,
                jti=jti,
                first_seen_at=now,
                expires_at=now + timedelta(seconds=self._retention_seconds),
            )
            .on_conflict_do_nothing(
                index_elements=[
                    ReplayJtiRow.issuer,
                    ReplayJtiRow.audience,
                    ReplayJtiRow.jti,
                ]
            )
            .returning(ReplayJtiRow.jti)
        )
        with self._database.session() as session:
            with session.begin():
                inserted = session.scalar(statement)
        if inserted is None:
            return ReplayDecision.DENY_REPLAY
        return ReplayDecision.ALLOW

    def purge_expired(self, *, at: datetime | None = None) -> int:
        moment = at if at is not None else datetime.now(UTC)
        with self._database.session() as session:
            with session.begin():
                statement = (
                    delete(ReplayJtiRow)
                    .where(ReplayJtiRow.expires_at <= moment)
                    .returning(ReplayJtiRow.id)
                )
                deleted_ids = list(session.scalars(statement))
                return len(deleted_ids)


class SecurityEventStore:
    def __init__(self, database: XciaDatabase) -> None:
        self._database = database

    def record(
        self,
        *,
        event_type: str,
        detail: str,
        subject_value: str | None = None,
        sid: str | None = None,
        occurred_at: datetime | None = None,
    ) -> None:
        moment = occurred_at if occurred_at is not None else datetime.now(UTC)
        with self._database.session() as session:
            with session.begin():
                session.add(
                    SecurityEventRow(
                        id=str(uuid.uuid4()),
                        event_type=event_type,
                        subject_value=subject_value,
                        sid=sid,
                        detail=detail,
                        occurred_at=moment,
                    )
                )


class DurablePinCredentialStore:
    def __init__(self, database: XciaDatabase) -> None:
        self._database = database

    def find_by_phone_digest(self, digest: str) -> CustomerPinCredentialRow | None:
        with self._database.session() as session:
            return session.scalar(
                select(CustomerPinCredentialRow).where(
                    CustomerPinCredentialRow.phone_lookup_digest == digest,
                    CustomerPinCredentialRow.status == "active",
                )
            )

    def replace(
        self,
        *,
        subject_id: str,
        phone_lookup_digest: str,
        verifier: str,
        now: datetime,
    ) -> CustomerPinCredentialRow:
        with self._database.session() as session:
            with session.begin():
                previous = session.scalar(
                    select(CustomerPinCredentialRow)
                    .where(CustomerPinCredentialRow.phone_lookup_digest == phone_lookup_digest)
                    .with_for_update()
                )
                version = 1
                if previous is not None:
                    previous.status = "superseded"
                    previous.updated_at = now
                    version = previous.credential_version + 1
                row = CustomerPinCredentialRow(
                    credential_id=str(uuid.uuid4()),
                    customer_subject_id=subject_id,
                    credential_type="XAFPAY_PIN",
                    phone_lookup_digest=phone_lookup_digest,
                    credential_verifier=verifier,
                    credential_version=version,
                    status="active",
                    created_at=now,
                    updated_at=now,
                    failed_attempt_count=0,
                    locked_until=None,
                    last_success_at=None,
                )
                session.add(row)
                session.flush()
                return row

    def record_failure(
        self,
        row: CustomerPinCredentialRow,
        *,
        now: datetime,
        lockout_after_failures: int,
        lockout_seconds: int,
    ) -> None:
        with self._database.session() as session:
            with session.begin():
                current = session.get(CustomerPinCredentialRow, row.credential_id)
                if current is None:
                    return
                current.failed_attempt_count += 1
                current.updated_at = now
                if current.failed_attempt_count >= lockout_after_failures:
                    excess = current.failed_attempt_count - lockout_after_failures
                    seconds = min(lockout_seconds * (2**excess), 86_400)
                    current.locked_until = now + timedelta(seconds=seconds)

    def record_success(self, row: CustomerPinCredentialRow, *, now: datetime) -> None:
        with self._database.session() as session:
            with session.begin():
                current = session.get(CustomerPinCredentialRow, row.credential_id)
                if current is None:
                    raise ValueError("credential is missing")
                current.failed_attempt_count = 0
                current.locked_until = None
                current.last_success_at = now
                current.updated_at = now


class DurableAuthenticationControlStore:
    def __init__(self, database: XciaDatabase) -> None:
        self._database = database

    def is_locked(self, scope_type: str, scope_digest: str, *, now: datetime) -> bool:
        with self._database.session() as session:
            row = session.scalar(
                select(AuthenticationBucketRow).where(
                    AuthenticationBucketRow.scope_type == scope_type,
                    AuthenticationBucketRow.scope_digest == scope_digest,
                )
            )
            return row is not None and row.locked_until is not None and now < row.locked_until

    def record_failure(
        self,
        scope_type: str,
        scope_digest: str,
        *,
        now: datetime,
        lockout_after_failures: int,
        lockout_seconds: int,
    ) -> None:
        with self._database.session() as session:
            with session.begin():
                row = session.scalar(
                    select(AuthenticationBucketRow)
                    .where(
                        AuthenticationBucketRow.scope_type == scope_type,
                        AuthenticationBucketRow.scope_digest == scope_digest,
                    )
                    .with_for_update()
                )
                if row is None:
                    row = AuthenticationBucketRow(
                        id=str(uuid.uuid4()),
                        scope_type=scope_type,
                        scope_digest=scope_digest,
                        failed_attempt_count=0,
                        locked_until=None,
                        updated_at=now,
                    )
                    session.add(row)
                row.failed_attempt_count += 1
                row.updated_at = now
                if row.failed_attempt_count >= lockout_after_failures:
                    excess = row.failed_attempt_count - lockout_after_failures
                    seconds = min(lockout_seconds * (2**excess), 86_400)
                    row.locked_until = now + timedelta(seconds=seconds)

    def clear_failures(self, scope_type: str, scope_digest: str, *, now: datetime) -> None:
        with self._database.session() as session:
            with session.begin():
                row = session.scalar(
                    select(AuthenticationBucketRow).where(
                        AuthenticationBucketRow.scope_type == scope_type,
                        AuthenticationBucketRow.scope_digest == scope_digest,
                    )
                )
                if row is not None:
                    row.failed_attempt_count = 0
                    row.locked_until = None
                    row.updated_at = now

    def trust_device(self, subject_id: str, device_digest: str, *, now: datetime) -> None:
        with self._database.session() as session:
            with session.begin():
                row = session.scalar(
                    select(TrustedDeviceRow).where(
                        TrustedDeviceRow.customer_subject_id == subject_id,
                        TrustedDeviceRow.device_digest == device_digest,
                    )
                )
                if row is None:
                    session.add(
                        TrustedDeviceRow(
                            id=str(uuid.uuid4()),
                            customer_subject_id=subject_id,
                            device_digest=device_digest,
                            trusted_at=now,
                            last_seen_at=now,
                        )
                    )
                else:
                    row.last_seen_at = now

    def is_trusted_device(self, subject_id: str, device_digest: str) -> bool:
        with self._database.session() as session:
            return (
                session.scalar(
                    select(TrustedDeviceRow.id).where(
                        TrustedDeviceRow.customer_subject_id == subject_id,
                        TrustedDeviceRow.device_digest == device_digest,
                    )
                )
                is not None
            )
