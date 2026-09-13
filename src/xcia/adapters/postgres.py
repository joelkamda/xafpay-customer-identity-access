from __future__ import annotations

import hashlib
import secrets
import uuid
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
    CustomerSubjectRow,
    RefreshFamilyRow,
    ReplayJtiRow,
    SecurityEventRow,
    SessionRow,
    SigningKeyRow,
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

    def is_sid_revoked(self, sid: str, *, at: datetime | None = None) -> bool:
        moment = at if at is not None else datetime.now(UTC)
        snapshot = self.get_session(sid)
        return snapshot is None or not snapshot.is_active(moment)


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
