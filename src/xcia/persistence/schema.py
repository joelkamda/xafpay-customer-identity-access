from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class CustomerSubjectRow(Base):
    __tablename__ = "xcia_customer_subjects"
    __table_args__ = (
        UniqueConstraint(
            "environment",
            "relying_party",
            "mapping_digest",
            name="uq_xcia_subject_mapping",
        ),
        UniqueConstraint(
            "environment",
            "relying_party",
            "subject_value",
            name="uq_xcia_subject_value",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    subject_value: Mapped[str] = mapped_column(String(255), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    relying_party: Mapped[str] = mapped_column(String(255), nullable=False)
    mapping_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SessionRow(Base):
    __tablename__ = "xcia_sessions"

    sid: Mapped[str] = mapped_column(String(255), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        ForeignKey("xcia_customer_subjects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    subject_value: Mapped[str] = mapped_column(String(255), nullable=False)
    sender_jkt: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    auth_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_activity: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    refresh_family_id: Mapped[str | None] = mapped_column(String(255))
    security_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class RefreshFamilyRow(Base):
    __tablename__ = "xcia_refresh_families"

    family_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    sid: Mapped[str] = mapped_column(
        ForeignKey("xcia_sessions.sid", ondelete="CASCADE"),
        nullable=False,
    )
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    verifier_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReplayJtiRow(Base):
    __tablename__ = "xcia_replay_jtis"
    __table_args__ = (
        UniqueConstraint("issuer", "audience", "jti", name="uq_xcia_replay_identity"),
        Index("ix_xcia_replay_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    audience: Mapped[str] = mapped_column(String(255), nullable=False)
    jti: Mapped[str] = mapped_column(String(255), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SigningKeyRow(Base):
    __tablename__ = "xcia_signing_keys"
    __table_args__ = (
        UniqueConstraint(
            "environment",
            "issuer",
            "kid",
            name="uq_xcia_signing_key_identity",
        ),
    )

    kid: Mapped[str] = mapped_column(String(255), primary_key=True)
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    public_jwk: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SecurityEventRow(Base):
    __tablename__ = "xcia_security_events"
    __table_args__ = (Index("ix_xcia_security_event_subject", "subject_value"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_value: Mapped[str | None] = mapped_column(String(255))
    sid: Mapped[str | None] = mapped_column(String(255))
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
