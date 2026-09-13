"""Establish XCIA2 durable staging trust runtime.

Revision ID: xcia2_0001
Revises:
Create Date: 2026-09-12
"""

import sqlalchemy as sa
from alembic import op

revision = "xcia2_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "xcia_customer_subjects",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("subject_value", sa.String(length=255), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("relying_party", sa.String(length=255), nullable=False),
        sa.Column("mapping_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "environment",
            "relying_party",
            "mapping_digest",
            name="uq_xcia_subject_mapping",
        ),
        sa.UniqueConstraint(
            "environment",
            "relying_party",
            "subject_value",
            name="uq_xcia_subject_value",
        ),
    )
    op.create_table(
        "xcia_sessions",
        sa.Column("sid", sa.String(length=255), nullable=False),
        sa.Column("subject_id", sa.String(length=36), nullable=False),
        sa.Column("subject_value", sa.String(length=255), nullable=False),
        sa.Column("sender_jkt", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("auth_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("refresh_family_id", sa.String(length=255), nullable=True),
        sa.Column("security_version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["subject_id"],
            ["xcia_customer_subjects.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("sid"),
    )
    op.create_table(
        "xcia_refresh_families",
        sa.Column("family_id", sa.String(length=255), nullable=False),
        sa.Column("sid", sa.String(length=255), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("verifier_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reused_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["sid"],
            ["xcia_sessions.sid"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("family_id"),
    )
    op.create_table(
        "xcia_replay_jtis",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("issuer", sa.String(length=255), nullable=False),
        sa.Column("audience", sa.String(length=255), nullable=False),
        sa.Column("jti", sa.String(length=255), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "issuer",
            "audience",
            "jti",
            name="uq_xcia_replay_identity",
        ),
    )
    op.create_index(
        "ix_xcia_replay_expires_at",
        "xcia_replay_jtis",
        ["expires_at"],
        unique=False,
    )
    op.create_table(
        "xcia_signing_keys",
        sa.Column("kid", sa.String(length=255), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("issuer", sa.String(length=255), nullable=False),
        sa.Column("algorithm", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("public_jwk", sa.JSON(), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("kid"),
        sa.UniqueConstraint(
            "environment",
            "issuer",
            "kid",
            name="uq_xcia_signing_key_identity",
        ),
    )
    op.create_table(
        "xcia_security_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("subject_value", sa.String(length=255), nullable=True),
        sa.Column("sid", sa.String(length=255), nullable=True),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_xcia_security_event_subject",
        "xcia_security_events",
        ["subject_value"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_xcia_security_event_subject", table_name="xcia_security_events")
    op.drop_table("xcia_security_events")
    op.drop_table("xcia_signing_keys")
    op.drop_index("ix_xcia_replay_expires_at", table_name="xcia_replay_jtis")
    op.drop_table("xcia_replay_jtis")
    op.drop_table("xcia_refresh_families")
    op.drop_table("xcia_sessions")
    op.drop_table("xcia_customer_subjects")
