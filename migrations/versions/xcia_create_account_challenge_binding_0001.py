"""Bind phone-verification challenges to opaque phone identity.

Revision ID: xcia_create_account_challenge_binding_0001
Revises: fl1f_0001_wallet_session_handoff
Create Date: 2026-09-29
"""

import sqlalchemy as sa
from alembic import op

revision = "xcia_create_account_challenge_binding_0001"
down_revision = "fl1f_0001_wallet_session_handoff"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "xcia_phone_verification_challenges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("challenge_id", sa.String(255), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("bound_phone_digest", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verify_attempt_count", sa.Integer(), nullable=False),
        sa.Column("completion_outcome", sa.String(64), nullable=True),
        sa.Column("completed_subject_id", sa.String(36), nullable=True),
        sa.Column("completed_session_sid", sa.String(255), nullable=True),
        sa.Column("completion_sender_jkt_digest", sa.String(64), nullable=True),
        sa.Column("completion_device_digest", sa.String(64), nullable=True),
        sa.Column("completion_origin", sa.String(512), nullable=True),
        sa.UniqueConstraint("challenge_id", name="uq_xcia_phone_challenge_id"),
        sa.CheckConstraint(
            "state IN ('issued','verified','consumed','expired','superseded')",
            name="ck_xcia_phone_challenge_state",
        ),
        sa.CheckConstraint(
            "verify_attempt_count >= 0",
            name="ck_xcia_phone_challenge_verify_attempt_count",
        ),
        sa.CheckConstraint(
            "created_at < expires_at",
            name="ck_xcia_phone_challenge_issue_expiry",
        ),
    )
    op.create_index(
        "ix_xcia_phone_challenge_expires_at",
        "xcia_phone_verification_challenges",
        ["expires_at"],
    )
    op.create_index(
        "uq_xcia_phone_challenge_active_phone",
        "xcia_phone_verification_challenges",
        ["bound_phone_digest"],
        unique=True,
        postgresql_where=sa.text("state IN ('issued', 'verified')"),
    )
    op.create_index(
        "uq_xcia_pin_active_phone",
        "xcia_customer_pin_credentials",
        ["phone_lookup_digest"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_xcia_pin_active_phone",
        table_name="xcia_customer_pin_credentials",
    )
    op.drop_index(
        "uq_xcia_phone_challenge_active_phone",
        table_name="xcia_phone_verification_challenges",
    )
    op.drop_index(
        "ix_xcia_phone_challenge_expires_at",
        table_name="xcia_phone_verification_challenges",
    )
    op.drop_table("xcia_phone_verification_challenges")
