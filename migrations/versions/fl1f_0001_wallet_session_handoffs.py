"""Add FL1F Wallet trusted session handoff persistence.

Revision ID: fl1f_0001_wallet_session_handoffs
Revises: xcia3_0001
Create Date: 2026-09-24
"""

import sqlalchemy as sa
from alembic import op

revision = "fl1f_0001_wallet_session_handoffs"
down_revision = "xcia3_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "xcia_wallet_session_handoffs",
        sa.Column("auth_completion_id", sa.String(length=255), primary_key=True),
        sa.Column("code_digest", sa.LargeBinary(), nullable=False),
        sa.Column(
            "session_sid",
            sa.String(length=255),
            sa.ForeignKey("xcia_sessions.sid", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relying_party", sa.String(length=64), nullable=False),
        sa.Column("sender_jkt", sa.String(length=256), nullable=False),
        sa.Column("security_version", sa.Integer(), nullable=False),
        sa.Column("trusted_origin", sa.String(length=512), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reconcile_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("code_digest", name="uq_xcia_wallet_handoff_code_digest"),
        sa.CheckConstraint("security_version >= 1", name="ck_xcia_wallet_handoff_security_version"),
        sa.CheckConstraint("issued_at < expires_at", name="ck_xcia_wallet_handoff_issue_expiry"),
    )
    op.create_index(
        "ix_xcia_wallet_handoff_expires_at",
        "xcia_wallet_session_handoffs",
        ["expires_at"],
    )
    op.create_index(
        "ix_xcia_wallet_handoff_session_sid",
        "xcia_wallet_session_handoffs",
        ["session_sid"],
    )


def downgrade() -> None:
    op.drop_index("ix_xcia_wallet_handoff_session_sid", table_name="xcia_wallet_session_handoffs")
    op.drop_index("ix_xcia_wallet_handoff_expires_at", table_name="xcia_wallet_session_handoffs")
    op.drop_table("xcia_wallet_session_handoffs")
