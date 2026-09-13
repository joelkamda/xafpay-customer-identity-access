"""Add XCIA3 verifier-only customer PIN credentials.

Revision ID: xcia3_0001
Revises: xcia2_0001
"""

import sqlalchemy as sa
from alembic import op

revision = "xcia3_0001"
down_revision = "xcia2_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "xcia_customer_pin_credentials",
        sa.Column("credential_id", sa.String(36), primary_key=True),
        sa.Column(
            "customer_subject_id",
            sa.String(36),
            sa.ForeignKey("xcia_customer_subjects.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("credential_type", sa.String(32), nullable=False),
        sa.Column("phone_lookup_digest", sa.String(64), nullable=False),
        sa.Column("credential_verifier", sa.Text(), nullable=False),
        sa.Column("credential_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failed_attempt_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "phone_lookup_digest",
            "credential_version",
            name="uq_xcia_pin_phone_lookup_version",
        ),
    )
    op.create_table(
        "xcia_authentication_buckets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scope_type", sa.String(16), nullable=False),
        sa.Column("scope_digest", sa.String(64), nullable=False),
        sa.Column("failed_attempt_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "scope_type",
            "scope_digest",
            name="uq_xcia_auth_bucket_scope",
        ),
    )
    op.create_table(
        "xcia_trusted_devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "customer_subject_id",
            sa.String(36),
            sa.ForeignKey("xcia_customer_subjects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("device_digest", sa.String(64), nullable=False),
        sa.Column("trusted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "customer_subject_id",
            "device_digest",
            name="uq_xcia_trusted_device",
        ),
    )


def downgrade() -> None:
    op.drop_table("xcia_trusted_devices")
    op.drop_table("xcia_authentication_buckets")
    op.drop_table("xcia_customer_pin_credentials")
