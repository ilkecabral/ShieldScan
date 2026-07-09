"""initial_schema

Revision ID: 0001
Revises:
Create Date: 2026-06-20

Creates all ShieldScan tables from scratch:
  - users
  - scans
  - findings
  - passkey_credentials
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users ────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("email", sa.String(255), unique=True, index=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("is_admin", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        # AWS credentials (Fernet-encrypted)
        sa.Column("aws_access_key_enc", sa.Text(), nullable=True),
        sa.Column("aws_secret_key_enc", sa.Text(), nullable=True),
        sa.Column("aws_region", sa.String(50), server_default="us-east-1", nullable=True),
        sa.Column("aws_account_id", sa.String(20), nullable=True),
        sa.Column("aws_connected", sa.Boolean(), server_default=sa.false(), nullable=False),
        # Brute-force lockout
        sa.Column("failed_login_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
        # TOTP 2FA
        sa.Column("totp_secret", sa.String(64), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("backup_codes", sa.Text(), nullable=True),
        # Passkey / WebAuthn
        sa.Column("pub_key_fingerprint", sa.String(64), nullable=True),
        # Account recovery
        sa.Column("recovery_token_hash", sa.String(64), nullable=True),
        sa.Column("recovery_token_expires", sa.DateTime(), nullable=True),
        # Soft-delete
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        # Email verification
        sa.Column("email_verified", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("email_verify_code", sa.String(8), nullable=True),
        sa.Column("email_verify_expires", sa.DateTime(), nullable=True),
        # Password reset
        sa.Column("reset_token_hash", sa.String(64), nullable=True),
        sa.Column("reset_token_expires", sa.DateTime(), nullable=True),
    )

    # ── scans ────────────────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "status",
            sa.Enum("PENDING", "RUNNING", "COMPLETED", "FAILED", name="scanstatusenum"),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("critical_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("high_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("medium_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("low_count", sa.Integer(), server_default="0", nullable=False),
        sa.Index("ix_scans_user_id", "user_id"),
    )

    # ── findings ─────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("finding_id", sa.String(50), nullable=False),
        sa.Column(
            "finding_type",
            sa.Enum("CSPM", "CWPP", name="findingtypeenum"),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severityenum"),
            nullable=False,
        ),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("resource", sa.String(255), nullable=True),
        sa.Column("region", sa.String(50), nullable=True),
        sa.Column("fix_recommendation", sa.Text(), nullable=True),
        sa.Column("is_resolved", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        # CWPP-specific
        sa.Column("cve_id", sa.String(50), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("affected_package", sa.String(255), nullable=True),
        sa.Column("fixed_version", sa.String(100), nullable=True),
        sa.Index("ix_findings_scan_id", "scan_id"),
        sa.Index("ix_findings_severity", "severity"),
    )

    # ── passkey_credentials ──────────────────────────────────────────────────
    op.create_table(
        "passkey_credentials",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("credential_id", sa.Text(), unique=True, nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("aaguid", sa.String(100), nullable=True),
        sa.Column("transports", sa.Text(), nullable=True),
        sa.Column("name", sa.String(100), server_default="Passkey", nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("passkey_credentials")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("users")
    # Drop Postgres enums (no-op on SQLite)
    op.execute("DROP TYPE IF EXISTS severityenum")
    op.execute("DROP TYPE IF EXISTS findingtypeenum")
    op.execute("DROP TYPE IF EXISTS scanstatusenum")
