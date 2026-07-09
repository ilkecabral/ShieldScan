"""
models.py — SQLAlchemy ORM models
Tables: User, Scan, Finding
"""

from datetime import datetime, timezone


def _utcnow():
    """Timezone-aware UTC now, stored as naive datetime for SQLite/PostgreSQL compatibility."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
from sqlalchemy import (
    Column, Integer, String, Float, Boolean,
    DateTime, ForeignKey, Text, Enum
)
from sqlalchemy.orm import relationship
import enum

from .database import Base


# ─────────────────────────────────────────
# Enums
# ─────────────────────────────────────────

class SeverityEnum(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatusEnum(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FindingTypeEnum(str, enum.Enum):
    CSPM = "CSPM"   # Cloud Security Posture Management (boto3)
    CWPP = "CWPP"   # Cloud Workload Protection (Trivy)


# ─────────────────────────────────────────
# User
# ─────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin  = Column(Boolean, default=False)    # grants access to /api/admin/* endpoints
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    # Encrypted AWS credentials (Fernet encrypted, stored as string)
    aws_access_key_enc = Column(Text, nullable=True)
    aws_secret_key_enc = Column(Text, nullable=True)
    aws_region = Column(String(50), nullable=True, default="us-east-1")
    aws_account_id = Column(String(20), nullable=True)   # from STS GetCallerIdentity
    aws_connected = Column(Boolean, default=False)

    # Security: brute-force lockout
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

    # Security: TOTP 2FA
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False)
    backup_codes = Column(Text, nullable=True)   # JSON list of bcrypt-hashed codes

    # Security: RSA Key Pair authentication
    # Server stores ONLY the public key fingerprint (SHA-256 of DER-encoded public key).
    # The private key is held exclusively by the user — never stored server-side.
    pub_key_fingerprint = Column(String(64), nullable=True)

    # Account recovery token (email-link method)
    # Token is a 32-byte random hex string, stored as SHA-256 hash (never plain-text).
    recovery_token_hash = Column(String(64), nullable=True)
    recovery_token_expires = Column(DateTime, nullable=True)

    # Soft-delete: set when the user requests account deletion.
    # Account is invisible to login/API for 30 days, then eligible for purge.
    deleted_at = Column(DateTime, nullable=True)

    # Email verification
    email_verified = Column(Boolean, default=False)
    email_verify_code = Column(String(8), nullable=True)        # 6-digit OTP
    email_verify_expires = Column(DateTime, nullable=True)

    # Security: Password reset tokens
    # Token is a 32-byte random hex string, stored as SHA-256 hash (never plain-text).
    reset_token_hash = Column(String(64), nullable=True)
    reset_token_expires = Column(DateTime, nullable=True)

    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    passkeys = relationship("PasskeyCredential", back_populates="user", cascade="all, delete-orphan")


# ─────────────────────────────────────────
# Scan
# ─────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(Enum(ScanStatusEnum), default=ScanStatusEnum.PENDING)
    risk_score = Column(Float, nullable=True)          # 0–100, from XGBoost
    started_at = Column(DateTime, default=_utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Summary counts (denormalized for fast dashboard loads)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Relationships
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


# ─────────────────────────────────────────
# Finding
# ─────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    # Core fields — matches the shape agreed with CSPM/CWPP teammates
    finding_id = Column(String(50), nullable=False)          # e.g. F001, CVE-2024-XXXX
    finding_type = Column(Enum(FindingTypeEnum), nullable=False)
    severity = Column(Enum(SeverityEnum), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    resource = Column(String(255), nullable=True)            # AWS resource ARN or container name
    region = Column(String(50), nullable=True)
    fix_recommendation = Column(Text, nullable=True)         # AI-generated or hardcoded fix tip
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)

    # CWPP-specific (Trivy CVE data)
    cve_id = Column(String(50), nullable=True)               # e.g. CVE-2024-1234
    cvss_score = Column(Float, nullable=True)
    affected_package = Column(String(255), nullable=True)
    fixed_version = Column(String(100), nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="findings")


# ─────────────────────────────────────────
# PasskeyCredential
# ─────────────────────────────────────────

class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # WebAuthn credential data
    credential_id = Column(Text, unique=True, nullable=False)   # base64url-encoded bytes
    public_key = Column(Text, nullable=False)                    # base64-encoded COSE key bytes
    sign_count = Column(Integer, default=0)

    # Metadata
    aaguid = Column(String(100), nullable=True)
    transports = Column(Text, nullable=True)                     # JSON list e.g. ["internal"]
    name = Column(String(100), nullable=True, default="Passkey") # friendly label shown to user
    created_at = Column(DateTime, default=_utcnow)

    # Relationships
    user = relationship("User", back_populates="passkeys")
