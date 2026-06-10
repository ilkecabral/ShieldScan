"""
models.py — SQLAlchemy ORM models
Tables: User, Scan, Finding
"""

from datetime import datetime
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
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Encrypted AWS credentials (Fernet encrypted, stored as string)
    aws_access_key_enc = Column(Text, nullable=True)
    aws_secret_key_enc = Column(Text, nullable=True)
    aws_region = Column(String(50), nullable=True, default="us-east-1")
    aws_connected = Column(Boolean, default=False)

    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")


# ─────────────────────────────────────────
# Scan
# ─────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(Enum(ScanStatusEnum), default=ScanStatusEnum.PENDING)
    risk_score = Column(Float, nullable=True)          # 0–100, from XGBoost
    started_at = Column(DateTime, default=datetime.utcnow)
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
    created_at = Column(DateTime, default=datetime.utcnow)

    # CWPP-specific (Trivy CVE data)
    cve_id = Column(String(50), nullable=True)               # e.g. CVE-2024-1234
    cvss_score = Column(Float, nullable=True)
    affected_package = Column(String(255), nullable=True)
    fixed_version = Column(String(100), nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="findings")
