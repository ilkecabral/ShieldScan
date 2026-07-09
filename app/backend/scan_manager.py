"""
scan_manager.py — Scan Orchestrator
Owner: Kiran

Coordinates CSPM + CWPP + risk scoring into a single scan run.
Saves results to the database.
Uses asyncio.to_thread for each boto3 check so the event loop stays
responsive and GET /api/scan/progress can be served during a live scan.
"""

import asyncio
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

from . import models
from .auth import decrypt_aws_credential
from .services.cspm_service import (
    MOCK_FINDINGS,
    _check_s3_public_access,
    _check_iam_root,
    _check_iam_users_mfa,
    _check_ec2_open_ports,
    _check_cloudtrail,
    _check_password_policy,
    _check_ebs_encryption,
    _check_rds_encryption,
    _check_vpc_flow_logs,
    _check_s3_access_logging,
    _check_iam_admin_policies,
    _check_kms_rotation,
    _check_guardduty,
)
from .services.cwpp_service import run_cwpp_scan
from .services.risk_scorer import score_findings

logger = logging.getLogger(__name__)


# ── In-memory scan progress (keyed by user_id) ──────────────────────────────
# Thread-safe for reads/writes under CPython GIL.
_scan_progress: dict = {}


def get_scan_progress(user_id: int) -> dict:
    """Return the current progress for a user's active scan."""
    return _scan_progress.get(
        user_id,
        # done=False so polling doesn't self-terminate before a scan starts
        {"step": "Ready", "pct": 0, "done": False},
    )


def _set_progress(user_id: int, step: str, pct: int, done: bool = False) -> None:
    _scan_progress[user_id] = {"step": step, "pct": int(pct), "done": done}


# ── Main scan entry point ────────────────────────────────────────────────────

async def run_full_scan(
    user: models.User,
    db: Session,
    image_name: str = "nginx:latest",
) -> models.Scan:
    """
    Run a complete scan for a user: CSPM + CWPP + risk scoring.
    Saves a Scan record + all Finding records to the database.

    Each boto3 CSPM check runs in a thread pool via asyncio.to_thread,
    keeping the event loop free to serve /api/scan/progress poll requests.

    CSPM checks (13 total):
      1.  S3 public access block
      2.  IAM root access keys + MFA
      3.  IAM users MFA (console + programmatic)
      4.  EC2 security groups (dangerous open ports)
      5.  CloudTrail logging
      6.  IAM password policy
      7.  EBS volume encryption
      8.  RDS instance encryption
      9.  VPC flow logs
      10. S3 server access logging
      11. IAM admin policy on users
      12. KMS key rotation
      13. GuardDuty enabled + active findings
    """

    # 1. Create scan record (status = RUNNING)
    scan = models.Scan(
        user_id=user.id,
        status=models.ScanStatusEnum.RUNNING,
        started_at=_utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    _set_progress(user.id, "Connecting to AWS account…", 5)
    await asyncio.sleep(0)   # yield so the event loop can serve pending progress polls

    try:
        all_findings_raw = []

        logger.info(
            "Scan start: aws_connected=%s, has_key=%s",
            user.aws_connected, bool(user.aws_access_key_enc)
        )

        if user.aws_connected and user.aws_access_key_enc:
            aws_key    = decrypt_aws_credential(user.aws_access_key_enc)
            aws_secret = decrypt_aws_credential(user.aws_secret_key_enc)
            region     = user.aws_region or "us-east-1"

            _set_progress(user.id, "Initialising AWS session…", 8)
            await asyncio.sleep(0)

            import boto3
            session = await asyncio.to_thread(
                lambda: boto3.Session(
                    aws_access_key_id=aws_key,
                    aws_secret_access_key=aws_secret,
                    region_name=region,
                )
            )

            # ── CSPM checks — each yields the event loop before and after ──

            _set_progress(user.id, "Scanning S3 bucket permissions…", 13)
            await asyncio.sleep(0)
            s3_pub_f = await asyncio.to_thread(_check_s3_public_access, session, region)

            _set_progress(user.id, "Auditing IAM root account…", 20)
            await asyncio.sleep(0)
            iam_root_f = await asyncio.to_thread(_check_iam_root, session)

            _set_progress(user.id, "Checking IAM user MFA settings…", 27)
            await asyncio.sleep(0)
            iam_mfa_f = await asyncio.to_thread(_check_iam_users_mfa, session)

            _set_progress(user.id, "Checking IAM admin policies…", 33)
            await asyncio.sleep(0)
            iam_admin_f = await asyncio.to_thread(_check_iam_admin_policies, session)

            _set_progress(user.id, "Scanning EC2 security groups…", 40)
            await asyncio.sleep(0)
            ec2_f = await asyncio.to_thread(_check_ec2_open_ports, session, region)

            _set_progress(user.id, "Verifying CloudTrail logging…", 47)
            await asyncio.sleep(0)
            ct_f = await asyncio.to_thread(_check_cloudtrail, session, region)

            _set_progress(user.id, "Checking IAM password policies…", 52)
            await asyncio.sleep(0)
            pw_f = await asyncio.to_thread(_check_password_policy, session)

            _set_progress(user.id, "Checking EBS volume encryption…", 57)
            await asyncio.sleep(0)
            ebs_f = await asyncio.to_thread(_check_ebs_encryption, session, region)

            _set_progress(user.id, "Checking RDS instance encryption…", 62)
            await asyncio.sleep(0)
            rds_f = await asyncio.to_thread(_check_rds_encryption, session, region)

            _set_progress(user.id, "Checking VPC flow logs…", 66)
            await asyncio.sleep(0)
            vpc_f = await asyncio.to_thread(_check_vpc_flow_logs, session, region)

            _set_progress(user.id, "Checking S3 access logging…", 70)
            await asyncio.sleep(0)
            s3_log_f = await asyncio.to_thread(_check_s3_access_logging, session, region)

            _set_progress(user.id, "Checking KMS key rotation…", 74)
            await asyncio.sleep(0)
            kms_f = await asyncio.to_thread(_check_kms_rotation, session, region)

            _set_progress(user.id, "Pulling GuardDuty findings…", 78)
            await asyncio.sleep(0)
            gd_f = await asyncio.to_thread(_check_guardduty, session, region)

            cspm_findings = (
                s3_pub_f + iam_root_f + iam_mfa_f + iam_admin_f +
                ec2_f + ct_f + pw_f +
                ebs_f + rds_f + vpc_f + s3_log_f + kms_f + gd_f
            )
            logger.info("CSPM complete: %d findings across 13 checks", len(cspm_findings))

        else:
            # No AWS creds — step through mock data with visible delays
            steps = [
                ("Initialising AWS session…",        8),
                ("Scanning S3 bucket permissions…",  13),
                ("Auditing IAM root account…",        20),
                ("Checking IAM user MFA settings…",  27),
                ("Checking IAM admin policies…",      33),
                ("Scanning EC2 security groups…",     40),
                ("Verifying CloudTrail logging…",     47),
                ("Checking IAM password policies…",  52),
                ("Checking EBS volume encryption…",  57),
                ("Checking RDS instance encryption…",62),
                ("Checking VPC flow logs…",           66),
                ("Checking S3 access logging…",       70),
                ("Checking KMS key rotation…",        74),
                ("Pulling GuardDuty findings…",       78),
            ]
            for step_label, pct in steps:
                _set_progress(user.id, step_label, pct)
                await asyncio.sleep(0.4)
            cspm_findings = MOCK_FINDINGS

        all_findings_raw.extend(cspm_findings)

        # ── CWPP scan ────────────────────────────────────────────────────────
        _set_progress(user.id, "Running container vulnerability scan…", 83)
        await asyncio.sleep(0)
        cwpp_findings = await asyncio.to_thread(run_cwpp_scan, image_name)
        all_findings_raw.extend(cwpp_findings)

        # ── Risk scoring ─────────────────────────────────────────────────────
        _set_progress(user.id, "Calculating risk score…", 92)
        await asyncio.sleep(0)
        risk_score = await asyncio.to_thread(score_findings, all_findings_raw)

        # ── Save to DB ───────────────────────────────────────────────────────
        _set_progress(user.id, "Saving results to database…", 97)
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for raw in all_findings_raw:
            severity = raw.get("severity", "LOW")
            if severity in severity_counts:
                severity_counts[severity] += 1

            finding = models.Finding(
                scan_id=scan.id,
                finding_id=raw["finding_id"],
                finding_type=models.FindingTypeEnum(raw["finding_type"]),
                severity=models.SeverityEnum(severity),
                title=raw.get("title", ""),
                description=raw.get("description", ""),
                resource=raw.get("resource", ""),
                region=raw.get("region", ""),
                fix_recommendation=raw.get("fix_recommendation", ""),
                cve_id=raw.get("cve_id"),
                cvss_score=raw.get("cvss_score"),
                affected_package=raw.get("affected_package"),
                fixed_version=raw.get("fixed_version"),
            )
            db.add(finding)

        scan.status         = models.ScanStatusEnum.COMPLETED
        scan.risk_score     = risk_score
        scan.completed_at   = _utcnow()
        scan.critical_count = severity_counts["CRITICAL"]
        scan.high_count     = severity_counts["HIGH"]
        scan.medium_count   = severity_counts["MEDIUM"]
        scan.low_count      = severity_counts["LOW"]

        db.commit()
        db.refresh(scan)

        logger.info(
            "Scan #%d complete: score=%.1f, total=%d (C=%d H=%d M=%d L=%d)",
            scan.id, risk_score, len(all_findings_raw),
            severity_counts["CRITICAL"], severity_counts["HIGH"],
            severity_counts["MEDIUM"], severity_counts["LOW"],
        )

        _set_progress(user.id, "Scan complete!", 100, done=True)
        return scan

    except Exception as e:
        logger.exception("Scan failed: %s", e)
        _set_progress(user.id, f"Scan failed — {type(e).__name__}", 0, done=True)
        scan.status = models.ScanStatusEnum.FAILED
        db.commit()
        raise e
