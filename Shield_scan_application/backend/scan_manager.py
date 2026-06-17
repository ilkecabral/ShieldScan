"""
scan_manager.py — Scan Orchestrator
Owner: Kiran

Coordinates CSPM + CWPP + risk scoring into a single scan run.
Saves results to the database.

This file is complete — teammates only need to fill in their service files:
  services/cspm_service.py  → run_cspm_scan()
  services/cwpp_service.py  → run_cwpp_scan()
  services/risk_scorer.py   → score_findings()
"""

from datetime import datetime
from sqlalchemy.orm import Session

from . import models
from .auth import decrypt_aws_credential
from .services.cspm_service import run_cspm_scan
from .services.cwpp_service import run_cwpp_scan
from .services.risk_scorer import score_findings


async def run_full_scan(
    user: models.User,
    db: Session,
    image_name: str = "nginx:latest",
) -> models.Scan:
    """
    Run a complete scan for a user: CSPM + CWPP + risk scoring.
    Saves a Scan record + all Finding records to the database.

    Args:
        user:       The authenticated User (must have AWS creds if running real CSPM)
        db:         SQLAlchemy DB session
        image_name: Container image to scan with Trivy (default: nginx:latest)

    Returns:
        The completed Scan ORM object with findings attached.
    """

    # 1. Create scan record (status = RUNNING)
    scan = models.Scan(
        user_id=user.id,
        status=models.ScanStatusEnum.RUNNING,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        all_findings_raw = []

        # 2. Run CSPM scan (AWS posture)
        if user.aws_connected and user.aws_access_key_enc:
            aws_key = decrypt_aws_credential(user.aws_access_key_enc)
            aws_secret = decrypt_aws_credential(user.aws_secret_key_enc)
            cspm_findings = run_cspm_scan(aws_key, aws_secret, user.aws_region or "us-east-1")
        else:
            # No AWS creds — run with mock data so the app still works
            from .services.cspm_service import MOCK_FINDINGS
            cspm_findings = MOCK_FINDINGS

        all_findings_raw.extend(cspm_findings)

        # 3. Run CWPP scan (container CVEs)
        cwpp_findings = run_cwpp_scan(image_name)
        all_findings_raw.extend(cwpp_findings)

        # 4. Score all findings
        risk_score = score_findings(all_findings_raw)

        # 5. Save findings to DB
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

        # 6. Update scan record (status = COMPLETED)
        scan.status = models.ScanStatusEnum.COMPLETED
        scan.risk_score = risk_score
        scan.completed_at = datetime.utcnow()
        scan.critical_count = severity_counts["CRITICAL"]
        scan.high_count = severity_counts["HIGH"]
        scan.medium_count = severity_counts["MEDIUM"]
        scan.low_count = severity_counts["LOW"]

        db.commit()
        db.refresh(scan)
        return scan

    except Exception as e:
        # Mark scan as failed so the user sees an error state
        scan.status = models.ScanStatusEnum.FAILED
        db.commit()
        raise e
