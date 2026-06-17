"""
routers/scans.py — Scans and Findings endpoints
POST /api/scan/run       → trigger live/mock scan, save to database
GET  /api/scan/findings  → fetch findings from the latest completed scan
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional

from ..database import get_db
from .. import models
from ..auth import get_current_user
from ..scan_manager import run_full_scan

router = APIRouter(prefix="/api/scan", tags=["scans"])


def serialize_scan(scan: models.Scan):
    """Map DB models to the structure expected by the React frontend."""
    findings_list = []
    for f in scan.findings:
        title_lower = f.title.lower()
        res_type = "AWS Resource"
        if "s3" in title_lower:
            res_type = "S3 Bucket"
        elif "iam" in title_lower or "root" in title_lower:
            res_type = "IAM"
        elif "security group" in title_lower or "sg-" in title_lower or "ssh" in title_lower:
            res_type = "Security Group"
        elif "rds" in title_lower:
            res_type = "RDS Instance"
        elif "cloudtrail" in title_lower:
            res_type = "CloudTrail"
        elif "ec2" in title_lower or "instance" in title_lower:
            res_type = "EC2 Instance"
        elif f.finding_type == models.FindingTypeEnum.CWPP:
            res_type = "Container Image"

        # Determine cis_control
        cis_control = "Trivy CVE"
        if f.finding_type == models.FindingTypeEnum.CSPM:
            if "s3 public" in title_lower or "block public" in title_lower:
                cis_control = "CIS AWS 2.1.1"
            elif "root" in title_lower:
                cis_control = "CIS AWS 1.4"
            elif "ssh" in title_lower or "port 22" in title_lower:
                cis_control = "CIS AWS 5.2"
            elif "rds" in title_lower:
                cis_control = "CIS AWS 2.3.2"
            elif "cloudtrail" in title_lower:
                cis_control = "CIS AWS 3.1"
            elif "versioning" in title_lower:
                cis_control = "CIS AWS 2.1.3"
            elif "imds" in title_lower:
                cis_control = "CIS AWS 5.6"
            else:
                cis_control = "CIS AWS Benchmark"

        # Determine risk score if not exists
        risk_score = 10
        if f.finding_type == models.FindingTypeEnum.CWPP and f.cvss_score:
            risk_score = int(f.cvss_score * 10)
        else:
            if f.severity == models.SeverityEnum.CRITICAL:
                risk_score = 92 if "root" in title_lower else 95
            elif f.severity == models.SeverityEnum.HIGH:
                if "ssh" in title_lower:
                    risk_score = 78
                elif "rds" in title_lower:
                    risk_score = 74
                else:
                    risk_score = 70
            elif f.severity == models.SeverityEnum.MEDIUM:
                risk_score = 45 if "versioning" in title_lower else 42
            elif f.severity == models.SeverityEnum.LOW:
                risk_score = 20
            elif f.severity == models.SeverityEnum.INFO:
                risk_score = 5

        findings_list.append({
            "id": f.finding_id,
            "finding_id": f.finding_id,
            "resource": f.resource,
            "resource_type": res_type,
            "finding": f.title,
            "title": f.title,
            "severity": f.severity.value,
            "service": f.finding_type.value,
            "finding_type": f.finding_type.value,
            "region": f.region,
            "risk_score": risk_score,
            "remediation": f.fix_recommendation or "No recommendation available",
            "fix_recommendation": f.fix_recommendation,
            "cis_control": cis_control,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "affected_package": f.affected_package,
            "fixed_version": f.fixed_version,
            "is_resolved": f.is_resolved,
        })

    return {
        "findings": findings_list,
        "risk_score": scan.risk_score or 0.0,
        "total": len(findings_list),
        "critical": scan.critical_count,
        "high": scan.high_count,
        "medium": scan.medium_count,
        "low": scan.low_count,
        "scanned_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "account_id": "123456789012",
        "regions": list(set(f["region"] for f in findings_list if f["region"])) or ["us-east-1", "global"],
    }


@router.post("/run")
async def run_scan(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Trigger a live/mock scan, store in DB, and return findings + stats."""
    try:
        scan = await run_full_scan(user=current_user, db=db)
        return serialize_scan(scan)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )


@router.get("/findings")
def get_findings(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve the user's latest completed scan and return findings."""
    latest_scan = (
        db.query(models.Scan)
        .filter(
            models.Scan.user_id == current_user.id,
            models.Scan.status == models.ScanStatusEnum.COMPLETED,
        )
        .order_by(models.Scan.completed_at.desc())
        .first()
    )
    if not latest_scan:
        return {
            "findings": [],
            "risk_score": 0.0,
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "scanned_at": None,
            "account_id": "123456789012",
            "regions": ["us-east-1", "global"],
        }
    return serialize_scan(latest_scan)
