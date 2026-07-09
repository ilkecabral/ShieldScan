"""
routers/scans.py — Scan management endpoints

POST /api/scan/run          → trigger a full CSPM + CWPP + risk scoring scan
GET  /api/scan/findings     → get findings from the latest (or specific) scan
GET  /api/scan/history      → list all past scans for the current user
GET  /api/scan/stats        → summary stats for the dashboard (risk score, counts)
"""

import asyncio
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

from ..database import get_db, SessionLocal
from .. import models
from ..auth import get_current_user
from ..auth import decode_token, oauth2_scheme
from ..scan_manager import run_full_scan, get_scan_progress, _set_progress

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["scans"])


# ─────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────

class ScanRequest(BaseModel):
    image_name: str = "nginx:latest"    # container image to scan with CWPP


class FindingOut(BaseModel):
    id: int
    finding_id: str
    finding_type: str
    severity: str
    title: str
    description: Optional[str]
    resource: Optional[str]
    region: Optional[str]
    fix_recommendation: Optional[str]
    is_resolved: bool
    cve_id: Optional[str]
    cvss_score: Optional[float]
    affected_package: Optional[str]
    fixed_version: Optional[str]

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    status: str
    risk_score: Optional[float]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: str
    completed_at: Optional[str]

    class Config:
        from_attributes = True


class StatsOut(BaseModel):
    risk_score: float
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    last_scan_at: Optional[str]
    aws_connected: bool


# ─────────────────────────────────────────
# Helper
# ─────────────────────────────────────────

def _scan_to_dict(scan: models.Scan) -> dict:
    return {
        "id": scan.id,
        "status": scan.status.value,
        "risk_score": scan.risk_score,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "started_at": scan.started_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


def _finding_to_dict(f: models.Finding) -> dict:
    return {
        "id": f.id,
        "finding_id": f.finding_id,
        "finding_type": f.finding_type.value,
        "severity": f.severity.value,
        "title": f.title,
        "description": f.description,
        "resource": f.resource,
        "region": f.region,
        "fix_recommendation": f.fix_recommendation,
        "is_resolved": f.is_resolved,
        "cve_id": f.cve_id,
        "cvss_score": f.cvss_score,
        "affected_package": f.affected_package,
        "fixed_version": f.fixed_version,
    }


# ─────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────

async def _background_scan(user_id: int, image_name: str) -> None:
    """
    Background coroutine that runs the full scan with its own DB session.
    Called after the HTTP response for /run is already sent — the request DB
    session is closed by then, so we must open a fresh one here.
    """
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            logger.error("Background scan: user %d not found", user_id)
            return
        await run_full_scan(user=user, db=db, image_name=image_name)
    except Exception:
        logger.exception("Background scan failed for user %d", user_id)
    finally:
        db.close()


@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(get_current_user),
):
    """
    Trigger a full CSPM + CWPP scan for the current user.

    Returns 202 immediately — scan runs as a background task so the uvicorn
    worker is never blocked for 60+ seconds.

    Poll GET /api/scan/progress with the same Bearer token to watch progress.
    When done=true, call GET /api/scan/history or GET /api/scan/findings for results.
    """
    _set_progress(current_user.id, "Scan queued…", 2)
    background_tasks.add_task(_background_scan, current_user.id, payload.image_name)
    return {
        "message": "Scan started",
        "status": "RUNNING",
        "poll_url": "/api/scan/progress",
        "results_url": "/api/scan/findings",
    }


@router.get("/findings")
def get_findings(
    scan_id: Optional[int] = None,
    severity: Optional[str] = None,       # filter: CRITICAL / HIGH / MEDIUM / LOW
    finding_type: Optional[str] = None,   # filter: CSPM / CWPP
    resolved: bool = False,
    page: int = 1,
    page_size: int = 50,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get findings for the current user's latest scan (or a specific scan_id).
    Supports filtering by severity, type, resolved status, and pagination.
    """
    if page < 1:
        raise HTTPException(status_code=400, detail="page must be ≥ 1")
    if not (1 <= page_size <= 200):
        raise HTTPException(status_code=400, detail="page_size must be between 1 and 200")

    # Find the scan to pull findings from
    if scan_id:
        scan = db.query(models.Scan).filter(
            models.Scan.id == scan_id,
            models.Scan.user_id == current_user.id,
        ).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = (
            db.query(models.Scan)
            .filter(
                models.Scan.user_id == current_user.id,
                models.Scan.status == models.ScanStatusEnum.COMPLETED,
            )
            .order_by(models.Scan.completed_at.desc())
            .first()
        )
        if not scan:
            return {"findings": [], "scan_id": None, "message": "No completed scans yet — run a scan first"}

    # Build query with filters
    query = db.query(models.Finding).filter(
        models.Finding.scan_id == scan.id,
        models.Finding.is_resolved == resolved,
    )
    if severity:
        try:
            query = query.filter(models.Finding.severity == models.SeverityEnum(severity.upper()))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
    if finding_type:
        try:
            query = query.filter(models.Finding.finding_type == models.FindingTypeEnum(finding_type.upper()))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid finding_type: {finding_type}")

    total = query.count()
    offset = (page - 1) * page_size
    findings = query.order_by(models.Finding.id).offset(offset).limit(page_size).all()

    return {
        "scan_id": scan.id,
        "risk_score": scan.risk_score,
        "findings": [_finding_to_dict(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/stats")
def get_stats(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Dashboard summary: risk score + finding counts from the latest scan.
    Returns zeros if no scan has been run yet.
    """
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
        return StatsOut(
            risk_score=0.0,
            total_findings=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            last_scan_at=None,
            aws_connected=current_user.aws_connected,
        )

    total = (
        latest_scan.critical_count
        + latest_scan.high_count
        + latest_scan.medium_count
        + latest_scan.low_count
    )

    return StatsOut(
        risk_score=latest_scan.risk_score or 0.0,
        total_findings=total,
        critical=latest_scan.critical_count,
        high=latest_scan.high_count,
        medium=latest_scan.medium_count,
        low=latest_scan.low_count,
        last_scan_at=latest_scan.completed_at.isoformat() if latest_scan.completed_at else None,
        aws_connected=current_user.aws_connected,
    )


@router.get("/progress")
def get_progress(token: str = Depends(oauth2_scheme)):
    """
    Poll the real-time progress of the current user's active scan.
    Returns: { step: str, pct: int, done: bool }
    Intentionally avoids a DB query so it is never blocked by SQLite write locks
    during the scan's findings-save phase.
    """
    token_data = decode_token(token)
    return get_scan_progress(token_data.user_id)


@router.get("/history")
def get_scan_history(
    limit: int = 10,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List the user's past scans, most recent first."""
    scans = (
        db.query(models.Scan)
        .filter(models.Scan.user_id == current_user.id)
        .order_by(models.Scan.started_at.desc())
        .limit(limit)
        .all()
    )
    return {"scans": [_scan_to_dict(s) for s in scans]}


@router.get("/report")
def download_report(
    scan_id: Optional[int] = None,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate and download a PDF audit report for the latest (or specified) scan.
    Returns a downloadable PDF file.
    """
    from fpdf import FPDF

    # Resolve which scan to report on
    if scan_id:
        scan = db.query(models.Scan).filter(
            models.Scan.id == scan_id,
            models.Scan.user_id == current_user.id,
        ).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = (
            db.query(models.Scan)
            .filter(
                models.Scan.user_id == current_user.id,
                models.Scan.status == models.ScanStatusEnum.COMPLETED,
            )
            .order_by(models.Scan.completed_at.desc())
            .first()
        )
        if not scan:
            raise HTTPException(status_code=404, detail="No completed scans found. Run a scan first.")

    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan.id).all()

    # ── Build PDF ─────────────────────────────────────────────────────────────
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    SEVERITY_COLORS = {
        "CRITICAL": (220, 38, 38),    # red
        "HIGH":     (234, 88, 12),    # orange
        "MEDIUM":   (202, 138, 4),    # amber
        "LOW":      (37, 99, 235),    # blue
    }
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity.value, 9))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    scan_date = scan.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.completed_at else "N/A"
    report_date = _utcnow().strftime("%Y-%m-%d %H:%M UTC")
    user_email = current_user.email
    risk_score = scan.risk_score or 0.0

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Header bar
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 30, "F")
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(10, 8)
    pdf.cell(0, 12, "ShieldScan  |  Security Audit Report", ln=True)

    # Subheader
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(148, 163, 184)
    pdf.set_xy(10, 21)
    pdf.cell(0, 6, "Cloud-Native Application Protection Platform", ln=True)

    pdf.ln(8)

    # Meta block
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(30, 30, 30)
    meta = [
        ("Account",    user_email),
        ("Scan Date",  scan_date),
        ("Report Generated", report_date),
        ("Scan ID",    str(scan.id)),
    ]
    for label, value in meta:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(50, 6, f"{label}:", ln=False)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, value, ln=True)

    pdf.ln(4)

    # Risk score box
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, f"  Overall Risk Score: {risk_score:.1f} / 100", fill=True, ln=True)
    pdf.ln(2)

    # Summary table
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "Executive Summary", ln=True)

    col_w = 40
    headers = ["Severity", "Count", "Status"]
    pdf.set_fill_color(226, 232, 240)
    pdf.set_font("Helvetica", "B", 10)
    for h in headers:
        pdf.cell(col_w, 8, h, border=1, fill=True)
    pdf.ln()

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        r, g, b = SEVERITY_COLORS[sev]
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(col_w, 7, f"  {sev}", border=1, fill=True)
        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(col_w, 7, str(counts.get(sev, 0)), border=1, fill=True)
        status_text = "Requires immediate action" if sev == "CRITICAL" else ("Action required" if sev == "HIGH" else "Review recommended")
        pdf.cell(col_w, 7, status_text, border=1, fill=True)
        pdf.ln()

    pdf.ln(6)

    # Findings detail
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, f"Findings Detail  ({len(findings)} total)", ln=True)

    for idx, f in enumerate(sorted_findings, 1):
        sev = f.severity.value
        r, g, b = SEVERITY_COLORS.get(sev, (100, 100, 100))

        # Finding header
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        title_text = f"  [{sev}]  {f.title}"
        # Truncate long titles
        if len(title_text) > 80:
            title_text = title_text[:77] + "..."
        pdf.cell(0, 8, title_text, fill=True, ln=True)

        # Finding body
        pdf.set_fill_color(248, 250, 252)
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("Helvetica", "", 9)

        body_lines = [
            ("Resource",       f.resource or "N/A"),
            ("Region",         f.region or "N/A"),
            ("Finding ID",     f.finding_id),
        ]
        for label, value in body_lines:
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(35, 5, f"  {label}:", fill=True)
            pdf.set_font("Helvetica", "", 9)
            # Truncate long values
            val_str = str(value)
            if len(val_str) > 90:
                val_str = val_str[:87] + "..."
            pdf.cell(0, 5, val_str, fill=True, ln=True)

        if f.description:
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(35, 5, "  Description:", fill=True)
            pdf.set_font("Helvetica", "", 9)
            desc = f.description
            if len(desc) > 150:
                desc = desc[:147] + "..."
            pdf.multi_cell(0, 5, desc, fill=True)

        if f.fix_recommendation:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(240, 253, 244)
            pdf.set_text_color(22, 101, 52)
            pdf.cell(35, 5, "  Recommendation:", fill=True)
            pdf.set_font("Helvetica", "", 9)
            rec = f.fix_recommendation
            if len(rec) > 180:
                rec = rec[:177] + "..."
            pdf.multi_cell(0, 5, rec, fill=True)

        pdf.set_text_color(30, 30, 30)
        pdf.ln(2)

    # Footer on last page
    pdf.set_y(-20)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, f"Generated by ShieldScan CNAPP  •  {report_date}  •  Confidential", align="C")

    # Output PDF bytes
    pdf_bytes = pdf.output()

    filename = f"shieldscan-audit-{scan.id}-{_utcnow().strftime('%Y%m%d')}.pdf"
    return Response(
        content=bytes(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
def delete_scan(
    scan_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Delete a scan and all its findings.
    Cascade delete is handled by the ORM (cascade='all, delete-orphan').
    """
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id,
        models.Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": f"Scan {scan_id} deleted"}


@router.patch("/findings/{finding_id}/resolve", status_code=status.HTTP_200_OK)
def resolve_finding(
    finding_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mark a finding as resolved."""
    finding = (
        db.query(models.Finding)
        .join(models.Scan)
        .filter(
            models.Finding.id == finding_id,
            models.Scan.user_id == current_user.id,
        )
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.is_resolved = True
    db.commit()
    return {"message": "Finding marked as resolved", "finding_id": finding_id}
