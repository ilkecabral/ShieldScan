"""
routers/admin.py — Admin panel API
All endpoints require a valid JWT from an account with is_admin=True.

Endpoints:
  POST   /api/admin/login              → admin-specific login (returns token)
  GET    /api/admin/stats              → platform-wide counts
  GET    /api/admin/users              → paginated user list with filters
  PATCH  /api/admin/users/{id}         → update is_active / is_admin / restore soft-delete
  DELETE /api/admin/users/{id}         → hard-delete a user and all their data

Bootstrapping the first admin:
  Run in the backend folder:
    python -c "
    from app.backend.database import SessionLocal
    from app.backend import models
    db = SessionLocal()
    u = db.query(models.User).filter(models.User.email == 'your@email.com').first()
    u.is_admin = True
    db.commit()
    print('Done')
    "
"""

import logging
from datetime import datetime, timedelta, timezone


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from .. import models
from ..auth import verify_password, create_access_token, get_current_admin, ACCESS_TOKEN_EXPIRE_MINUTES

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin", tags=["admin"])


# ─────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────

class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserPatchRequest(BaseModel):
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    restore: Optional[bool] = None   # if True, clears deleted_at


class UserRow(BaseModel):
    id: int
    email: str
    full_name: Optional[str]
    is_active: bool
    is_admin: bool
    aws_connected: bool
    email_verified: bool
    totp_enabled: bool
    created_at: str
    deleted_at: Optional[str]
    scan_count: int
    failed_login_attempts: int
    locked_until: Optional[str]

    class Config:
        from_attributes = True


# ─────────────────────────────────────────
# Admin login — separate from /api/auth/login
# Returns same JWT but only for admin accounts
# ─────────────────────────────────────────

@router.post("/login")
def admin_login(payload: AdminLoginRequest, db: Session = Depends(get_db)):
    """
    Admin-only login. Identical to the normal login but rejects non-admin accounts
    so regular user credentials can't be used to access the admin panel.
    """
    user = db.query(models.User).filter(models.User.email == payload.email).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled.")

    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account does not have admin access.",
        )

    token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    logger.info("Admin login: user_id=%s email=%s", user.id, user.email)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
    }


# ─────────────────────────────────────────
# Platform stats
# ─────────────────────────────────────────

@router.get("/stats")
def get_stats(
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Platform-wide aggregate counts for the admin dashboard."""
    total_users     = db.query(models.User).count()
    active_users    = db.query(models.User).filter(models.User.is_active == True, models.User.deleted_at == None).count()
    deleted_users   = db.query(models.User).filter(models.User.deleted_at != None).count()
    admin_users     = db.query(models.User).filter(models.User.is_admin == True).count()
    locked_users    = db.query(models.User).filter(
        models.User.locked_until != None,
        models.User.locked_until > _utcnow()
    ).count()
    aws_connected   = db.query(models.User).filter(models.User.aws_connected == True).count()
    total_scans     = db.query(models.Scan).count()
    total_findings  = db.query(models.Finding).count()

    # Users registered in last 7 days
    week_ago = _utcnow() - timedelta(days=7)
    new_this_week = db.query(models.User).filter(models.User.created_at >= week_ago).count()

    return {
        "total_users":    total_users,
        "active_users":   active_users,
        "deleted_users":  deleted_users,
        "admin_users":    admin_users,
        "locked_users":   locked_users,
        "aws_connected":  aws_connected,
        "total_scans":    total_scans,
        "total_findings": total_findings,
        "new_this_week":  new_this_week,
    }


# ─────────────────────────────────────────
# User list
# ─────────────────────────────────────────

@router.get("/users")
def list_users(
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
    search: str = Query("", description="Filter by email or name"),
    show_deleted: bool = Query(False, description="Include soft-deleted accounts"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    """Paginated user list with optional search and deleted-account filter."""
    q = db.query(models.User)

    if search:
        like = f"%{search}%"
        q = q.filter(
            (models.User.email.ilike(like)) | (models.User.full_name.ilike(like))
        )

    if not show_deleted:
        q = q.filter(models.User.deleted_at == None)

    total = q.count()
    users = q.order_by(models.User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    rows = []
    for u in users:
        rows.append({
            "id":                   u.id,
            "email":                u.email,
            "full_name":            u.full_name,
            "is_active":            u.is_active,
            "is_admin":             u.is_admin,
            "aws_connected":        u.aws_connected,
            "email_verified":       bool(u.email_verified),
            "totp_enabled":         u.totp_enabled,
            "created_at":           u.created_at.isoformat() if u.created_at else None,
            "deleted_at":           u.deleted_at.isoformat() if u.deleted_at else None,
            "scan_count":           len(u.scans),
            "failed_login_attempts": u.failed_login_attempts,
            "locked_until":         u.locked_until.isoformat() if u.locked_until else None,
        })

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "users": rows,
    }


# ─────────────────────────────────────────
# Update a user
# ─────────────────────────────────────────

@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserPatchRequest,
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Toggle is_active, is_admin, or restore a soft-deleted account."""
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot modify your own account from the admin panel.",
        )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if payload.is_active is not None:
        user.is_active = payload.is_active
        # Clear lockout when reactivating
        if payload.is_active:
            user.failed_login_attempts = 0
            user.locked_until = None

    if payload.is_admin is not None:
        user.is_admin = payload.is_admin

    if payload.restore:
        user.deleted_at = None
        user.recovery_token_hash = None
        user.recovery_token_expires = None
        logger.info("Admin restored account: user_id=%s by admin_id=%s", user_id, admin.id)

    db.commit()
    logger.info("Admin updated user_id=%s: %s by admin_id=%s", user_id, payload.dict(exclude_none=True), admin.id)

    return {"message": f"User {user_id} updated.", "user_id": user_id}


# ─────────────────────────────────────────
# Dashboard overview (charts + recent activity)
# ─────────────────────────────────────────

@router.get("/overview")
def get_overview(
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """
    Rich data bundle for the admin dashboard overview tab.
    Returns: scans per day (7 days), findings by severity,
             recent users (5), recent scans (5).
    """
    # Scans per day — last 7 days
    scans_per_day = []
    for i in range(6, -1, -1):
        day_start = (_utcnow() - timedelta(days=i)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        day_end = day_start.replace(hour=23, minute=59, second=59, microsecond=999999)
        count = db.query(models.Scan).filter(
            models.Scan.started_at >= day_start,
            models.Scan.started_at <= day_end,
        ).count()
        scans_per_day.append({
            "date": day_start.strftime("%b %d"),
            "count": count,
        })

    # Findings by severity
    sev_rows = db.query(
        models.Finding.severity, func.count(models.Finding.id)
    ).group_by(models.Finding.severity).all()
    sev_map = {}
    for s, c in sev_rows:
        key = s.value if hasattr(s, "value") else str(s)
        sev_map[key] = c

    # Recent 5 users
    recent_users = (
        db.query(models.User)
        .order_by(models.User.created_at.desc())
        .limit(5)
        .all()
    )

    # Recent 5 scans (with user pre-loaded)
    recent_scans = (
        db.query(models.Scan)
        .options(joinedload(models.Scan.user))
        .order_by(models.Scan.started_at.desc())
        .limit(5)
        .all()
    )

    return {
        "scans_per_day": scans_per_day,
        "findings_by_severity": {
            "CRITICAL": sev_map.get("CRITICAL", 0),
            "HIGH":     sev_map.get("HIGH", 0),
            "MEDIUM":   sev_map.get("MEDIUM", 0),
            "LOW":      sev_map.get("LOW", 0),
            "INFO":     sev_map.get("INFO", 0),
        },
        "recent_users": [
            {
                "id":         u.id,
                "email":      u.email,
                "full_name":  u.full_name,
                "is_active":  u.is_active,
                "is_admin":   u.is_admin,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in recent_users
        ],
        "recent_scans": [
            {
                "id":             s.id,
                "user_id":        s.user_id,
                "user_email":     s.user.email if s.user else "—",
                "status":         s.status.value if hasattr(s.status, "value") else str(s.status),
                "risk_score":     s.risk_score,
                "critical_count": s.critical_count,
                "high_count":     s.high_count,
                "medium_count":   s.medium_count,
                "low_count":      s.low_count,
                "started_at":     s.started_at.isoformat() if s.started_at else None,
                "completed_at":   s.completed_at.isoformat() if s.completed_at else None,
            }
            for s in recent_scans
        ],
    }


# ─────────────────────────────────────────
# All scans (admin view)
# ─────────────────────────────────────────

@router.get("/scans")
def list_scans(
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    scan_status: str = Query("", alias="status"),
    user_id: int = Query(0),
):
    """Paginated list of all scans across all users."""
    q = db.query(models.Scan).options(joinedload(models.Scan.user))

    if scan_status:
        # Match enum value case-insensitively
        from ..models import ScanStatusEnum
        try:
            q = q.filter(models.Scan.status == ScanStatusEnum(scan_status.upper()))
        except ValueError:
            pass

    if user_id:
        q = q.filter(models.Scan.user_id == user_id)

    total = q.count()
    scans = q.order_by(models.Scan.started_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    rows = []
    for s in scans:
        rows.append({
            "id":             s.id,
            "user_id":        s.user_id,
            "user_email":     s.user.email if s.user else "—",
            "user_name":      s.user.full_name if s.user else "—",
            "status":         s.status.value if hasattr(s.status, "value") else str(s.status),
            "risk_score":     s.risk_score,
            "critical_count": s.critical_count,
            "high_count":     s.high_count,
            "medium_count":   s.medium_count,
            "low_count":      s.low_count,
            "finding_count":  len(s.findings),
            "started_at":     s.started_at.isoformat() if s.started_at else None,
            "completed_at":   s.completed_at.isoformat() if s.completed_at else None,
        })

    return {"total": total, "page": page, "per_page": per_page, "scans": rows}


# ─────────────────────────────────────────
# Hard-delete a user
# ─────────────────────────────────────────

@router.delete("/users/{user_id}")
def hard_delete_user(
    user_id: int,
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """
    Permanently delete a user and all related data (scans, findings, passkeys).
    This is irreversible. Only use after the 30-day soft-delete window has passed,
    or for compliance/GDPR erasure requests.
    """
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account from the admin panel.",
        )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    email = user.email
    db.delete(user)
    db.commit()
    logger.warning("HARD DELETE: user_id=%s email=%s by admin_id=%s", user_id, email, admin.id)

    return {"message": f"User {user_id} ({email}) permanently deleted."}
