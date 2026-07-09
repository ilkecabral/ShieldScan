"""
routers/recover.py — Account recovery for soft-deleted users

Two recovery paths:

  Path A — Sign-in recovery (instant):
    POST /api/auth/account/recover/login
    Body: { email, password }
    → If credentials are valid AND the account is soft-deleted within 30-day window
      → clears deleted_at, issues a full access token (user is back immediately)

  Path B — Email-link recovery:
    POST /api/auth/account/recover/request
    Body: { email }
    → Generates a recovery token, stores hash, emails a link (#recover?token=XXX)
    → Always returns 200 (no email enumeration)

    POST /api/auth/account/recover/confirm
    Body: { token }
    → Verifies token hash, clears deleted_at, issues full access token

Both paths refuse accounts that are not in a soft-deleted state, or whose
30-day window has already expired (permanently deleted-eligible).
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..database import get_db
from .. import models
from ..auth import verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from ..services.email_service import send_account_recovery_email, is_email_configured

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth/account/recover", tags=["account-recovery"])
limiter = Limiter(key_func=get_remote_address)

RECOVERY_TOKEN_EXPIRY_MINUTES = 60
SOFT_DELETE_GRACE_DAYS = 30


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _generate_token() -> str:
    return secrets.token_hex(32)   # 64 hex chars


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _is_recoverable(user: models.User) -> bool:
    """Return True if the account is soft-deleted and still within the 30-day grace window."""
    if user.deleted_at is None:
        return False
    grace_ends = user.deleted_at + timedelta(days=SOFT_DELETE_GRACE_DAYS)
    return _utcnow() < grace_ends


def _reactivate(user: models.User, db: Session) -> None:
    """Clear soft-delete flag and any pending recovery token."""
    user.deleted_at = None
    user.recovery_token_hash = None
    user.recovery_token_expires = None
    db.commit()
    logger.info("Account recovered: user_id=%s email=%s", user.id, user.email)


def _issue_token(user: models.User) -> dict:
    token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "message": "Account recovered successfully. Welcome back!",
    }


# ─────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────

class RecoverLoginRequest(BaseModel):
    email: EmailStr
    password: str


class RecoverRequestPayload(BaseModel):
    email: EmailStr


class RecoverConfirmPayload(BaseModel):
    token: str


# ─────────────────────────────────────────
# Path A — Sign-in recovery
# ─────────────────────────────────────────

@router.post("/login")
@limiter.limit("5/minute")
def recover_via_login(
    request: Request,
    payload: RecoverLoginRequest,
    db: Session = Depends(get_db),
):
    """
    Recover a soft-deleted account by signing in with the original credentials.
    If the email + password are correct and the account is within the 30-day grace window,
    the account is immediately reactivated and a full access token is returned.
    """
    user = db.query(models.User).filter(models.User.email == payload.email).first()

    # Use the same vague error for both "not found" and "wrong password"
    # to prevent enumeration of deleted accounts.
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    if not _is_recoverable(user):
        if user.deleted_at is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This account is not scheduled for deletion.",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=(
                    "The 30-day recovery window for this account has expired. "
                    "The account data is no longer recoverable."
                ),
            )

    _reactivate(user, db)
    return _issue_token(user)


# ─────────────────────────────────────────
# Path B — Email-link recovery
# ─────────────────────────────────────────

@router.post("/request")
@limiter.limit("3/minute")
def recover_via_email_request(
    request: Request,
    payload: RecoverRequestPayload,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Request an account recovery link by email.
    Only sends an email if the account exists, is soft-deleted, and is within the grace window.
    Always returns 200 to prevent enumeration.
    """
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    token = _generate_token()

    if user and _is_recoverable(user):
        user.recovery_token_hash = _hash_token(token)
        user.recovery_token_expires = _utcnow() + timedelta(minutes=RECOVERY_TOKEN_EXPIRY_MINUTES)
        db.commit()

        if is_email_configured():
            background_tasks.add_task(
                send_account_recovery_email,
                user.email,
                user.full_name or "",
                token,
            )
            return {
                "message": "If that email belongs to a recoverable account, a recovery link has been sent.",
                "expires_in_minutes": RECOVERY_TOKEN_EXPIRY_MINUTES,
            }
        else:
            # Dev mode — expose token so recovery can be tested without SMTP
            return {
                "message": "Recovery token generated (dev mode — email not configured).",
                "recovery_token": token,
                "expires_in_minutes": RECOVERY_TOKEN_EXPIRY_MINUTES,
                "dev_note": "Set EMAIL_USER + EMAIL_PASSWORD in .env to send real recovery emails.",
            }

    # Not found, not deleted, or window expired — same response shape
    return {
        "message": "If that email belongs to a recoverable account, a recovery link has been sent.",
        "expires_in_minutes": RECOVERY_TOKEN_EXPIRY_MINUTES,
    }


@router.post("/confirm")
@limiter.limit("10/minute")
def recover_via_email_confirm(
    request: Request,
    payload: RecoverConfirmPayload,
    db: Session = Depends(get_db),
):
    """
    Confirm account recovery using the token from the email link.
    Reactivates the account and returns a full access token.
    Token is single-use and expires in 60 minutes.
    """
    token_hash = _hash_token(payload.token.strip())

    user = db.query(models.User).filter(
        models.User.recovery_token_hash == token_hash
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired recovery link. Request a new one.",
        )

    if not user.recovery_token_expires or user.recovery_token_expires < _utcnow():
        user.recovery_token_hash = None
        user.recovery_token_expires = None
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Recovery link has expired (valid for {RECOVERY_TOKEN_EXPIRY_MINUTES} minutes). Request a new one.",
        )

    if not _is_recoverable(user):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="The 30-day recovery window for this account has expired.",
        )

    _reactivate(user, db)
    return _issue_token(user)
