"""
routers/reset.py — Password reset and lost key pair recovery

Password reset flow:
  1. POST /api/auth/password-reset/request  → generate token, store hashed, return token
     (in production: send token via email — SMTP wiring left as TODO)
  2. POST /api/auth/password-reset/confirm  → verify token + set new password

Lost key recovery:
  - Key regeneration is handled by POST /api/auth/keypair/generate (idcard.py)
  - That endpoint requires a valid Bearer token (password login still works even if key is lost)
  - So the "lost key" path is: login normally → Settings → Security → Regenerate Key
  - No separate endpoint needed; this file only handles password reset

Change password (authenticated):
  POST /api/auth/password-reset/change → requires current token + old password + new password
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..auth import hash_password, verify_password, get_current_user
from ..services.email_service import send_password_reset_email, is_email_configured

router = APIRouter(prefix="/api/auth/password-reset", tags=["password-reset"])

TOKEN_EXPIRY_MINUTES = 60   # reset link valid for 1 hour


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _generate_reset_token() -> str:
    """Generate a 32-byte cryptographically secure hex token."""
    return secrets.token_hex(32)   # 64 hex chars = 256 bits


def _hash_token(token: str) -> str:
    """SHA-256 hash of the token for safe storage."""
    return hashlib.sha256(token.encode()).hexdigest()


# ─────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────

class ResetRequestPayload(BaseModel):
    email: EmailStr


class ResetConfirmPayload(BaseModel):
    token: str
    new_password: str


class ChangePasswordPayload(BaseModel):
    old_password: str
    new_password: str


# ─────────────────────────────────────────
# Password validation (same rules as registration)
# ─────────────────────────────────────────

import re

def _validate_password(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one special character."
    return None


# ─────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────

@router.post("/request")
def request_reset(
    payload: ResetRequestPayload,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Request a password reset.
    If email is configured → sends a reset link to the user's inbox (token hidden from response).
    If email is NOT configured (dev mode) → returns the token directly so testing still works.
    Always returns 200 regardless of whether the email exists (prevents enumeration).
    """
    user = db.query(models.User).filter(models.User.email == payload.email).first()

    token = _generate_reset_token()

    if user:
        user.reset_token_hash = _hash_token(token)
        user.reset_token_expires = _utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
        db.commit()

        if is_email_configured():
            background_tasks.add_task(
                send_password_reset_email,
                user.email,
                user.full_name or "",
                token,
            )
            return {
                "message": "Password reset link sent to your email address.",
                "expires_in_minutes": TOKEN_EXPIRY_MINUTES,
            }
        else:
            # Dev mode — expose token so you can test without SMTP
            return {
                "message": "If that email is registered, a reset token has been generated.",
                "reset_token": token,
                "expires_in_minutes": TOKEN_EXPIRY_MINUTES,
                "dev_note": "Email not configured. Set EMAIL_USER + EMAIL_PASSWORD in .env to send real emails.",
            }

    # Email not found — same shape to prevent enumeration
    return {
        "message": "If that email is registered, a reset link has been sent.",
        "expires_in_minutes": TOKEN_EXPIRY_MINUTES,
    }


@router.post("/confirm")
def confirm_reset(payload: ResetConfirmPayload, db: Session = Depends(get_db)):
    """
    Verify reset token and set a new password.
    Clears the token after use (single-use).
    """
    token_hash = _hash_token(payload.token.strip())

    user = db.query(models.User).filter(
        models.User.reset_token_hash == token_hash
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token. Request a new one."
        )

    if not user.reset_token_expires or user.reset_token_expires < _utcnow():
        # Expired — clear it
        user.reset_token_hash = None
        user.reset_token_expires = None
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Reset token has expired (valid for {TOKEN_EXPIRY_MINUTES} minutes). Request a new one."
        )

    # Validate new password strength
    err = _validate_password(payload.new_password)
    if err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=err)

    # Set new password and clear token (single-use)
    user.hashed_password = hash_password(payload.new_password)
    user.reset_token_hash = None
    user.reset_token_expires = None
    # Also reset lockout counters if the account was locked
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    return {"message": "Password updated successfully. You can now log in with your new password."}


@router.post("/change")
def change_password(
    payload: ChangePasswordPayload,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Change password while authenticated (Settings → Security).
    Requires the current password for confirmation.
    """
    if not verify_password(payload.old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect."
        )

    err = _validate_password(payload.new_password)
    if err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=err)

    if payload.old_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current one."
        )

    current_user.hashed_password = hash_password(payload.new_password)
    db.commit()

    return {"message": "Password changed successfully."}
