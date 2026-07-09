"""
routers/totp.py — TOTP two-factor authentication
POST /api/auth/totp/setup          → generate secret + QR code + backup codes
POST /api/auth/totp/enable         → verify first code to activate 2FA
POST /api/auth/totp/complete-login → verify code after password login
POST /api/auth/totp/disable        → turn off 2FA (requires password)
"""

import json
import secrets
import string
import io
import base64
from datetime import timedelta

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..auth import (
    get_current_user,
    verify_password,
    hash_password,
    create_access_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    SECRET_KEY,
    ALGORITHM,
)
from jose import jwt, JWTError

router = APIRouter(prefix="/api/auth/totp", tags=["totp"])

APP_NAME = "ShieldScan"
BACKUP_CODE_COUNT = 8


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _generate_backup_codes() -> tuple[list[str], list[str]]:
    """Return (plaintext_codes, hashed_codes). Show plaintext once, store hashed."""
    alphabet = string.ascii_uppercase + string.digits
    codes = []
    for _ in range(BACKUP_CODE_COUNT):
        part1 = "".join(secrets.choice(alphabet) for _ in range(4))
        part2 = "".join(secrets.choice(alphabet) for _ in range(4))
        codes.append(f"{part1}-{part2}")
    hashed = [hash_password(c) for c in codes]
    return codes, hashed


def _make_qr_base64(secret: str, email: str) -> str:
    """Generate a QR code PNG as a base64 data URL."""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=APP_NAME)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def _verify_backup_code(plain: str, hashed_list: list[str]) -> int | None:
    """Return index of matched backup code, or None if no match."""
    plain = plain.upper().replace(" ", "")
    for i, h in enumerate(hashed_list):
        if verify_password(plain, h):
            return i
    return None


# ─────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────

class SetupResponse(BaseModel):
    secret: str
    qr_code: str          # base64 PNG data URL
    backup_codes: list[str]


class EnableRequest(BaseModel):
    code: str             # 6-digit TOTP code from authenticator app


class CompleteLoginRequest(BaseModel):
    partial_token: str    # short-lived token from /login
    code: str             # 6-digit TOTP or backup code


class DisableRequest(BaseModel):
    password: str
    code: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    email: str
    full_name: str | None


# ─────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────

@router.post("/setup", response_model=SetupResponse)
def setup(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Generate a new TOTP secret, QR code, and backup codes.
    Does NOT enable 2FA yet — user must call /enable after scanning.
    """
    secret = pyotp.random_base32()
    plain_codes, hashed_codes = _generate_backup_codes()

    current_user.totp_secret = secret
    current_user.backup_codes = json.dumps(hashed_codes)
    # totp_enabled stays False until /enable is called
    db.commit()

    qr = _make_qr_base64(secret, current_user.email)

    return SetupResponse(
        secret=secret,
        qr_code=qr,
        backup_codes=plain_codes,
    )


@router.post("/enable")
def enable(
    payload: EnableRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify the first TOTP code to confirm the user scanned correctly, then enable 2FA."""
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="Run /setup first.")

    totp = pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid code. Make sure your device clock is correct.")

    current_user.totp_enabled = True
    db.commit()
    return {"message": "Two-factor authentication enabled successfully."}


@router.post("/complete-login", response_model=TokenResponse)
def complete_login(payload: CompleteLoginRequest, db: Session = Depends(get_db)):
    """
    Second step of login — verify TOTP code (or backup code) after password was accepted.
    Accepts the partial_token issued by /login and returns a full access token.
    """
    # Decode partial token
    try:
        claims = jwt.decode(payload.partial_token, SECRET_KEY, algorithms=[ALGORITHM])
        if claims.get("type") != "totp_pending":
            raise HTTPException(status_code=401, detail="Invalid token type.")
        user_id = int(claims["sub"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expired or invalid. Please log in again.")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or not user.totp_enabled:
        raise HTTPException(status_code=401, detail="Invalid session.")

    code = payload.code.strip().upper()

    # Try TOTP first
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(code, valid_window=1):
        # Valid TOTP — issue full token
        token = create_access_token(
            data={"sub": str(user.id), "email": user.email},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return TokenResponse(access_token=token, user_id=user.id, email=user.email, full_name=user.full_name)

    # Try backup codes
    if user.backup_codes:
        hashed_list = json.loads(user.backup_codes)
        idx = _verify_backup_code(code, hashed_list)
        if idx is not None:
            # Consume the backup code (mark as used by replacing with empty hash)
            hashed_list[idx] = ""
            user.backup_codes = json.dumps(hashed_list)
            db.commit()
            token = create_access_token(
                data={"sub": str(user.id), "email": user.email},
                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            )
            sum(1 for c in hashed_list if c)
            # Return token — frontend can warn user about remaining backup codes
            return TokenResponse(access_token=token, user_id=user.id, email=user.email, full_name=user.full_name)

    raise HTTPException(status_code=401, detail="Invalid code. Try again or use a backup code.")


@router.post("/disable")
def disable(
    payload: DisableRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disable 2FA — requires current password + valid TOTP code as confirmation."""
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password.")

    if current_user.totp_enabled and current_user.totp_secret:
        totp = pyotp.TOTP(current_user.totp_secret)
        if not totp.verify(payload.code, valid_window=1):
            raise HTTPException(status_code=400, detail="Invalid authenticator code.")

    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.backup_codes = None
    db.commit()
    return {"message": "Two-factor authentication disabled."}
