"""
routers/auth.py — Authentication endpoints
POST /api/auth/register   → create account, return token
POST /api/auth/login      → email+password → return token
GET  /api/auth/me         → return current user profile (requires token)
PUT  /api/auth/aws        → save encrypted AWS credentials for current user
"""

import re
import random
import logging
from datetime import datetime, timedelta, timezone


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..database import get_db
from .. import models
from ..auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    encrypt_aws_credential,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from ..services.email_service import send_verification_email, is_email_configured

logger = logging.getLogger(__name__)
VERIFY_CODE_EXPIRY_MINUTES = 15

router = APIRouter(prefix="/api/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _validate_password(password: str) -> str | None:
    """Returns error message if password is invalid, None if OK."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number (0-9)."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one special character (!@#$%^&*...)."
    return None


# ─────────────────────────────────────────
# Pydantic schemas (request/response shapes)
# ─────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    email: str
    full_name: str | None


class LoginResponse(BaseModel):
    # Either returns a full token OR a partial token requiring TOTP / email verification
    access_token: str | None = None
    token_type: str = "bearer"
    user_id: int | None = None
    email: str | None = None
    full_name: str | None = None
    requires_totp: bool = False
    partial_token: str | None = None
    requires_email_verification: bool = False
    verify_partial_token: str | None = None   # short-lived token for the verify-email endpoint


class UserProfile(BaseModel):
    id: int
    email: str
    full_name: str | None
    aws_connected: bool
    aws_region: str | None
    aws_account_id: Optional[str] = None
    created_at: str
    totp_enabled: bool = False
    email_verified: bool = True

    class Config:
        from_attributes = True


class VerifyEmailRequest(BaseModel):
    code: str


class ResendVerifyRequest(BaseModel):
    email: EmailStr


class AWSConnectRequest(BaseModel):
    aws_access_key: str
    aws_secret_key: str
    aws_region: str = "us-east-1"
    account_id: Optional[str] = None   # from prior /aws/validate call


class AWSConnectResponse(BaseModel):
    message: str
    aws_region: str
    account_id: Optional[str] = None


class AWSValidateRequest(BaseModel):
    aws_access_key: str
    aws_secret_key: str
    aws_region: str = "us-east-1"


# ─────────────────────────────────────────
# Routes
# ─────────────────────────────────────────

def _generate_verify_code() -> str:
    """Return a 6-digit numeric verification code."""
    return f"{random.randint(0, 999999):06d}"


def _set_verify_code(user: models.User, db: Session) -> str:
    """Generate a new code, store it on the user, commit, and return the plain code."""
    code = _generate_verify_code()
    user.email_verify_code = code
    user.email_verify_expires = _utcnow() + timedelta(minutes=VERIFY_CODE_EXPIRY_MINUTES)
    db.commit()
    return code


@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def register(
    request: Request,
    payload: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Create a new user account.
    If email is configured → sends a 6-digit verification code and returns
    requires_email_verification=True + a short-lived verify_partial_token.
    If email is NOT configured (dev mode) → marks user verified immediately
    and returns a full access token so testing isn't blocked.
    """

    # Check email not already taken
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists"
        )

    # Validate password strength (server-side — never trust the frontend alone)
    pwd_err = _validate_password(payload.password)
    if pwd_err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=pwd_err)

    email_ready = is_email_configured()

    user = models.User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        email_verified=not email_ready,   # auto-verify in dev mode
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    if email_ready:
        # Send verification code in background so the response is instant
        code = _set_verify_code(user, db)
        background_tasks.add_task(
            send_verification_email, user.email, user.full_name or "", code
        )

        # Issue a short-lived partial token for the verify-email endpoint only
        verify_token = create_access_token(
            data={"sub": str(user.id), "email": user.email, "type": "email_verify_pending"},
            expires_delta=timedelta(minutes=VERIFY_CODE_EXPIRY_MINUTES),
        )
        return {
            "requires_email_verification": True,
            "verify_partial_token": verify_token,
            "email": user.email,
            "message": f"Verification code sent to {user.email}",
        }
    else:
        # Dev / no-email mode — issue full token immediately
        logger.warning(
            "EMAIL not configured — user %s auto-verified (dev mode). "
            "Set EMAIL_USER + EMAIL_PASSWORD in .env for production.",
            user.email,
        )
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
            "requires_email_verification": False,
            "dev_note": "Email not configured — account auto-verified. Add EMAIL_USER/EMAIL_PASSWORD to .env.",
        }


@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
def login(request: Request, payload: LoginRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Authenticate with email + password.
    If TOTP is enabled, returns requires_totp=True + partial_token (5 min).
    Client must then call POST /api/auth/totp/complete-login with the code.
    """
    user = db.query(models.User).filter(models.User.email == payload.email).first()

    # Check account lockout
    if user and user.locked_until and user.locked_until > _utcnow():
        remaining = int((user.locked_until - _utcnow()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account locked due to too many failed attempts. Try again in {remaining} minute(s)."
        )

    # Validate credentials
    if not user or not verify_password(payload.password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = _utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes."
                )
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # Soft-deleted accounts cannot log in during the 30-day grace period
    if user.deleted_at is not None:
        grace_ends = user.deleted_at + timedelta(days=30)
        days_left = (grace_ends - _utcnow()).days + 1
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"This account has been scheduled for deletion. "
                f"It will be permanently deleted in {days_left} day(s). "
                f"Contact support to recover it."
            ),
        )

    # Reset lockout counters on successful password check
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    # If email not verified, resend a fresh code and block login
    if not user.email_verified:
        if is_email_configured():
            code = _set_verify_code(user, db)
            background_tasks.add_task(
                send_verification_email, user.email, user.full_name or "", code
            )
        verify_token = create_access_token(
            data={"sub": str(user.id), "email": user.email, "type": "email_verify_pending"},
            expires_delta=timedelta(minutes=VERIFY_CODE_EXPIRY_MINUTES),
        )
        return LoginResponse(
            requires_email_verification=True,
            verify_partial_token=verify_token,
            email=user.email,
        )

    # If TOTP is enabled, issue a short-lived partial token — full token issued after TOTP verify
    if user.totp_enabled:
        partial_token = create_access_token(
            data={"sub": str(user.id), "email": user.email, "type": "totp_pending"},
            expires_delta=timedelta(minutes=5),
        )
        return LoginResponse(requires_totp=True, partial_token=partial_token)

    # No TOTP — issue full access token immediately
    token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return LoginResponse(
        access_token=token,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
    )


@router.get("/me", response_model=UserProfile)
def get_me(current_user: models.User = Depends(get_current_user)):
    """Return the profile of the currently authenticated user."""
    return UserProfile(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        aws_connected=current_user.aws_connected,
        aws_region=current_user.aws_region,
        aws_account_id=current_user.aws_account_id,
        created_at=current_user.created_at.isoformat(),
        totp_enabled=current_user.totp_enabled,
        email_verified=bool(current_user.email_verified),
    )


@router.put("/aws", response_model=AWSConnectResponse)
def connect_aws(
    payload: AWSConnectRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Save encrypted AWS credentials for the current user."""
    current_user.aws_access_key_enc = encrypt_aws_credential(payload.aws_access_key)
    current_user.aws_secret_key_enc = encrypt_aws_credential(payload.aws_secret_key)
    current_user.aws_region = payload.aws_region
    if payload.account_id:
        current_user.aws_account_id = payload.account_id
    current_user.aws_connected = True
    db.commit()

    return AWSConnectResponse(
        message="AWS credentials saved successfully",
        aws_region=payload.aws_region,
        account_id=current_user.aws_account_id,
    )


@router.delete("/aws", status_code=status.HTTP_204_NO_CONTENT)
def disconnect_aws(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove stored AWS credentials."""
    current_user.aws_access_key_enc = None
    current_user.aws_secret_key_enc = None
    current_user.aws_region = None
    current_user.aws_account_id = None
    current_user.aws_connected = False
    db.commit()


@router.post("/verify-email")
@limiter.limit("10/minute")
def verify_email(
    request: Request,
    payload: VerifyEmailRequest,
    db: Session = Depends(get_db),
):
    """
    Verify email with the 6-digit code.
    Accepts the verify_partial_token in the Authorization header
    (type: email_verify_pending) to identify the user without a full session.
    Returns a full access token on success.
    """
    from jose import JWTError, jwt as jose_jwt
    from ..auth import SECRET_KEY, ALGORITHM

    # Pull token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing verify token")

    token = auth_header.split(" ", 1)[1]
    try:
        payload_data = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload_data.get("type") != "email_verify_pending":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = int(payload_data["sub"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired verify token — request a new code")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.email_verified:
        # Already verified — just issue a full token
        token_out = create_access_token(
            data={"sub": str(user.id), "email": user.email},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return {"access_token": token_out, "token_type": "bearer",
                "user_id": user.id, "email": user.email, "full_name": user.full_name}

    # Check code
    if not user.email_verify_code or user.email_verify_code != payload.code.strip():
        raise HTTPException(status_code=400, detail="Incorrect verification code")

    if not user.email_verify_expires or user.email_verify_expires < _utcnow():
        raise HTTPException(status_code=400, detail="Code has expired — request a new one")

    # Mark verified and clear the code
    user.email_verified = True
    user.email_verify_code = None
    user.email_verify_expires = None
    db.commit()

    full_token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {
        "access_token": full_token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
    }


@router.post("/resend-verification")
@limiter.limit("3/minute")
def resend_verification(
    request: Request,
    payload: ResendVerifyRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Resend a verification code to the given email.
    Always returns 200 to prevent email enumeration.
    """
    user = db.query(models.User).filter(models.User.email == payload.email).first()

    if user and not user.email_verified:
        if is_email_configured():
            code = _set_verify_code(user, db)
            background_tasks.add_task(
                send_verification_email, user.email, user.full_name or "", code
            )

    return {"message": "If that email has a pending verification, a new code has been sent."}


class DeleteAccountRequest(BaseModel):
    password: str   # require password confirmation before deletion


@router.delete("/account", status_code=status.HTTP_200_OK)
def delete_account(
    payload: DeleteAccountRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Soft-delete the current user's account.
    - Verifies the user's password before proceeding.
    - Sets deleted_at = now(). The account is blocked from login immediately.
    - Data is retained for 30 days to allow recovery (contact support).
    - After 30 days the account is eligible for permanent purge.
    """
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password. Account deletion cancelled.",
        )

    if current_user.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Account is already scheduled for deletion.",
        )

    current_user.deleted_at = _utcnow()
    db.commit()

    logger.info("Account soft-deleted: user_id=%s email=%s", current_user.id, current_user.email)

    return {
        "message": "Account scheduled for deletion.",
        "deleted_at": current_user.deleted_at.isoformat(),
        "purge_after": (current_user.deleted_at + timedelta(days=30)).isoformat(),
    }


@router.post("/aws/validate")
def validate_aws(
    payload: AWSValidateRequest,
    current_user: models.User = Depends(get_current_user),
):
    """
    Validate AWS credentials by calling sts:GetCallerIdentity.
    Does NOT save credentials — call PUT /aws after successful validation.
    Returns: account_id, arn, user_id
    """
    try:
        import boto3
        sts = boto3.client(
            "sts",
            aws_access_key_id=payload.aws_access_key,
            aws_secret_access_key=payload.aws_secret_key,
            region_name=payload.aws_region,
        )
        identity = sts.get_caller_identity()
        return {
            "valid": True,
            "account_id": identity["Account"],
            "arn": identity["Arn"],
            "user_id": identity["UserId"],
        }
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="boto3 is not installed. Run: pip install boto3 --break-system-packages",
        )
    except Exception as exc:
        # Surface the exact AWS error (InvalidClientTokenId, AuthFailure, etc.)
        raise HTTPException(
            status_code=400,
            detail=f"AWS credential validation failed: {exc}",
        )
