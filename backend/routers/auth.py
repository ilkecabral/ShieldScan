"""
routers/auth.py — Authentication endpoints
POST /api/auth/register   → create account, return token
POST /api/auth/login      → email+password → return token
GET  /api/auth/me         → return current user profile (requires token)
PUT  /api/auth/aws        → save encrypted AWS credentials for current user
"""

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    encrypt_aws_credential,
    decrypt_aws_credential,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


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


class UserProfile(BaseModel):
    id: int
    email: str
    full_name: str | None
    aws_connected: bool
    aws_region: str | None
    created_at: str

    class Config:
        from_attributes = True


class AWSConnectRequest(BaseModel):
    aws_access_key: str
    aws_secret_key: str
    aws_region: str = "us-east-1"


class AWSConnectResponse(BaseModel):
    message: str
    aws_region: str


# ─────────────────────────────────────────
# Routes
# ─────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """Create a new user account and return an access token."""

    # Check email not already taken
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists"
        )

    # Validate password length
    if len(payload.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be at least 8 characters"
        )

    user = models.User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return TokenResponse(
        access_token=token,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
    )


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate with email + password, return access token."""

    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return TokenResponse(
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
        created_at=current_user.created_at.isoformat(),
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
    current_user.aws_connected = True
    db.commit()

    return AWSConnectResponse(
        message="AWS credentials saved successfully",
        aws_region=payload.aws_region,
    )


@router.delete("/aws", status_code=status.HTTP_204_NO_CONTENT)
def disconnect_aws(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove stored AWS credentials."""
    current_user.aws_access_key_enc = None
    current_user.aws_secret_key_enc = None
    current_user.aws_connected = False
    db.commit()
