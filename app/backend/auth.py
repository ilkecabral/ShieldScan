"""
auth.py — JWT token logic + password hashing
Used by routers/auth.py and as a FastAPI dependency (Depends(get_current_user))
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from .database import get_db
from . import models

load_dotenv()

# ─────────────────────────────────────────
# Config — all from .env
# ─────────────────────────────────────────

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-in-production-please")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

# ─────────────────────────────────────────
# Password hashing
# ─────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# ─────────────────────────────────────────
# JWT token creation + decoding
# ─────────────────────────────────────────

class TokenData(BaseModel):
    user_id: Optional[int] = None
    email: Optional[str] = None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        email: str = payload.get("email")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return TokenData(user_id=int(user_id), email=email)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─────────────────────────────────────────
# FastAPI dependency: get the current logged-in user
# Usage in any route: current_user: models.User = Depends(get_current_user)
# ─────────────────────────────────────────

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> models.User:
    token_data = decode_token(token)
    user = db.query(models.User).filter(models.User.id == token_data.user_id).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ─────────────────────────────────────────
# AWS credential encryption (Fernet symmetric)
# ─────────────────────────────────────────

def _get_fernet():
    """Lazy import so Fernet is only needed when AWS creds are used."""
    from cryptography.fernet import Fernet
    key = os.getenv("AWS_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("AWS_ENCRYPTION_KEY not set in .env")
    return Fernet(key.encode())


def encrypt_aws_credential(value: str) -> str:
    f = _get_fernet()
    return f.encrypt(value.encode()).decode()


def decrypt_aws_credential(encrypted_value: str) -> str:
    f = _get_fernet()
    return f.decrypt(encrypted_value.encode()).decode()
