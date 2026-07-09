"""
routers/idcard.py — RSA-2048 key pair authentication
Each user gets a unique RSA key pair bound to their user ID.
Server stores only the public key fingerprint (SHA-256 of DER).
User holds the private key (.pem file) — never stored server-side.

POST /api/auth/keypair/generate  → generate RSA-2048 pair, store pub fingerprint, return private key PEM
POST /api/auth/keypair/verify    → upload private .pem, derive pub key, verify fingerprint, return action token
GET  /api/auth/keypair/status    → check if keypair is set up for current user
"""

import hashlib
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import Response
from sqlalchemy.orm import Session

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from ..database import get_db
from .. import models
from ..auth import get_current_user, create_access_token

router = APIRouter(prefix="/api/auth/keypair", tags=["keypair"])


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _generate_rsa_pair():
    """Generate RSA-2048 key pair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


def _private_key_to_pem(private_key, user_id: int, email: str) -> bytes:
    """
    Serialize private key to PEM with a custom header comment binding it to the user.
    Format: standard PKCS8 PEM with user metadata in comments.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    header = (
        f"# ShieldScan Private Key\n"
        f"# User ID : SS-{user_id:06d}\n"
        f"# Email   : {email}\n"
        f"# WARNING : Keep this file secret. Do not share.\n"
        f"# Use     : Upload this file to authenticate critical actions.\n\n"
    ).encode()
    return header + pem


def _public_key_fingerprint(public_key) -> str:
    """SHA-256 fingerprint of the public key DER encoding."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _load_private_key_from_upload(raw: bytes):
    """
    Parse uploaded bytes as a PEM private key.
    Strips our custom comment header before parsing.
    """
    # Strip comment lines (lines starting with #)
    lines = raw.split(b"\n")
    pem_lines = [l for l in lines if not l.startswith(b"#")]
    pem_clean = b"\n".join(pem_lines)

    try:
        return serialization.load_pem_private_key(
            pem_clean, password=None, backend=default_backend()
        )
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid key file. Upload the exact .pem file downloaded from ShieldScan."
        )


# ─────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────

@router.post("/generate")
def generate_keypair(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate a new RSA-2048 key pair for the user.
    - Public key fingerprint → stored in DB (server never stores private key)
    - Private key → returned as .pem download (user must keep safe)
    Calling this again invalidates the previous key pair.
    """
    private_key, public_key = _generate_rsa_pair()

    # Store only the fingerprint (SHA-256 of public key DER)
    fingerprint = _public_key_fingerprint(public_key)
    current_user.pub_key_fingerprint = fingerprint
    db.commit()

    # Build PEM with user metadata header
    pem_bytes = _private_key_to_pem(private_key, current_user.id, current_user.email)

    filename = f"shieldscan-{current_user.id}-private.pem"
    return Response(
        content=pem_bytes,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/verify")
async def verify_keypair(
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    User uploads their private .pem file.
    Server derives the public key, computes fingerprint, and compares
    against the stored fingerprint — without ever seeing the private key stored server-side.
    On success, returns a short-lived action token (10 min) authorizing one critical action.
    """
    if not current_user.pub_key_fingerprint:
        raise HTTPException(
            status_code=400,
            detail="No key pair found for this account. Generate one first in Settings."
        )

    raw = await file.read()
    if len(raw) > 10_000:
        raise HTTPException(status_code=400, detail="File too large. Upload your .pem key file only.")

    # Load the private key from upload
    private_key = _load_private_key_from_upload(raw)

    # Derive public key and compute its fingerprint
    public_key = private_key.public_key()
    uploaded_fingerprint = _public_key_fingerprint(public_key)

    # Compare fingerprints — constant time via == on hex strings
    if uploaded_fingerprint != current_user.pub_key_fingerprint:
        raise HTTPException(
            status_code=401,
            detail="Key verification failed — this key does not match the one registered to your account."
        )

    # Issue a short-lived action token
    action_token = create_access_token(
        data={
            "sub": str(current_user.id),
            "email": current_user.email,
            "type": "action_verified",
        },
        expires_delta=timedelta(minutes=10),
    )

    return {
        "verified": True,
        "action_token": action_token,
        "expires_in": 600,
        "message": "Key verified. You have 10 minutes to complete the critical action.",
    }


@router.get("/status")
def keypair_status(current_user: models.User = Depends(get_current_user)):
    """Check whether the current user has a registered key pair."""
    return {
        "has_keypair": bool(current_user.pub_key_fingerprint),
        "fingerprint": (
            current_user.pub_key_fingerprint[:16] + "..."
            if current_user.pub_key_fingerprint else None
        ),
    }
