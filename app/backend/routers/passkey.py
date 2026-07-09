"""
routers/passkey.py — WebAuthn / Passkey authentication (FIDO2)
Compatible with: Touch ID (Mac), Face ID (iOS), Windows Hello, YubiKeys

Endpoints:
  POST /api/passkey/register/begin    → generate registration challenge
  POST /api/passkey/register/complete → store credential after browser attestation
  POST /api/passkey/login/begin       → generate authentication challenge
  POST /api/passkey/login/complete    → verify assertion, return JWT

Flow:
  Register: frontend calls /begin (logged in) → browser navigator.credentials.create()
            → frontend sends result to /complete → credential stored in DB

  Login:    frontend calls /begin (anonymous) → browser navigator.credentials.get()
            → frontend sends result to /complete → JWT returned

RP settings:
  - Local dev: rp_id="localhost", origin="http://localhost:3000"
  - The rp_id MUST match the domain serving the frontend.
"""

import json
import os
import base64
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..auth import get_current_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES

# ─────────────────────────────────────────
# WebAuthn imports
# ─────────────────────────────────────────
try:
    from webauthn import (
        generate_registration_options,
        verify_registration_response,
        generate_authentication_options,
        verify_authentication_response,
        options_to_json,
        base64url_to_bytes,
    )
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        UserVerificationRequirement,
        ResidentKeyRequirement,
        PublicKeyCredentialDescriptor,
        AuthenticatorAttestationResponse,
        AuthenticatorAssertionResponse,
        RegistrationCredential,
        AuthenticationCredential,
    )
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False

router = APIRouter(prefix="/api/passkey", tags=["passkey"])

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
# Read from env vars so Docker (port 80) and bare Python (port 3000) both work.
# Set WEBAUTHN_RP_ID, WEBAUTHN_RP_NAME, WEBAUTHN_ORIGIN in your .env (already present).
RP_ID   = os.getenv("WEBAUTHN_RP_ID",   "localhost")
RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "ShieldScan")
ORIGIN  = os.getenv("WEBAUTHN_ORIGIN",  "http://localhost")

# In-memory challenge store: {user_id: challenge_bytes} for register,
#                             {email: challenge_bytes} for login
# Production would use Redis with TTL. For local dev this is fine.
_register_challenges: dict[int, bytes] = {}
_login_challenges: dict[str, bytes] = {}


def _webauthn_check():
    if not WEBAUTHN_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail=(
                "WebAuthn library not installed. "
                "Run: pip install webauthn --break-system-packages"
            ),
        )


# ─────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────

class RegisterCompleteRequest(BaseModel):
    response: dict          # navigator.credentials.create() result as JSON
    name: Optional[str] = "Passkey"


class LoginBeginRequest(BaseModel):
    email: str


class LoginCompleteRequest(BaseModel):
    email: str
    response: dict          # navigator.credentials.get() result as JSON


class PasskeyInfo(BaseModel):
    id: int
    name: str
    created_at: str


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ─────────────────────────────────────────
# Register flow (requires logged-in user)
# ─────────────────────────────────────────

@router.post("/register/begin")
def register_begin(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate WebAuthn registration options. User must be authenticated."""
    _webauthn_check()

    # Collect IDs of credentials already registered (so browser won't offer them)
    existing = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred.credential_id))
        for cred in current_user.passkeys
    ]

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(current_user.id).encode(),
        user_name=current_user.email,
        user_display_name=current_user.full_name or current_user.email,
        exclude_credentials=existing,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )

    _register_challenges[current_user.id] = options.challenge

    return json.loads(options_to_json(options))


@router.post("/register/complete")
def register_complete(
    payload: RegisterCompleteRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify registration response from browser and store credential."""
    _webauthn_check()

    challenge = _register_challenges.get(current_user.id)
    if not challenge:
        raise HTTPException(status_code=400, detail="No pending registration challenge. Call /begin first.")

    try:
        resp = payload.response
        reg_cred = RegistrationCredential(
            id=resp["id"],
            raw_id=base64url_to_bytes(resp["rawId"]),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(resp["response"]["clientDataJSON"]),
                attestation_object=base64url_to_bytes(resp["response"]["attestationObject"]),
            ),
        )
        verification = verify_registration_response(
            credential=reg_cred,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Registration verification failed: {exc}")

    # Clean up challenge
    _register_challenges.pop(current_user.id, None)

    # Store credential
    credential_id_b64 = _b64url_encode(verification.credential_id)
    public_key_b64 = base64.b64encode(verification.credential_public_key).decode()

    # Check for duplicate
    existing = db.query(models.PasskeyCredential).filter_by(
        credential_id=credential_id_b64
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="This passkey is already registered.")

    cred = models.PasskeyCredential(
        user_id=current_user.id,
        credential_id=credential_id_b64,
        public_key=public_key_b64,
        sign_count=verification.sign_count,
        aaguid=str(verification.aaguid) if verification.aaguid else None,
        name=payload.name or "Passkey",
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)

    return {
        "message": "Passkey registered successfully.",
        "passkey_id": cred.id,
        "name": cred.name,
    }


# ─────────────────────────────────────────
# Login flow (anonymous — no JWT required)
# ─────────────────────────────────────────

@router.post("/login/begin")
def login_begin(payload: LoginBeginRequest, db: Session = Depends(get_db)):
    """Generate WebAuthn authentication options for a given email."""
    _webauthn_check()

    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not user.passkeys:
        raise HTTPException(
            status_code=400,
            detail="No passkeys registered for this account.",
        )

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred.credential_id))
        for cred in user.passkeys
    ]

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    _login_challenges[payload.email] = options.challenge

    return json.loads(options_to_json(options))


@router.post("/login/complete")
def login_complete(payload: LoginCompleteRequest, db: Session = Depends(get_db)):
    """Verify authentication assertion and return full JWT on success."""
    _webauthn_check()

    challenge = _login_challenges.get(payload.email)
    if not challenge:
        raise HTTPException(status_code=400, detail="No pending authentication challenge.")

    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

    # Find matching credential
    credential_id_from_response = payload.response.get("id", "")
    # Normalize base64url (add padding)
    cred_record = db.query(models.PasskeyCredential).filter_by(
        credential_id=credential_id_from_response
    ).first()

    if not cred_record or cred_record.user_id != user.id:
        raise HTTPException(status_code=401, detail="Passkey not recognized.")

    public_key_bytes = base64.b64decode(cred_record.public_key)

    try:
        resp = payload.response
        resp_inner = resp.get("response", {})
        auth_cred = AuthenticationCredential(
            id=resp["id"],
            raw_id=base64url_to_bytes(resp["rawId"]),
            response=AuthenticatorAssertionResponse(
                client_data_json=base64url_to_bytes(resp_inner["clientDataJSON"]),
                authenticator_data=base64url_to_bytes(resp_inner["authenticatorData"]),
                signature=base64url_to_bytes(resp_inner["signature"]),
                user_handle=base64url_to_bytes(resp_inner["userHandle"]) if resp_inner.get("userHandle") else None,
            ),
        )
        verification = verify_authentication_response(
            credential=auth_cred,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=public_key_bytes,
            credential_current_sign_count=cred_record.sign_count,
            require_user_verification=True,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Passkey verification failed: {exc}")

    # Clean up challenge
    _login_challenges.pop(payload.email, None)

    # Update sign count (replay attack prevention)
    cred_record.sign_count = verification.new_sign_count
    db.commit()

    # Issue full JWT
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
    }


# ─────────────────────────────────────────
# Passkey management (logged in)
# ─────────────────────────────────────────

@router.get("/list")
def list_passkeys(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all passkeys for the current user."""
    return {
        "passkeys": [
            {
                "id": p.id,
                "name": p.name,
                "created_at": p.created_at.isoformat() if p.created_at else "",
                "aaguid": p.aaguid,
            }
            for p in current_user.passkeys
        ]
    }


@router.delete("/remove/{passkey_id}")
def remove_passkey(
    passkey_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove a passkey by ID. User can only remove their own passkeys."""
    cred = db.query(models.PasskeyCredential).filter_by(
        id=passkey_id, user_id=current_user.id
    ).first()
    if not cred:
        raise HTTPException(status_code=404, detail="Passkey not found.")

    db.delete(cred)
    db.commit()
    return {"message": "Passkey removed."}
