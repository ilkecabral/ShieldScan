"""
main.py — ShieldScan FastAPI application entry point
Run: uvicorn backend.main:app --reload --port 8000
"""

import os
import json
import uuid
import logging
from pathlib import Path
from datetime import timezone, datetime

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

# ─────────────────────────────────────────
# Structured JSON logging (CloudWatch-compatible)
# ─────────────────────────────────────────

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "shieldscan-api",
        }
        if record.exc_info:
            log["exception"] = self.formatException(record.exc_info)
        return json.dumps(log)

_handler = logging.StreamHandler()
_handler.setFormatter(_JsonFormatter())
logging.basicConfig(handlers=[_handler], level=logging.INFO, force=True)

logger = logging.getLogger(__name__)

# ── CloudWatch logging (production only) ──────────────────────────────────────
# Activated when ENV=production and CLOUDWATCH_LOG_GROUP is set.
# Uses watchtower — sends structured JSON logs to AWS CloudWatch Logs.
# EC2 instance must have logs:CreateLogGroup, logs:CreateLogStream,
# logs:PutLogEvents in its IAM instance profile.
if os.getenv("ENV") == "production":
    _cw_group = os.getenv("CLOUDWATCH_LOG_GROUP", "/shieldscan/api")
    _cw_stream = os.getenv("CLOUDWATCH_STREAM", "backend")
    try:
        import watchtower
        import boto3 as _boto3
        _cw_client = _boto3.client(
            "logs",
            region_name=os.getenv("AWS_REGION", "eu-west-1"),
        )
        _cw_handler = watchtower.CloudWatchLogHandler(
            boto3_client=_cw_client,
            log_group=_cw_group,
            stream_name=_cw_stream,
            create_log_group=True,
        )
        _cw_handler.setFormatter(_JsonFormatter())
        logging.getLogger().addHandler(_cw_handler)
        logger.info("CloudWatch logging enabled: %s/%s", _cw_group, _cw_stream)
    except ImportError:
        logger.warning("watchtower not installed — CloudWatch logging disabled. Run: pip install watchtower")
    except Exception as _cw_exc:
        logger.warning("CloudWatch logging setup failed: %s", _cw_exc)

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .database import engine, Base, run_migrations, SessionLocal, get_db
from . import models
from .routers import auth as auth_router
from .routers import ai as ai_router
from .routers import scans as scans_router
from .routers import totp as totp_router
from .routers import idcard as idcard_router
from .routers import reset as reset_router
from .routers import passkey as passkey_router
from .routers import recover as recover_router
from .routers import admin as admin_router
from .routers import version as version_router
from .cnappgoat_routes_fastapi import router as cnappgoat_router
from .version import APP

# Run lightweight migrations BEFORE create_all — adds missing columns to existing tables
run_migrations()

# Create all DB tables on startup (safe to call multiple times — only creates missing tables)
Base.metadata.create_all(bind=engine)


def seed_admin():
    """
    Create the admin account from ADMIN_EMAIL + ADMIN_PASSWORD env vars.
    If ADMIN_PASSWORD is not set, skip silently — no default password ever.
    """
    admin_email = os.getenv("ADMIN_EMAIL", "admin@shieldscan.com")
    admin_pass  = os.getenv("ADMIN_PASSWORD", "").strip()

    if not admin_pass:
        logger.warning(
            "ADMIN_PASSWORD env var not set — admin account NOT seeded. "
            "Set ADMIN_PASSWORD in .env to create the admin account on first start."
        )
        return

    db = SessionLocal()
    try:
        existing = db.query(models.User).filter(models.User.email == admin_email).first()
        if not existing:
            from .auth import hash_password
            admin = models.User(
                email=admin_email,
                full_name="ShieldScan Admin",
                hashed_password=hash_password(admin_pass),
                is_admin=True,
                is_active=True,
                email_verified=True,
            )
            db.add(admin)
            db.commit()
            logger.info("Admin account created: %s", admin_email)
        else:
            if not existing.is_admin:
                existing.is_admin = True
                db.commit()
                logger.info("Promoted %s to admin.", admin_email)
    except Exception as exc:
        logger.warning("Admin seed skipped: %s", exc)
    finally:
        db.close()


seed_admin()

# ─────────────────────────────────────────
# Rate limiter (slowapi)
# ─────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="ShieldScan API",
    description="Lightweight CNAPP platform for students and early-stage startups",
    version=str(APP),
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─────────────────────────────────────────
# CORS — locked to env-var-defined origins
# Set CORS_ALLOWED_ORIGINS in .env as a JSON array:
#   dev:  '["http://localhost:3000","http://localhost:8000"]'
#   prod: '["https://shieldscan.io","https://www.shieldscan.io"]'
# ─────────────────────────────────────────
_raw_origins = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    '["http://localhost:3000","http://localhost:8000","http://127.0.0.1:8000"]',
)
try:
    ALLOWED_ORIGINS = json.loads(_raw_origins)
except json.JSONDecodeError:
    logger.error("CORS_ALLOWED_ORIGINS is not valid JSON — defaulting to localhost only")
    ALLOWED_ORIGINS = ["http://localhost:3000", "http://localhost:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# ─────────────────────────────────────────
# Request ID middleware — adds X-Request-ID to every response
# Enables distributed tracing across logs
# ─────────────────────────────────────────
class _RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

app.add_middleware(_RequestIdMiddleware)

# ─────────────────────────────────────────
# Security headers middleware
# ─────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # CNAPPgoat dashboard is served inside an iframe — allow same-origin framing
    is_cnappgoat = request.url.path.startswith("/cnappgoat")
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "SAMEORIGIN" if is_cnappgoat else "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]      = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    frame_ancestors = "'self'" if is_cnappgoat else "'none'"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        f"frame-ancestors {frame_ancestors};"
    )
    return response

# ─────────────────────────────────────────
# Routers
# ─────────────────────────────────────────
app.include_router(auth_router.router)
app.include_router(totp_router.router)
app.include_router(idcard_router.router)
app.include_router(reset_router.router)
app.include_router(recover_router.router)
app.include_router(passkey_router.router)
app.include_router(ai_router.router)
app.include_router(scans_router.router)
app.include_router(admin_router.router)
app.include_router(version_router.router)
app.include_router(cnappgoat_router)

# Future routers:
# from .routers import reports
# app.include_router(reports.router)


# ─────────────────────────────────────────
# Admin panel — served at /admin
# Accessible via: http://localhost:8000/admin
# ─────────────────────────────────────────
_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

@app.get("/admin", include_in_schema=False)
def serve_admin():
    return FileResponse(_FRONTEND_DIR / "admin.html")


# ─────────────────────────────────────────
# Health check — checks DB + AI provider
# Used by ALB, ECS, Docker HEALTHCHECK, and FTR reviewers
# ─────────────────────────────────────────
@app.get("/health")
def health(db: Session = Depends(get_db)):
    checks: dict = {}

    # Database connectivity
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"

    # AI provider config check
    ai_provider = os.getenv("AI_PROVIDER", "ollama")
    checks["ai_provider"] = ai_provider
    if ai_provider == "groq" and not os.getenv("GROQ_API_KEY"):
        checks["ai_config"] = "warning: GROQ_API_KEY not set"
    elif ai_provider == "claude" and not os.getenv("ANTHROPIC_API_KEY"):
        checks["ai_config"] = "warning: ANTHROPIC_API_KEY not set"
    else:
        checks["ai_config"] = "ok"

    overall = "ok" if checks["database"] == "ok" else "degraded"
    status_code = 200 if overall == "ok" else 503

    return JSONResponse(
        status_code=status_code,
        content={
            "status": overall,
            "service": "shieldscan-api",
            "version": str(APP),
            "checks": checks,
        },
    )
