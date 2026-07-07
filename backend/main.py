"""
main.py — ShieldScan FastAPI application entry point
Run: uvicorn backend.main:app --reload --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import os

from .database import engine, Base
from .routers import auth as auth_router
from .routers import ai as ai_router
from .routers import scans as scans_router

# Create all DB tables on startup (safe to call multiple times — only creates missing tables)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ShieldScan API",
    description="Lightweight CNAPP platform for students and early-stage startups",
    version="0.1.0",
)

# ─────────────────────────────────────────
# CORS — allow the frontend (any origin in dev, lock down in prod)
# ─────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # TODO: restrict to your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────
# Routers
# ─────────────────────────────────────────
app.include_router(auth_router.router)
app.include_router(ai_router.router)
app.include_router(scans_router.router)


# ─────────────────────────────────────────
# Serve Frontend
# ─────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def read_root():
    frontend_path = os.path.join(os.path.dirname(__file__), "../frontend/index.html")
    if os.path.exists(frontend_path):
        with open(frontend_path, "r") as f:
            return f.read()
    return HTMLResponse(content="<h3>Frontend index.html not found</h3>", status_code=404)


# ─────────────────────────────────────────
# Health check
# ─────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "shieldscan-api"}
