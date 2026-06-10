"""
main.py — ShieldScan FastAPI application entry point
Run: uvicorn backend.main:app --reload --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import engine, Base
from .routers import auth as auth_router
from .routers import ai as ai_router

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

# Future routers — uncomment as teammates finish their services:
# from .routers import scans, reports
# app.include_router(scans.router)
# app.include_router(reports.router)


# ─────────────────────────────────────────
# Health check
# ─────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "shieldscan-api"}
