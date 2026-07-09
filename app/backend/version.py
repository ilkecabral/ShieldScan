"""
version.py — ShieldScan version registry

Single source of truth for all component and application versions.
Import from here everywhere — never hardcode version strings in other files.

Versioning scheme: Semantic Versioning (SemVer) — MAJOR.MINOR.PATCH
  MAJOR — breaking change (API contract, model schema, auth flow)
  MINOR — new feature or check added, backwards compatible
  PATCH — bug fix, no new behaviour

Bump rules by component:
  APP           → bump whenever a release is tagged in git
  API           → bump when an endpoint is added, changed, or removed
  CSPM          → bump when an AWS check is added or its logic changes
  CWPP          → bump when Trivy integration or output format changes
  RISK_SCORER   → bump when XGBoost model is retrained or scoring logic changes
  AI_SERVICE    → bump when a new LLM provider is added or system prompt changes
  RAG           → bump when knowledge base documents are added or retrieval logic changes
  AUTH          → bump when auth flow changes (new MFA method, token format, etc.)
  FRONTEND      → bump when the UI ships a meaningful change

History is tracked in CHANGELOG.md (one entry per component per release).
"""

from dataclasses import dataclass
from datetime import date


# ─────────────────────────────────────────────────────────────────────────────
# Version dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    label: str = ""          # optional pre-release label, e.g. "alpha", "beta", "rc1"

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{self.label}" if self.label else base

    def as_dict(self) -> dict:
        return {
            "version": str(self),
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            **({"label": self.label} if self.label else {}),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Component versions
# ─────────────────────────────────────────────────────────────────────────────
#
# When you add/change a component, bump its version HERE and add an entry to
# CHANGELOG.md. CI will surface the current versions via GET /api/version.
#

# Overall application release — bump when tagging a release in git
APP = Version(1, 0, 0, label="beta")

# FastAPI backend — bump when any endpoint is added, changed, or removed
API = Version(1, 0, 0)

# CSPM module (boto3 AWS checks) — 13 checks implemented
# v1.0.0 — initial release: S3, IAM, EC2, CloudTrail, EBS, RDS, VPC, KMS, GuardDuty
CSPM = Version(1, 0, 0)

# CWPP module (Trivy container scanning)
# v1.0.0 — initial release: CVE scanning with severity classification
CWPP = Version(1, 0, 0)

# Risk Scorer (XGBoost) — bump when model is retrained or scoring formula changes
# v1.0.0 — initial release: weighted severity scoring
RISK_SCORER = Version(1, 0, 0)

# AI Service (LLM provider abstraction + system prompt)
# v1.0.0 — initial release: ollama / groq / claude providers, scope-locked system prompt
AI_SERVICE = Version(1, 0, 0)

# RAG module (ChromaDB + CIS benchmark knowledge base)
# v1.0.0 — initial release: 15 CIS AWS Benchmark documents seeded
RAG = Version(1, 0, 0)

# Auth module (JWT + bcrypt + TOTP + WebAuthn + Fernet)
# v1.0.0 — initial release: full auth stack with 2FA, passkeys, email verification
AUTH = Version(1, 0, 0)

# Frontend (React single-page app)
# v1.0.0 — initial release: dashboard, findings, AI chat widget
FRONTEND = Version(1, 0, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Registry — all components in one place
# ─────────────────────────────────────────────────────────────────────────────

REGISTRY: dict[str, Version] = {
    "app":          APP,
    "api":          API,
    "cspm":         CSPM,
    "cwpp":         CWPP,
    "risk_scorer":  RISK_SCORER,
    "ai_service":   AI_SERVICE,
    "rag":          RAG,
    "auth":         AUTH,
    "frontend":     FRONTEND,
}

# Release date of the current APP version
RELEASE_DATE = date(2026, 6, 20)


def get_version_info() -> dict:
    """
    Return the full version manifest — used by GET /api/version and /health.
    """
    return {
        "app":          str(APP),
        "release_date": RELEASE_DATE.isoformat(),
        "components": {
            name: str(ver) for name, ver in REGISTRY.items() if name != "app"
        },
    }
