"""
routers/version.py — Version endpoints

GET  /api/version         → full version manifest (public, no auth needed)
GET  /api/version/{name}  → single component version (e.g. /api/version/cspm)
"""

from fastapi import APIRouter, HTTPException
from ..version import get_version_info, REGISTRY, APP

router = APIRouter(prefix="/api/version", tags=["version"])


@router.get("", summary="Full version manifest")
def get_versions():
    """
    Returns the current version of the application and each component.
    Public endpoint — no authentication required.

    Example response:
    {
        "app": "1.0.0-beta",
        "release_date": "2026-06-20",
        "components": {
            "api":         "1.0.0",
            "cspm":        "1.0.0",
            "cwpp":        "1.0.0",
            "risk_scorer": "1.0.0",
            "ai_service":  "1.0.0",
            "rag":         "1.0.0",
            "auth":        "1.0.0",
            "frontend":    "1.0.0"
        }
    }
    """
    return get_version_info()


@router.get("/{component}", summary="Single component version")
def get_component_version(component: str):
    """
    Returns the version of a single component.
    Valid names: app, api, cspm, cwpp, risk_scorer, ai_service, rag, auth, frontend

    Example: GET /api/version/cspm → { "component": "cspm", "version": "1.0.0", "major": 1, ... }
    """
    key = component.lower()
    if key == "app":
        return {"component": "app", **APP.as_dict()}

    ver = REGISTRY.get(key)
    if not ver:
        valid = sorted(REGISTRY.keys())
        raise HTTPException(
            status_code=404,
            detail=f"Unknown component '{component}'. Valid names: {', '.join(valid)}",
        )
    return {"component": key, **ver.as_dict()}
