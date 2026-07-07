"""
routers/ai.py — AI chat endpoint
POST /api/ai/chat  → JWT-protected, context-injected AI response

Flow:
  1. Validate JWT → get current user
  2. Load user's latest scan findings from DB
  3. Run RAG retrieval on the user's message
  4. Call ai_service.get_ai_response(message, findings, rag_context)
  5. Return response + metadata
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from ..database import get_db
from .. import models
from ..auth import get_current_user
from ..ai_service import get_ai_response
from ..rag_module import retrieve

router = APIRouter(prefix="/api/ai", tags=["ai"])


# ─────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    scan_id: Optional[int] = None          # if None, use the user's latest scan
    include_findings_context: bool = True   # set False to ask general questions


class ChatResponse(BaseModel):
    reply: str
    provider: str                           # which LLM was used (ollama/groq/claude)
    findings_injected: int                  # how many findings were in context
    rag_docs_retrieved: int                 # how many RAG snippets were used


# ─────────────────────────────────────────
# Helper: load findings for context
# ─────────────────────────────────────────

def _get_findings_for_context(
    user: models.User,
    scan_id: Optional[int],
    db: Session,
    limit: int = 20,
) -> list[dict]:
    """
    Load findings from the user's latest (or specified) scan.
    Prioritizes CRITICAL and HIGH findings to keep the context tight.
    """
    query = db.query(models.Finding).join(models.Scan).filter(
        models.Scan.user_id == user.id
    )

    if scan_id:
        query = query.filter(models.Finding.scan_id == scan_id)
    else:
        # Get the most recent completed scan
        latest_scan = (
            db.query(models.Scan)
            .filter(
                models.Scan.user_id == user.id,
                models.Scan.status == models.ScanStatusEnum.COMPLETED,
            )
            .order_by(models.Scan.completed_at.desc())
            .first()
        )
        if latest_scan:
            query = query.filter(models.Finding.scan_id == latest_scan.id)
        else:
            return []

    # Order by severity (CRITICAL first) and take top N
    severity_order = {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
    }
    findings = query.filter(models.Finding.is_resolved == False).all()
    findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))
    findings = findings[:limit]

    return [
        {
            "finding_id": f.finding_id,
            "severity": f.severity.value,
            "title": f.title,
            "resource": f.resource,
            "finding_type": f.finding_type.value,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "affected_package": f.affected_package,
            "fixed_version": f.fixed_version,
        }
        for f in findings
    ]


# ─────────────────────────────────────────
# Endpoint
# ─────────────────────────────────────────

@router.post("/chat", response_model=ChatResponse)
async def chat(
    payload: ChatRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Send a message to ShieldScan AI.
    The AI automatically receives the user's latest scan findings and relevant
    knowledge base snippets as context — no extra setup needed.
    """
    import os

    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    # 1. Load findings context
    findings = []
    if payload.include_findings_context:
        findings = _get_findings_for_context(current_user, payload.scan_id, db)

    # 2. RAG retrieval
    rag_context = retrieve(payload.message, n_results=3)
    rag_count = len(rag_context.split("[")) - 1 if rag_context else 0

    # 3. Get AI response
    reply = await get_ai_response(
        user_message=payload.message,
        findings=findings,
        rag_context=rag_context,
    )

    provider = os.getenv("AI_PROVIDER", "ollama")

    return ChatResponse(
        reply=reply,
        provider=provider,
        findings_injected=len(findings),
        rag_docs_retrieved=max(rag_count, 0),
    )


@router.get("/status")
def ai_status():
    """Check which AI provider is configured and RAG knowledge base size."""
    import os
    from ..rag_module import get_collection_size

    provider = os.getenv("AI_PROVIDER", "ollama")
    kb_size = get_collection_size()

    return {
        "provider": provider,
        "model": os.getenv("OLLAMA_MODEL" if provider == "ollama" else "GROQ_MODEL", "unknown"),
        "knowledge_base_documents": kb_size,
        "status": "ready",
    }
