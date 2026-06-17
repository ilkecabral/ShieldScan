"""
ai_service.py — LLM provider abstraction for ShieldScan
Supports: ollama (local dev) | groq (cloud free tier) | claude (paid)
Switch by setting AI_PROVIDER in .env — zero code changes needed.

Usage:
    from .ai_service import get_ai_response
    reply = await get_ai_response(user_message, context_findings, rag_context)
"""

import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama").lower()

# ─────────────────────────────────────────
# Shared system prompt — scope-locked to cloud security
# ─────────────────────────────────────────

SYSTEM_PROMPT_BASE = """You are ShieldScan AI, a cloud security assistant built into the ShieldScan CNAPP platform.

Your ONLY job is to help users understand and fix cloud security findings, misconfigurations, vulnerabilities, and compliance gaps.

Rules:
- Answer ONLY questions about cloud security, AWS, containers, CVEs, compliance (CIS, NIST, SOC2), IAM, networking, and infrastructure security.
- If asked anything unrelated to cloud security or infrastructure, reply: "I can only help with cloud security topics. Please ask me about your findings or security configurations."
- Always be specific and actionable. Reference the actual finding data provided.
- Keep answers concise. Lead with the fix, then explain why.
- For CVEs, always mention the affected package, severity, and fix version if available.

When scan findings are provided in context, prioritize answering based on those specific findings."""


def _build_full_system_prompt(findings_context: str, rag_context: str) -> str:
    """Inject the user's real findings + RAG knowledge into the system prompt."""
    parts = [SYSTEM_PROMPT_BASE]

    if findings_context:
        parts.append(f"\n\n--- USER'S CURRENT SCAN FINDINGS ---\n{findings_context}")

    if rag_context:
        parts.append(f"\n\n--- RELEVANT SECURITY KNOWLEDGE BASE ---\n{rag_context}")

    return "\n".join(parts)


def _format_findings_for_context(findings: list[dict]) -> str:
    """Turn a list of finding dicts into a readable string for the system prompt."""
    if not findings:
        return ""
    lines = []
    for f in findings:
        severity = f.get("severity", "UNKNOWN")
        title = f.get("title", "Untitled finding")
        resource = f.get("resource", "N/A")
        finding_id = f.get("finding_id", "")
        cve = f.get("cve_id", "")
        cve_str = f" [{cve}]" if cve else ""
        lines.append(f"- [{severity}]{cve_str} {title} (resource: {resource}, id: {finding_id})")
    return "\n".join(lines)


# ─────────────────────────────────────────
# Provider: Ollama (local dev)
# ─────────────────────────────────────────

async def _call_ollama(system_prompt: str, user_message: str) -> str:
    import ollama as ollama_client

    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    try:
        client = ollama_client.Client(host=base_url)
        response = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        )
        return response.message.content
    except Exception as e:
        return f"[Ollama error: {e}. Is Ollama running? Run: ollama serve]"


# ─────────────────────────────────────────
# Provider: Groq (free tier, cloud deploy)
# Model: llama-3.3-70b-versatile — 14,400 req/day, 500 tok/sec
# ─────────────────────────────────────────

async def _call_groq(system_prompt: str, user_message: str) -> str:
    import httpx

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "[Groq error: GROQ_API_KEY not set in .env]"

    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "temperature": 0.3,
        "max_tokens": 1024,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[Groq error: {e}]"


# ─────────────────────────────────────────
# Provider: Claude API (Anthropic — paid)
# ─────────────────────────────────────────

async def _call_claude(system_prompt: str, user_message: str) -> str:
    import httpx

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return "[Claude error: ANTHROPIC_API_KEY not set in .env]"

    model = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")

    payload = {
        "model": model,
        "max_tokens": 1024,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_message}],
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]
    except Exception as e:
        return f"[Claude error: {e}]"


# ─────────────────────────────────────────
# Public interface — called by routers/ai.py
# ─────────────────────────────────────────

async def get_ai_response(
    user_message: str,
    findings: Optional[list[dict]] = None,
    rag_context: Optional[str] = None,
) -> str:
    """
    Main entry point. Builds context-injected system prompt and calls the
    configured AI provider.

    Args:
        user_message: The user's question
        findings: List of finding dicts from the user's latest scan (can be empty)
        rag_context: Retrieved RAG snippets from ChromaDB (can be empty string)

    Returns:
        The AI's response as a string
    """
    findings_context = _format_findings_for_context(findings or [])
    system_prompt = _build_full_system_prompt(findings_context, rag_context or "")

    provider = AI_PROVIDER
    if provider == "groq":
        return await _call_groq(system_prompt, user_message)
    elif provider == "claude":
        return await _call_claude(system_prompt, user_message)
    else:
        # Default: ollama
        return await _call_ollama(system_prompt, user_message)
