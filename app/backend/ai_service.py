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

SYSTEM_PROMPT_BASE = """You are ShieldScan AI, an expert cloud security assistant embedded in the ShieldScan CNAPP platform.

YOUR SOLE PURPOSE is to help users understand, prioritize, and remediate cloud security issues:
- AWS misconfigurations (IAM, S3, EC2, VPC, RDS, CloudTrail, KMS)
- Container CVEs detected by Trivy
- Compliance gaps (CIS AWS Benchmark, NIST 800-53, SOC 2, PCI-DSS)
- Security best practices for cloud-native infrastructure
- Analysis of scan findings from the user's connected AWS account

HARD RESTRICTIONS — you MUST follow these without exception:
1. SCOPE: Only answer questions related to cloud security, AWS, containers, CVEs, infrastructure security, compliance, and the user's scan findings. Reject everything else.
2. OFF-TOPIC REFUSAL: If the user asks about anything outside cloud security (coding help, math, recipes, general AI questions, current events, personal advice, etc.), respond ONLY with: "I'm ShieldScan AI — I can only help with cloud security topics. Ask me about your scan findings, AWS misconfigurations, CVEs, or compliance requirements."
3. NO HALLUCINATION: Only reference CVEs, controls, or services that are explicitly mentioned in the scan findings or knowledge base context provided below. Do not invent finding IDs or CVE numbers.
4. FINDINGS FIRST: When scan findings are provided, always anchor your answer to those specific findings. Reference finding IDs, resource names, and severities.
5. ACTIONABLE: Lead every answer with the concrete fix (CLI command or console steps), then explain why it matters.
6. CONCISE: Keep answers under 300 words unless a step-by-step guide is explicitly requested."""


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
# Provider: Ollama (local — via REST API, no Python SDK needed)
# ─────────────────────────────────────────

async def _call_ollama(system_prompt: str, user_message: str) -> str:
    import httpx

    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
    }

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{base_url}/api/chat",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data["message"]["content"]
    except httpx.ConnectError:
        return (
            "Ollama is not running. Open a terminal and run:\n\n"
            "  ollama serve\n\n"
            "Keep that terminal open, then send your message again."
        )
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return (
                f"Model '{model}' is not pulled yet. In a terminal run:\n\n"
                f"  ollama pull {model}\n\n"
                f"Then send your message again."
            )
        return f"Ollama returned an error ({e.response.status_code}): {e.response.text}"
    except Exception as e:
        return f"Ollama error: {e}"


# ─────────────────────────────────────────
# Provider: Groq (free tier, cloud deploy)
# Model: llama-3.3-70b-versatile — 14,400 req/day, 500 tok/sec
# ─────────────────────────────────────────

async def _call_groq(system_prompt: str, user_message: str) -> str:
    import httpx

    api_key = (os.getenv("GROQ_API_KEY") or "").strip()
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

def _check_provider_configured() -> "str | None":
    """
    Return a setup-instructions string if the selected provider is not properly
    configured or not reachable, or None if everything looks good.
    """
    provider = AI_PROVIDER
    if provider == "ollama":
        # No pre-flight check — the actual call handles connection errors with
        # clear messages. A blocking 2-second check here slows every request.
        return None
    elif provider == "groq":
        key = os.getenv("GROQ_API_KEY", "").strip()
        if not key:
            return (
                "⚙️ **Groq API key not configured.**\n\n"
                "Get a free key (takes 60 seconds, no credit card):\n"
                "1. Go to https://console.groq.com/keys\n"
                "2. Sign in with GitHub or Google\n"
                "3. Click **Create API Key** → copy it\n"
                "4. Open `.env` → set `GROQ_API_KEY=<your-key>`\n"
                "5. Restart the backend (Ctrl+C → run uvicorn again)\n\n"
                "Groq is free: 14,400 requests/day, no billing info needed."
            )
    elif provider == "claude":
        key = os.getenv("ANTHROPIC_API_KEY", "")
        if not key or key.startswith("your_"):
            return (
                "⚙️ ANTHROPIC_API_KEY not set in .env. "
                "Add your key from https://console.anthropic.com and restart the backend."
            )
    return None


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
    # Guard: check provider is properly configured before making any network call
    config_error = _check_provider_configured()
    if config_error:
        return config_error

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
