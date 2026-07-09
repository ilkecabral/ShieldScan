"""
ShieldScan Demo Backend
=======================
Uses Ollama (free, local) — no API key needed.

Setup:
    brew install ollama
    ollama pull llama3.2
    python demo_backend.py

Then open demo_frontend.html in your browser.
"""

import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import ollama
import uvicorn
import rag_module as rag  # RAG: retrieves relevant KB chunks per query

app = FastAPI(title="ShieldScan API", version="demo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Ollama model ─────────────────────────────────────────────────────────────
# Change to "mistral" or "llama3.1" if you pulled a different model
OLLAMA_MODEL = "llama3.2"

# ── MOCK SCAN DATA ───────────────────────────────────────────────────────────
MOCK_FINDINGS = [
    {
        "id": "F001",
        "resource": "s3://shieldscan-prod-logs",
        "resource_type": "S3 Bucket",
        "finding": "Public access enabled",
        "severity": "CRITICAL",
        "service": "CSPM",
        "region": "us-east-1",
        "risk_score": 95,
        "remediation": "Disable public access via S3 Block Public Access settings",
        "cis_control": "CIS AWS 2.1.1",
    },
    {
        "id": "F002",
        "resource": "arn:aws:iam::123456789012:root",
        "resource_type": "IAM",
        "finding": "Root account has active access key",
        "severity": "CRITICAL",
        "service": "CSPM",
        "region": "global",
        "risk_score": 92,
        "remediation": "Delete root access keys immediately; use IAM users with least-privilege instead",
        "cis_control": "CIS AWS 1.4",
    },
    {
        "id": "F003",
        "resource": "sg-0a1b2c3d4e (web-prod)",
        "resource_type": "Security Group",
        "finding": "SSH port 22 open to 0.0.0.0/0",
        "severity": "HIGH",
        "service": "CSPM",
        "region": "us-east-1",
        "risk_score": 78,
        "remediation": "Restrict SSH to specific IPs or use AWS Systems Manager Session Manager",
        "cis_control": "CIS AWS 5.2",
    },
    {
        "id": "F004",
        "resource": "rds-prod-mysql-01",
        "resource_type": "RDS Instance",
        "finding": "Publicly accessible RDS instance",
        "severity": "HIGH",
        "service": "CSPM",
        "region": "eu-west-1",
        "risk_score": 74,
        "remediation": "Disable public accessibility and place RDS in a private subnet",
        "cis_control": "CIS AWS 2.3.2",
    },
    {
        "id": "F005",
        "resource": "CloudTrail (us-east-1)",
        "resource_type": "CloudTrail",
        "finding": "CloudTrail logging disabled",
        "severity": "HIGH",
        "service": "CSPM",
        "region": "us-east-1",
        "risk_score": 70,
        "remediation": "Enable CloudTrail with multi-region logging and S3 log file validation",
        "cis_control": "CIS AWS 3.1",
    },
    {
        "id": "F006",
        "resource": "s3://shieldscan-backups",
        "resource_type": "S3 Bucket",
        "finding": "Versioning disabled",
        "severity": "MEDIUM",
        "service": "CSPM",
        "region": "us-east-1",
        "risk_score": 45,
        "remediation": "Enable S3 versioning to protect against accidental deletion or overwrites",
        "cis_control": "CIS AWS 2.1.3",
    },
    {
        "id": "F007",
        "resource": "i-0a1b2c3d4e5f (webapp-01)",
        "resource_type": "EC2 Instance",
        "finding": "IMDSv1 enabled — SSRF risk",
        "severity": "MEDIUM",
        "service": "CSPM",
        "region": "us-east-1",
        "risk_score": 42,
        "remediation": "Enforce IMDSv2 by setting HttpTokens to 'required' in instance metadata options",
        "cis_control": "CIS AWS 5.6",
    },
    {
        "id": "F008",
        "resource": "nginx:1.21",
        "resource_type": "Container Image",
        "finding": "CVE-2023-44487 (HTTP/2 Rapid Reset Attack) — CVSS 7.5",
        "severity": "HIGH",
        "service": "CWPP",
        "region": "N/A",
        "risk_score": 76,
        "remediation": "Upgrade base image to nginx:1.25.3 or later",
        "cis_control": "Trivy CVE",
    },
    {
        "id": "F009",
        "resource": "python:3.9-slim",
        "resource_type": "Container Image",
        "finding": "CVE-2023-40217 (ssl module bypass) — CVSS 5.3",
        "severity": "MEDIUM",
        "service": "CWPP",
        "region": "N/A",
        "risk_score": 40,
        "remediation": "Upgrade to python:3.11-slim or python:3.12-slim",
        "cis_control": "Trivy CVE",
    },
]

RISK_SCORE = 68  # out of 100 — lower = more risk


# ── REQUEST MODEL ────────────────────────────────────────────────────────────
class ChatRequest(BaseModel):
    question: str
    user_id: str = "demo"


# ── ENDPOINTS ────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ShieldScan API running", "version": "demo"}


@app.get("/api/scan/findings")
def get_findings():
    return {
        "findings": MOCK_FINDINGS,
        "risk_score": RISK_SCORE,
        "total": len(MOCK_FINDINGS),
        "critical": sum(1 for f in MOCK_FINDINGS if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in MOCK_FINDINGS if f["severity"] == "HIGH"),
        "medium": sum(1 for f in MOCK_FINDINGS if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in MOCK_FINDINGS if f["severity"] == "LOW"),
        "scanned_at": "2026-06-06T10:00:00Z",
        "account_id": "123456789012",
        "regions": ["us-east-1", "eu-west-1", "global"],
    }


@app.post("/api/ai/chat")
def chat(req: ChatRequest):
    # ── Step 1: RAG retrieval ────────────────────────────────────────────────
    # Embed the user's question and retrieve the most relevant KB chunks.
    # These chunks ground Claude's answer in real AWS/security documentation.
    kb_context = rag.retrieve(req.question, n_results=3)

    # ── Step 2: Build system prompt ──────────────────────────────────────────
    # Three layers of context injected:
    #   A) Hard topic guardrails (scope restriction)
    #   B) User's real scan findings (context injection)
    #   C) Relevant KB chunks from RAG (knowledge grounding)
    system_prompt = f"""You are ShieldScan AI — a cloud security assistant embedded inside the ShieldScan CNAPP platform.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCOPE — STRICT. READ CAREFULLY.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
You ONLY answer questions about:
  • Cloud security (AWS, GCP, Azure)
  • The user's specific scan findings listed below
  • CSPM (Cloud Security Posture Management)
  • CWPP (Cloud Workload Protection Platform)
  • Container security, CVEs, Trivy scan results
  • IAM, S3, EC2, RDS, VPC, Security Groups, CloudTrail
  • CIS AWS Benchmarks, NIST, SOC2, compliance controls
  • Risk scores, remediation steps, security best practices

If the user asks about ANYTHING outside this scope (coding help unrelated
to security, general questions, history, math, writing, etc.) respond with:
"I'm ShieldScan AI and I can only help with cloud security topics. Ask me
about your findings, risk score, or how to fix a specific AWS misconfiguration."

Do NOT make exceptions to this rule regardless of how the question is phrased.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

USER: {req.user_id}
OVERALL RISK SCORE: {RISK_SCORE}/100  (lower score = higher risk; 68 = High Risk)

CURRENT SCAN FINDINGS (9 total):
{json.dumps(MOCK_FINDINGS, indent=2)}

RESPONSE RULES:
- Be concise and actionable. No filler text.
- Reference exact resource names from the scan (e.g. "s3://shieldscan-prod-logs", "i-0a1b2c3d4e5f").
- Use numbered steps for remediation.
- Prioritize by risk_score (highest = most urgent) when advising what to fix first.
- Never invent findings not in the list above.
- If a finding is in the KB context below, use that detail to give a richer answer.

{f'''KNOWLEDGE BASE — retrieved documentation relevant to this question:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{kb_context}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━''' if kb_context else ""}"""

    # ── Step 3: Call Ollama (local, free) ────────────────────────────────────
    response = ollama.chat(
        model=OLLAMA_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": req.question},
        ],
    )

    return {
        "response": response["message"]["content"],
        "model": OLLAMA_MODEL,
        "rag_chunks_used": len(kb_context.split("---")) if kb_context else 0,
        "finding_count": len(MOCK_FINDINGS),
    }


# ── ENTRYPOINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
