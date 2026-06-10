# ShieldScan 🛡️

A lightweight **Cloud-Native Application Protection Platform (CNAPP)** built for students and early-stage startups.

> MSc Computer Security — EPITA Paris | Action Learning Project | Team of 4

---

## What it does

ShieldScan scans your AWS infrastructure and containers for security misconfigurations, vulnerabilities, and compliance gaps — then uses AI to explain findings and suggest fixes.

| Module | What it covers | Technology |
|--------|---------------|------------|
| **CSPM** | AWS misconfigurations (S3, IAM, Security Groups, RDS...) | Python + boto3 |
| **CWPP** | Container CVEs and image vulnerabilities | Trivy |
| **Risk Scoring** | Prioritizes findings by exploitability + impact | XGBoost |
| **AI Assistant** | Explains findings, suggests fixes in plain English | Ollama (dev) / Groq (prod) + RAG |
| **Frontend** | Dashboard, findings explorer, compliance view | React (CDN) |
| **Backend** | REST API, auth, database | FastAPI + SQLite |

---

## Project structure

```
shieldscan/
├── prototype/                  # Demo shown to professor — do NOT edit for prod
│   ├── demo_frontend.html      # Single-file React prototype
│   ├── demo_backend.py         # FastAPI mock backend
│   └── rag_module.py           # In-memory ChromaDB demo
│
└── app/                        # Production application
    ├── backend/
    │   ├── main.py             # FastAPI app entry point
    │   ├── database.py         # SQLAlchemy + SQLite setup
    │   ├── models.py           # DB models: User, Scan, Finding
    │   ├── auth.py             # JWT authentication
    │   ├── ai_service.py       # LLM provider abstraction (Ollama/Groq/Claude)
    │   ├── rag_module.py       # Persistent ChromaDB RAG
    │   ├── scan_manager.py     # Orchestrator: calls CSPM + CWPP + risk scorer
    │   ├── requirements.txt
    │   ├── .env.example        # Copy to .env and fill in secrets
    │   ├── routers/
    │   │   ├── auth.py         # /api/auth/register, /login, /me
    │   │   └── ai.py           # /api/ai/chat, /api/ai/status
    │   └── services/           # ← TEAMMATE CODE GOES HERE
    │       ├── cspm_service.py # [Teammate 1] AWS posture scanning (boto3)
    │       ├── cwpp_service.py # [Teammate 2] Container scanning (Trivy)
    │       └── risk_scorer.py  # [Teammate 3] XGBoost risk scoring
    └── frontend/
        └── index.html          # React frontend (connects to real API)
```

---

## Team ownership

| Area | Owner | Status |
|------|-------|--------|
| Frontend + Backend + AI | Kiran | 🟡 In progress |
| CSPM (boto3 AWS scanning) | Teammate 1 | ⏳ Pending |
| CWPP (Trivy container scanning) | Teammate 2 | ⏳ Pending |
| XGBoost risk scoring | Teammate 3 | ⏳ Pending |

---

## Getting started

### Prerequisites
- Python 3.11
- [Ollama](https://ollama.ai) (for local AI — run `ollama pull llama3.2`)

### Setup

```bash
# 1. Clone the repo
git clone https://github.com/Kaushik-reddy55/shieldscan.git
cd shieldscan

# 2. Create virtual environment
python3.11 -m venv ~/shieldscan-venv
source ~/shieldscan-venv/bin/activate

# 3. Install dependencies
pip install -r app/backend/requirements.txt

# 4. Set up environment variables
cp app/backend/.env.example app/backend/.env
# Edit app/backend/.env and fill in your values

# 5. Run the backend
cd app
uvicorn backend.main:app --reload --port 8000
```

Open `http://localhost:8000/docs` to see the interactive API docs.

To run the prototype demo (separate, no setup needed):
```bash
cd prototype
python demo_backend.py
# Then open demo_frontend.html in your browser
```

---

## API endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | No | Create account |
| POST | `/api/auth/login` | No | Login, get JWT token |
| GET | `/api/auth/me` | Yes | Get current user profile |
| PUT | `/api/auth/aws` | Yes | Save AWS credentials |
| POST | `/api/ai/chat` | Yes | Chat with AI about your findings |
| GET | `/api/ai/status` | No | Check AI provider + RAG status |
| GET | `/health` | No | Health check |

---

## For teammates — how to contribute

See [`app/backend/services/`](app/backend/services/) — each file has a clear interface contract showing exactly what functions to implement and what data shape to return.

**Contract (do not change the function signatures):**

- `cspm_service.py` → implement `run_cspm_scan(aws_access_key, aws_secret_key, region) -> list[Finding]`
- `cwpp_service.py` → implement `run_cwpp_scan(image_name) -> list[Finding]`
- `risk_scorer.py` → implement `score_findings(findings: list[Finding]) -> float`

The `scan_manager.py` orchestrator already calls these functions — your implementation just needs to match the interface.

---

## Environment variables

Copy `app/backend/.env.example` to `app/backend/.env` and fill in:

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | SQLite (default) or PostgreSQL | Yes |
| `JWT_SECRET_KEY` | Random 32-char string | Yes |
| `AWS_ENCRYPTION_KEY` | Fernet key for encrypting AWS creds | Yes |
| `AI_PROVIDER` | `ollama` (dev) or `groq` (prod) | Yes |
| `GROQ_API_KEY` | Free at console.groq.com | For prod |

⚠️ Never commit `.env` — it's gitignored.

---

## Tech stack

- **Backend:** FastAPI, SQLAlchemy, SQLite → PostgreSQL
- **Auth:** JWT (python-jose) + bcrypt (passlib)
- **AI:** Ollama locally, Groq API (free) on deploy
- **RAG:** ChromaDB with CIS AWS Benchmark knowledge base
- **Frontend:** React 18 (CDN), Tailwind CSS, no build step
- **Infra:** Oracle Cloud Always Free (deploy target)
- **Security scanning:** boto3 (CSPM), Trivy (CWPP), XGBoost (risk scoring)
