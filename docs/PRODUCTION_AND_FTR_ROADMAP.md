# ShieldScan — Production Readiness & AWS FTR Gap Analysis

**Audited:** 2026-06-20  
**Branch:** `kiran/full-backend`  
**Status at audit:** ~70% feature-complete, not production-safe

---

## How to read this doc

Each item is tagged with:
- `[BLOCKER]` — will cause outage, data loss, or FTR rejection
- `[HIGH]` — serious risk; fix before any public traffic
- `[MEDIUM]` — fix before FTR submission
- `[LOW]` — nice-to-have, doesn't block FTR

AWS FTR pillar codes: **SEC** / **REL** / **OPS** / **PERF** / **COST**

---

## 1. Critical Security Blockers

### 1.1 Hardcoded admin password in main.py `[BLOCKER][SEC]`

```python
# main.py line 51 — current code
admin = models.User(
    hashed_password=hash_password("Projectshieldscan@1234"),
```

This seeds a known password every restart. Anyone who reads the repo can log in as admin.

**Fix:** Read the password from `ADMIN_PASSWORD` env var, and only seed if the env var is set. Never commit a default.

```python
# main.py — replace seed_admin() with:
def seed_admin():
    admin_pass = os.getenv("ADMIN_PASSWORD")
    if not admin_pass:
        logger.warning("ADMIN_PASSWORD not set — skipping admin seed. Set it in .env.")
        return
    db = SessionLocal()
    try:
        existing = db.query(models.User).filter(
            models.User.email == os.getenv("ADMIN_EMAIL", "admin@shieldscan.com")
        ).first()
        if not existing:
            from .auth import hash_password
            admin = models.User(
                email=os.getenv("ADMIN_EMAIL", "admin@shieldscan.com"),
                full_name="ShieldScan Admin",
                hashed_password=hash_password(admin_pass),
                is_admin=True,
                is_active=True,
                email_verified=True,
            )
            db.add(admin)
            db.commit()
            logger.info("Admin account created from ADMIN_PASSWORD env var.")
    finally:
        db.close()
```

Add to `.env.example`:
```
ADMIN_EMAIL=admin@shieldscan.com
ADMIN_PASSWORD=        # generate: python -c "import secrets; print(secrets.token_urlsafe(24))"
```

---

### 1.2 JWT secret key has insecure fallback `[BLOCKER][SEC]`

```python
# auth.py line 27 — current code
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-in-production-please")
```

If `JWT_SECRET_KEY` is missing from `.env`, the app starts with a known secret. Tokens become forgeable.

**Fix:** Crash on startup if the secret is weak or missing:

```python
# auth.py — replace lines 27-28 with:
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "JWT_SECRET_KEY is not set or too short (must be ≥32 chars). "
        "Generate one: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
```

---

### 1.3 CORS is wide open `[BLOCKER][SEC]`

```python
# main.py line 91 — current code
allow_origins=["*"],
allow_credentials=True,   # ← this combination is illegal per spec
```

`allow_credentials=True` + `allow_origins=["*"]` violates the CORS spec and most browsers will block it. More importantly, it allows any website to make authenticated requests on behalf of your users.

**Fix:** Lock CORS to your actual domain. Use an env var so staging and prod differ:

```python
# main.py — replace CORSMiddleware block with:
import json
_raw_origins = os.getenv("CORS_ALLOWED_ORIGINS", '["http://localhost:3000","http://localhost:8000"]')
ALLOWED_ORIGINS = json.loads(_raw_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
```

Add to `.env.example`:
```
# Prod: '["https://shieldscan.io","https://www.shieldscan.io"]'
CORS_ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:8000"]
```

---

### 1.4 SQLite in production `[BLOCKER][REL]`

- SQLite cannot handle concurrent writes from multiple uvicorn workers
- Data is in `app/shieldscan.db` — not backed up, not replicated
- FTR reviewers will flag this immediately

**Fix:** Switch to PostgreSQL (RDS or Aurora Serverless on AWS).

```python
# database.py — already supports it, just set the env var:
DATABASE_URL=postgresql://shieldscan:STRONG_PASS@rds-endpoint:5432/shieldscan
```

For AWS Free Tier: use **RDS PostgreSQL** (db.t3.micro, 20GB). For the FTR badge path, use **RDS with Multi-AZ** (not free tier but required for REL pillar score).

**Also needed:** Replace the raw `ALTER TABLE` migration system in `database.py` with **Alembic**:

```bash
pip install alembic
alembic init alembic
# Then generate migrations from model changes:
alembic revision --autogenerate -m "initial"
alembic upgrade head
```

---

## 2. AWS FTR Pillar Requirements

### 2.1 SEC — Security

| Control | Status | Gap / Fix |
|---------|--------|-----------|
| No hardcoded credentials in code | ❌ | Admin password (item 1.1), JWT fallback (item 1.2) |
| IAM least privilege for app identity | ❌ | App should run with an IAM Role (EC2 instance profile), not embed keys |
| Encryption in transit | ❌ | Must run behind HTTPS — set up ACM cert + ALB or Nginx with Let's Encrypt |
| Encryption at rest | ⚠️ | AWS credentials are Fernet-encrypted in DB (✅), but DB itself (SQLite) is not encrypted at rest. Fix: RDS with encryption enabled |
| Secrets in AWS Secrets Manager | ❌ | `JWT_SECRET_KEY`, `AWS_ENCRYPTION_KEY`, `GROQ_API_KEY`, `ADMIN_PASSWORD` should all be in AWS Secrets Manager, not `.env` |
| WAF in front of API | ❌ | AWS WAF on ALB — protects against OWASP Top 10, DDoS |
| VPC with private subnets | ❌ | Backend and DB should be in a private subnet; only the ALB is public |
| Security group lockdown | ❌ | EC2 instance SG: only accept traffic from ALB SG on port 8000; RDS SG: only from EC2 SG on port 5432 |
| Vulnerability scanning of your own containers | ❌ (ironic) | ShieldScan scans others but doesn't scan itself. Add Trivy/ECR scanning to your CI pipeline |
| MFA on AWS root account | ❌ | Confirm it's enabled on the AWS account running ShieldScan infra |

**Secrets Manager integration (add to `database.py` and `auth.py`):**

```python
# utils/secrets.py — new file
import os, json, boto3, logging
logger = logging.getLogger(__name__)

def get_secret(secret_name: str, key: str = None) -> str:
    """Fetch a secret from AWS Secrets Manager, fallback to env var."""
    try:
        client = boto3.client("secretsmanager", region_name=os.getenv("AWS_REGION", "eu-west-1"))
        response = client.get_secret_value(SecretId=secret_name)
        secret = json.loads(response["SecretString"])
        return secret[key] if key else response["SecretString"]
    except Exception as e:
        logger.warning("Secrets Manager unavailable (%s), falling back to env var", e)
        return os.getenv(key or secret_name, "")
```

---

### 2.2 REL — Reliability

| Control | Status | Gap / Fix |
|---------|--------|-----------|
| Health check endpoint | ✅ | `/health` exists — extend to check DB + AI connectivity |
| Multi-AZ deployment | ❌ | RDS Multi-AZ + at least 2 EC2 instances behind ALB |
| Automated backups | ❌ | Enable RDS automated backups (7-day retention minimum for FTR) |
| Retry logic on external calls | ❌ | boto3 calls have no retry/backoff; Groq/Claude calls have no retry |
| Graceful error handling | ⚠️ | scan_manager.py catches exceptions, but returns them raw to the client |
| Pagination on `/api/scan/findings` | ❌ | Unbounded DB query — add `limit` + `offset` params |
| Background task queue | ❌ | Scans run synchronously (blocks a uvicorn worker). For prod: use Celery + Redis or AWS SQS |

**Extend health check to cover dependencies:**

```python
# main.py — replace /health with:
@app.get("/health")
def health(db: Session = Depends(get_db)):
    checks = {"api": "ok"}
    # DB check
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"
    # AI provider check
    checks["ai_provider"] = os.getenv("AI_PROVIDER", "ollama")
    overall = "ok" if all(v == "ok" or k == "ai_provider" for k, v in checks.items()) else "degraded"
    return {"status": overall, "service": "shieldscan-api", "checks": checks}
```

**Add retry decorator for boto3 calls (in `cspm_service.py`):**

```python
import time, functools

def retry(max_attempts=3, delay=1.0, backoff=2.0):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        raise
                    time.sleep(delay * (backoff ** (attempt - 1)))
        return wrapper
    return decorator

# Then decorate each CSPM check:
@retry(max_attempts=3, delay=0.5)
def _check_s3_public_access(session, region): ...
```

---

### 2.3 OPS — Operational Excellence

| Control | Status | Gap / Fix |
|---------|--------|-----------|
| Structured logging | ❌ | Logs are unstructured strings. FTR requires CloudWatch-compatible JSON logs |
| CloudWatch logging | ❌ | Needs `watchtower` library + log group |
| CloudWatch alarms | ❌ | Alarm on: 5xx rate > 1%, scan failure rate > 10%, p99 latency > 5s |
| AWS CloudTrail enabled | ❌ | Must be enabled in the infra account (separate from the app) |
| AWS Config enabled | ❌ | Required for FTR — tracks resource configuration changes |
| Infrastructure as Code | ❌ | No Dockerfile, no docker-compose, no Terraform/CDK |
| CI/CD pipeline | ❌ | No GitHub Actions workflow |
| API versioning | ❌ | Routes are `/api/auth/...` — add `/api/v1/auth/...` or use a versioning header |

**Structured JSON logging (add to `main.py`):**

```python
# main.py — add after imports:
import logging, json

class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "shieldscan-api",
        })

handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logging.basicConfig(handlers=[handler], level=logging.INFO)
```

**Request ID middleware (add to `main.py` for distributed tracing):**

```python
import uuid
from starlette.middleware.base import BaseHTTPMiddleware

class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

app.add_middleware(RequestIdMiddleware)
```

**CloudWatch logging (add `watchtower` to `requirements.txt`):**

```python
# requirements.txt additions:
watchtower==3.2.0
boto3==1.34.131   # already there

# main.py — add CloudWatch handler in production:
if os.getenv("ENV") == "production":
    import watchtower
    cw_handler = watchtower.CloudWatchLogHandler(
        log_group="/shieldscan/api",
        stream_name="backend",
    )
    cw_handler.setFormatter(JsonFormatter())
    logging.getLogger().addHandler(cw_handler)
```

---

### 2.4 PERF — Performance Efficiency

| Control | Status | Gap / Fix |
|---------|--------|-----------|
| Auto-scaling | ❌ | EC2 Auto Scaling Group (ASG) behind ALB — scale on CPU > 70% |
| Connection pooling | ❌ | SQLAlchemy pool_size not configured. Add: `create_engine(url, pool_size=10, max_overflow=20, pool_pre_ping=True)` |
| Async scan execution | ⚠️ | `run_full_scan` is `async` but uses `to_thread` for I/O — good, but a slow scan still holds a worker. Move to background task + SSE/WebSocket for progress. |
| ChromaDB for production | ❌ | ChromaDB runs in-process on local disk. For multi-worker prod: run ChromaDB as a separate server, or switch to PGVector (simpler if already using PostgreSQL) |

---

### 2.5 COST — Cost Optimization

| Control | Status | Gap / Fix |
|---------|--------|-----------|
| Cost allocation tags | ❌ | Tag all AWS resources: `Project=shieldscan`, `Environment=production`, `Team=epita` |
| Right-sizing | ❌ | Document instance type choices. Start with t3.micro (free tier), move to t3.small for prod |
| Spot instances for scan workers | ❌ | Non-critical background scans can run on Spot Instances (80% cost reduction) |

---

## 3. Production Infrastructure — What's Needed

### 3.1 Dockerfile (missing entirely)

```dockerfile
# app/backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install Trivy
RUN apt-get update && apt-get install -y wget curl && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo "deb https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list && \
    apt-get update && apt-get install -y trivy && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user (FTR requirement)
RUN useradd -m -u 1001 shieldscan
USER shieldscan

EXPOSE 8000

# Health check for ECS/ELB
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", "--access-log"]
```

### 3.2 docker-compose.yml (for local dev + staging)

```yaml
# docker-compose.yml (at repo root)
version: "3.9"

services:
  api:
    build: ./app/backend
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://shieldscan:shieldscan@db:5432/shieldscan
      - ENV=development
    env_file:
      - ./app/backend/.env
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - chroma_data:/app/chroma_db

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: shieldscan
      POSTGRES_PASSWORD: shieldscan
      POSTGRES_DB: shieldscan
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U shieldscan"]
      interval: 5s
      timeout: 3s
      retries: 5
    volumes:
      - postgres_data:/var/lib/postgresql/data

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./ssl:/etc/nginx/ssl:ro   # certs from Let's Encrypt / ACM
    depends_on:
      - api

volumes:
  postgres_data:
  chroma_data:
```

### 3.3 Nginx config (missing)

```nginx
# nginx.conf
server {
    listen 80;
    server_name shieldscan.io www.shieldscan.io;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name shieldscan.io www.shieldscan.io;

    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # HSTS (FTR requirement)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.tailwindcss.com; style-src 'self' 'unsafe-inline';" always;

    location / {
        root /usr/share/nginx/html;
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;   # scans can take a while
    }
}
```

### 3.4 CI/CD Pipeline (missing)

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, kiran/full-backend]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: test
          POSTGRES_DB: shieldscan_test
        ports: ["5432:5432"]
        options: --health-cmd pg_isready --health-interval 10s

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      
      - name: Install deps
        run: pip install -r app/backend/requirements.txt pytest pytest-asyncio httpx

      - name: Run Trivy scan on codebase (security)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Run tests
        env:
          DATABASE_URL: postgresql://postgres:test@localhost:5432/shieldscan_test
          JWT_SECRET_KEY: test-secret-key-for-ci-only-32chars
          AWS_ENCRYPTION_KEY: ${{ secrets.AWS_ENCRYPTION_KEY }}
        run: pytest app/backend/tests/ -v

  docker:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Build and push to ECR
        uses: aws-actions/amazon-ecr-login@v2
      - run: |
          docker build -t shieldscan-api ./app/backend
          docker tag shieldscan-api:latest ${{ secrets.ECR_REGISTRY }}/shieldscan-api:${{ github.sha }}
          docker push ${{ secrets.ECR_REGISTRY }}/shieldscan-api:${{ github.sha }}
```

---

## 4. Code-level Fixes (Non-Infrastructure)

### 4.1 `datetime.utcnow()` deprecation (Python 3.12+)

Affects `models.py`, `auth.py`, `routers/auth.py`, `scan_manager.py`.

```python
# Replace all occurrences of:
datetime.utcnow()

# With:
from datetime import datetime, timezone
datetime.now(timezone.utc).replace(tzinfo=None)  # or keep tzinfo if your DB supports it
```

### 4.2 Pagination on findings endpoint

```python
# routers/scans.py — add to get_findings():
@router.get("/findings")
def get_findings(
    ...
    page: int = 1,
    page_size: int = 50,
    ...
):
    offset = (page - 1) * page_size
    findings = query.offset(offset).limit(page_size).all()
    total = query.count()
    return {
        "scan_id": scan.id,
        "findings": [...],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }
```

### 4.3 Missing `is_email_configured` import guard

```python
# email_service.py — the function already exists as is_email_configured()
# but it's imported as is_email_configured in routers/auth.py ✅ — this is fine
```

### 4.4 Add `X-Content-Security-Policy` to security headers

```python
# main.py — extend add_security_headers:
response.headers["Content-Security-Policy"] = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self';"
)
response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
```

### 4.5 Rate limit the `/api/ai/chat` endpoint

LLM calls are expensive. Without a per-user limit, a single user can drain Groq quotas.

```python
# routers/ai.py — add rate limit:
@router.post("/chat")
@limiter.limit("20/hour")  # per IP / per user
async def chat(...):
```

---

## 5. AWS FTR Submission Checklist

Use this when you apply through the AWS Partner Network (APN) console.

| # | FTR Requirement | ShieldScan Status | Owner |
|---|----------------|------------------|-------|
| 1 | No hardcoded credentials | ❌ Fix items 1.1 + 1.2 | Kiran |
| 2 | IAM roles for EC2 (not embedded keys) | ❌ Add EC2 instance profile | Kiran |
| 3 | HTTPS/TLS in transit | ❌ Add ALB + ACM cert or Nginx + Let's Encrypt | Kiran |
| 4 | Encryption at rest (RDS) | ❌ Enable RDS encryption flag | Kiran |
| 5 | Secrets in AWS Secrets Manager | ❌ Migrate from `.env` | Kiran |
| 6 | AWS WAF on ALB | ❌ Create WAF Web ACL | Kiran |
| 7 | VPC with private subnets | ❌ IaC required | Kiran |
| 8 | CloudWatch logging | ❌ Add `watchtower` | Kiran |
| 9 | CloudWatch alarms | ❌ Create 3-5 alarms | Kiran |
| 10 | AWS CloudTrail enabled | ❌ 1-click in AWS console | Kiran |
| 11 | AWS Config enabled | ❌ 1-click in AWS console | Kiran |
| 12 | RDS automated backups | ❌ Enable in RDS settings | Kiran |
| 13 | IaC (Terraform or CDK) | ❌ Create for all infra | Kiran |
| 14 | Vulnerability scanning in CI | ❌ Add Trivy to GitHub Actions | Kiran |
| 15 | Multi-AZ or documented HA plan | ❌ At minimum document the RPO/RTO | Kiran |
| 16 | Cost allocation tags | ❌ Add to all resources | Kiran |
| 17 | Well-Architected review | ❌ Run AWS WA Tool self-assessment | Kiran |
| 18 | Health check endpoint | ✅ `/health` exists (extend it) | — |
| 19 | Rate limiting | ✅ slowapi in place | — |
| 20 | Account lockout | ✅ After 5 failed attempts | — |
| 21 | MFA for users | ✅ TOTP + passkey supported | — |
| 22 | Password strength validation | ✅ Server-side enforcement | — |
| 23 | Soft delete + GDPR account deletion | ✅ 30-day grace period | — |

---

## 6. Recommended Implementation Order

### Sprint 1 — Fix blockers (do this NOW, before any deployment)
1. Remove hardcoded admin password → env var (item 1.1)
2. Remove JWT secret fallback → crash on startup (item 1.2)
3. Fix CORS to locked-down origin list (item 1.3)
4. Write the `Dockerfile` (item 3.1)
5. Write `docker-compose.yml` with PostgreSQL (item 3.2)
6. Switch `DATABASE_URL` to PostgreSQL in your deploy `.env`

### Sprint 2 — AWS infrastructure (week before FTR application)
7. VPC: 2 public subnets (ALB) + 2 private subnets (EC2 + RDS)
8. RDS PostgreSQL — encryption enabled, Multi-AZ, 7-day backups
9. ACM certificate + ALB with HTTPS listener
10. AWS Secrets Manager: migrate all secrets from `.env`
11. EC2 instance profile IAM role (no long-term keys for the app itself)
12. AWS WAF on ALB (use managed rule groups)
13. CloudWatch log group + `watchtower` integration
14. Enable CloudTrail + AWS Config (console, 5 minutes)

### Sprint 3 — Operational excellence (complete FTR checklist)
15. GitHub Actions CI: Trivy scan + pytest + ECR push
16. CloudWatch alarms: 5xx rate, scan failure rate, CPU > 80%
17. Terraform or CDK for all infra above
18. Alembic migrations replacing raw ALTER TABLE
19. PGVector (replaces ChromaDB for prod — same PostgreSQL instance)
20. Run AWS Well-Architected Tool self-assessment → attach report to FTR submission

---

## 7. AWS FTR Application Path

1. Join **AWS Partner Network (APN)** free — register at `aws.amazon.com/partners`
2. Reach **Select Tier** (requires 2 AWS certifications on the team — MSc Computer Security counts toward knowledge requirements)
3. Submit **Foundational Technical Review** through the APN Partner Central console
4. Attach: architecture diagram, security controls doc, Well-Architected report
5. AWS reviews within 2–4 weeks → badge issued if passed

The FTR badge also makes you eligible for **AWS Activate** credits (up to $100,000 for startups) and listing on **AWS Marketplace**.

---

*This document was generated from a live codebase audit on 2026-06-20. Re-run the audit after each sprint to verify items are closed.*
