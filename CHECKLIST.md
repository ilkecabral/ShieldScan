# ShieldScan — Production & AWS FTR Checklist

Last updated: 2026-06-20

---

## Phase 1 — Code Security Fixes

- [x] Remove hardcoded admin password from `main.py` → `ADMIN_PASSWORD` env var
- [x] JWT secret crash-on-startup guard (fails if missing or under 32 chars)
- [x] CORS locked to `CORS_ALLOWED_ORIGINS` env var — no more `allow_origins=["*"]`
- [x] Add Content-Security-Policy (CSP) header
- [x] Add Strict-Transport-Security (HSTS) header
- [x] Add Request ID middleware (`X-Request-ID` on every response)
- [x] Structured JSON logging (CloudWatch-compatible format)
- [x] Replace all `datetime.utcnow()` — fixed in 8 files (`auth.py`, `models.py`, `routers/auth.py`, `routers/scans.py`, `routers/admin.py`, `routers/reset.py`, `routers/recover.py`, `scan_manager.py`)
- [x] Paginate `/api/scan/findings` — `page` + `page_size` params, max 200 per page
- [x] Rate limit `/api/ai/chat` — 20 requests/hour per IP
- [x] Update `.env.example` with all new variables documented

---

## Phase 2 — Infrastructure Files

- [x] `app/backend/Dockerfile` — multi-stage build, non-root user, Trivy bundled, health check
- [x] `app/backend/.dockerignore` — ensures `.env` never bakes into Docker image
- [x] `docker-compose.yml` — PostgreSQL 16 + API + Nginx with named volumes
- [x] `nginx.conf` — HTTPS redirect, TLS 1.2/1.3, nginx-level rate limiting, blocks `.env`/`.git` paths
- [x] `.github/workflows/ci.yml` — Trivy scan → pytest → ECR push (OIDC, no long-term AWS keys in CI)

---

## Phase 3 — Database

- [x] `database.py` rewritten — connection pooling (`pool_size=10`, `pool_pre_ping=True`), raw `ALTER TABLE` kept only for SQLite
- [x] Alembic scaffolded — `alembic.ini`, `env.py`, `script.py.mako`
- [x] Initial migration written — `alembic/versions/0001_initial_schema.py` (all 4 tables)
- [x] `requirements.txt` updated — added `alembic`, `psycopg2-binary`, `watchtower`, `uvicorn[standard]`
- [ ] Switch `DATABASE_URL` to PostgreSQL in production `.env`
- [ ] Run `alembic upgrade head` against production database

---

## Phase 4 — AWS Integrations (Code)

- [x] `utils/secrets.py` — AWS Secrets Manager wrapper with `.env` fallback
- [x] `auth.py` — `JWT_SECRET_KEY` and `AWS_ENCRYPTION_KEY` now fetched via `get_secret()`
- [x] CloudWatch logging via `watchtower` in `main.py` — activates when `ENV=production`
- [x] Retry decorator `@_aws_retry` on all 13 CSPM boto3 functions (exponential backoff on throttling)
- [x] Extended `/health` endpoint — checks DB connectivity + AI provider config

---

## Phase 5 — AWS Infrastructure (Console / Terraform)

- [ ] Create VPC with 2 public subnets (ALB) + 2 private subnets (EC2 + RDS)
- [ ] Launch RDS PostgreSQL (db.t3.micro free tier → db.t3.small for prod)
  - [ ] Enable encryption at rest
  - [ ] Enable Multi-AZ
  - [ ] Enable automated backups (7-day retention minimum)
- [ ] Request ACM certificate for your domain
- [ ] Create Application Load Balancer (ALB) with HTTPS listener (port 443)
- [ ] Create EC2 instance with IAM instance profile (no long-term keys)
- [ ] Create AWS WAF Web ACL on ALB (use AWS managed rule groups)
- [ ] Lock EC2 security group — only accept traffic from ALB SG on port 8000
- [ ] Lock RDS security group — only accept traffic from EC2 SG on port 5432
- [ ] Create ECR repository for Docker images

---

## Phase 6 — Secrets & Config

- [ ] Move all secrets to AWS Secrets Manager:
  - [ ] `JWT_SECRET_KEY`
  - [ ] `AWS_ENCRYPTION_KEY`
  - [ ] `GROQ_API_KEY` (or `ANTHROPIC_API_KEY`)
  - [ ] `ADMIN_PASSWORD`
  - [ ] `EMAIL_PASSWORD`
- [ ] Set `SECRETS_MANAGER_SECRET_NAME` in production `.env`
- [ ] Set `CORS_ALLOWED_ORIGINS` to your real production domain
- [ ] Set `ENV=production` to activate CloudWatch logging
- [ ] Set `APP_URL` to your production URL (used in email links)

---

## Phase 7 — Observability

- [ ] Create CloudWatch log group `/shieldscan/api`
- [ ] Create CloudWatch alarms:
  - [ ] 5xx error rate > 1% for 5 minutes
  - [ ] Scan failure rate > 10%
  - [ ] CPU > 80% for 10 minutes
  - [ ] RDS storage < 20% free
- [ ] Enable AWS CloudTrail in your AWS account (1-click in console)
- [ ] Enable AWS Config in your AWS account (1-click in console)

---

## Phase 8 — CI/CD Wiring

- [ ] Add GitHub repository secrets:
  - [ ] `CI_JWT_SECRET_KEY` — 32-char hex for test runs
  - [ ] `CI_AWS_ENCRYPTION_KEY` — Fernet key for test runs
  - [ ] `AWS_ECR_ROLE_ARN` — IAM role for OIDC ECR push
  - [ ] `AWS_REGION` — e.g. `eu-west-1`
- [ ] Create `app/backend/tests/` directory with at least one pytest test
- [ ] Configure GitHub Actions OIDC with AWS (avoids long-term access keys in CI)
- [ ] First successful CI run on `main` branch

---

## Phase 9 — AWS FTR Submission

- [ ] Run AWS Well-Architected Tool self-assessment (5 pillars)
- [ ] Draw architecture diagram (VPC, ALB, EC2, RDS, Secrets Manager, CloudWatch)
- [ ] Write security controls document (what each control does + evidence)
- [ ] Join AWS Partner Network (APN) — free at aws.amazon.com/partners
- [ ] Reach APN Select Tier (requires 2 AWS certifications on team)
- [ ] Submit Foundational Technical Review in APN Partner Central console
- [ ] Attach: architecture diagram + Well-Architected report + security controls doc
- [ ] Receive FTR badge (AWS reviews within 2–4 weeks)

---

## Progress Summary

| Phase | Status | Items Done | Items Left |
|-------|--------|-----------|------------|
| 1 — Code security | ✅ Done | 11 / 11 | 0 |
| 2 — Infrastructure files | ✅ Done | 5 / 5 | 0 |
| 3 — Database | 🔄 Partial | 4 / 6 | 2 |
| 4 — AWS integrations (code) | ✅ Done | 5 / 5 | 0 |
| 5 — AWS infrastructure | ⏳ Pending | 0 / 9 | 9 |
| 6 — Secrets & config | ⏳ Pending | 0 / 8 | 8 |
| 7 — Observability | ⏳ Pending | 0 / 7 | 7 |
| 8 — CI/CD wiring | ⏳ Pending | 0 / 8 | 8 |
| 9 — FTR submission | ⏳ Pending | 0 / 8 | 8 |
| **Total** | | **25 / 67** | **42** |
