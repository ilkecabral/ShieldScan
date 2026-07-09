# ShieldScan — Production Deployment Roadmap

**Created:** 2026-06-20  
**Target:** Public launch + AWS FTR badge

---

## Current Status (end of Phase 1–4)

Code is security-hardened and production-structured but not yet deployable.  
Three critical runtime issues remain before any real traffic can be served.

---

## Week 1 — Make the code production-safe
*No AWS account needed. All fixes are local code and Docker changes.*

### 🔴 Critical runtime fixes

| # | Issue | Impact | Status |
|---|-------|--------|--------|
| 1 | ChromaDB runs in-process (`PersistentClient`) | 2 uvicorn workers fight over same file → crash | ✅ |
| 2 | `/api/scan/run` blocks a uvicorn worker for 60s | 2 concurrent scans = API fully unresponsive | ✅ |

### 🟡 Required before CI works

| # | Task | Status |
|---|------|--------|
| 3 | Create `app/backend/tests/` with minimal pytest suite | ✅ |
| 4 | Add `docker-compose.prod.yml` (no exposed port 8000, ChromaDB as service) | ✅ |

### 🔵 Configuration

| # | Task | Status |
|---|------|--------|
| 5 | Set `CORS_ALLOWED_ORIGINS` in `.env` to production domain | ⬜ |
| 6 | Set `ADMIN_PASSWORD` in `.env` | ⬜ |
| 7 | Set `GROQ_API_KEY` or `ANTHROPIC_API_KEY` in `.env` | ⬜ |

---

## Week 2 — AWS infrastructure
*Requires AWS account. All done in AWS console or Terraform.*

### VPC & Networking
| # | Task | Status |
|---|------|--------|
| 8 | Create VPC with 2 public subnets (ALB) + 2 private subnets (EC2 + RDS) | ⬜ |
| 9 | Create security groups: ALB → EC2 (8000), EC2 → RDS (5432) | ⬜ |

### Database
| # | Task | Status |
|---|------|--------|
| 10 | Launch RDS PostgreSQL 16 (db.t3.micro) — encryption ON, Multi-AZ, 7-day backups | ⬜ |
| 11 | Run `alembic upgrade head` against RDS | ⬜ |
| 12 | Update `DATABASE_URL` in production `.env` to RDS endpoint | ⬜ |

### Compute & Load Balancing
| # | Task | Status |
|---|------|--------|
| 13 | Launch EC2 (t3.small) with IAM instance profile (no long-term keys) | ⬜ |
| 14 | Create ECR repository — push first Docker image | ⬜ |
| 15 | Create ALB + HTTPS listener (port 443) | ⬜ |
| 16 | Request ACM certificate for domain | ⬜ |

### Security
| # | Task | Status |
|---|------|--------|
| 17 | Move secrets to AWS Secrets Manager — set `SECRETS_MANAGER_SECRET_NAME` | ⬜ |
| 18 | Create AWS WAF Web ACL on ALB (AWS managed rule groups) | ⬜ |

### CI/CD
| # | Task | Status |
|---|------|--------|
| 19 | Add 4 GitHub Actions secrets (`CI_JWT_SECRET_KEY`, `CI_AWS_ENCRYPTION_KEY`, `AWS_ECR_ROLE_ARN`, `AWS_REGION`) | ⬜ |
| 20 | Configure OIDC trust between GitHub Actions and AWS | ⬜ |
| 21 | First successful CI pipeline run on `main` branch | ⬜ |

### SSL Certificates
| # | Task | Status |
|---|------|--------|
| 22 | Provision SSL cert via ACM (attach to ALB) OR certbot (attach to Nginx) | ⬜ |
| 23 | Verify HTTPS redirect works end-to-end | ⬜ |

---

## Week 3 — Hardening + FTR submission
*Final production hardening and AWS FTR application.*

### Observability
| # | Task | Status |
|---|------|--------|
| 24 | Verify CloudWatch logs flowing (`ENV=production` → watchtower active) | ⬜ |
| 25 | Create CloudWatch alarm: 5xx rate > 1% for 5 min | ⬜ |
| 26 | Create CloudWatch alarm: CPU > 80% for 10 min | ⬜ |
| 27 | Create CloudWatch alarm: RDS storage < 20% free | ⬜ |
| 28 | Create CloudWatch alarm: scan failure rate > 10% | ⬜ |

### AWS Compliance
| # | Task | Status |
|---|------|--------|
| 29 | Enable AWS CloudTrail (1-click in console) | ⬜ |
| 30 | Enable AWS Config (1-click in console) | ⬜ |
| 31 | Verify MFA on AWS root account | ⬜ |

### FTR Submission
| # | Task | Status |
|---|------|--------|
| 32 | Run AWS Well-Architected Tool self-assessment (all 5 pillars) | ⬜ |
| 33 | Draw architecture diagram (VPC, ALB, EC2, RDS, Secrets Manager, WAF, CloudWatch) | ⬜ |
| 34 | Write security controls document | ⬜ |
| 35 | Join AWS Partner Network (APN) at aws.amazon.com/partners | ⬜ |
| 36 | Reach APN Select Tier (2 AWS certifications on team) | ⬜ |
| 37 | Submit FTR in APN Partner Central console | ⬜ |
| 38 | Attach: architecture diagram + WA report + security controls doc | ⬜ |

---

## Progress tracker

| Week | Total tasks | Done | Remaining |
|------|-------------|------|-----------|
| Week 1 — Code prod-safe | 7 | 4 | 3 |
| Week 2 — AWS infrastructure | 16 | 0 | 16 |
| Week 3 — Hardening + FTR | 15 | 0 | 15 |
| **Total** | **38** | **4** | **34** |

*Update the Status column above (⬜ → ✅) as each item is completed.*
