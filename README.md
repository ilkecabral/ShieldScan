# ShieldScan

Cloud-Native CSPM + CWPP security platform for developers and early-stage startups.

---

## What is ShieldScan

ShieldScan unifies container vulnerability scanning (CWPP) and cloud security posture management (CSPM) into one lightweight platform. It is built for developers and student teams who are locked out of enterprise tools like Wiz, Lacework, or Orca that start at $20,000/year.

The platform pulls container and cloud-native security data into a single dashboard, filters noise with a triage engine, and surfaces only the real-world threats that need attention.

---

## The Problem

- **94% of enterprises** use cloud services
- **Half of all global workloads** now run in the public cloud
- **80% of organizations** suffered a cloud breach in the past year
- **99% of cloud security failures** are the customer's fault, primarily misconfigurations (Gartner)
- Average breach cost: **$4.3 million** per incident
- **86%** of exposed public container endpoints run on insecure default configurations

Free open-source scanners exist, but they operate in silos, dump raw JSON output, and never explain what to fix. ShieldScan closes that gap.

---

## Architecture

```
┌─────────────────────┐         ┌──────────────────────────────────┐
│  React Frontend     │         │   EC2 t3.micro (Ubuntu 24.04)    │
│                     │  HTTPS  │   ┌────────────────────────────┐ │
│                     │ ──────► │   │  nginx (reverse proxy)     │ │
│                     │         │   └──────────┬─────────────────┘ │
└─────────────────────┘         │              │                   │
                                │              ▼                   │
                                │   ┌────────────────────────────┐ │
                                │   │  FastAPI (uvicorn :8000)   │ │
                                │   │  /auth /scans /accounts    │ │
                                │   │  /findings /dashboard      │ │
                                │   └────────┬────────┬──────────┘ │
                                │            │        │            │
                                │     ┌──────▼──┐   ┌─▼──────────┐ │
                                │     │Postgres │   │  Trivy     │ │
                                │     │ (users) │   │  Prowler   │ │
                                │     │ Docker  │   │subprocess  │ │
                                │     └─────────┘   └────────────┘ │
                                └──────────────┬───────────────────┘
                                               │ boto3 + STS AssumeRole
                                               ▼
                                ┌──────────────────────────────────┐
                                │  User's AWS Account              │
                                │  (cross-account IAM role:        │
                                │   ShieldScanReadOnlyRole)        │
                                └──────────────────────────────────┘

DynamoDB (in ShieldScan's AWS account) stores findings, scans, account links
```

---

## What's Implemented

### CSPM — Cloud Security Posture Management

| Component | Status |
|---|---|
| AWS EC2 t3.micro provisioned (Ubuntu 26.04, eu-west-3) | ✅ Done |
| Disk resized to 28 GB with 2 GB swap | ✅ Done |
| ShieldScanEC2Role IAM role with SecurityAudit + ReadOnly + DynamoDB + ECR | ✅ Done |
| DynamoDB findings table (shieldscan-findings, PAY_PER_REQUEST) | ✅ Done |
| AWS CLI v2 authenticated via instance role | ✅ Done |
| Prowler installation on Python 3.12 venv | 🟡 In progress |
| Cross-account IAM role flow (CloudFormation template + STS AssumeRole) | ✅ Code complete |
| Daily scheduled CSPM scan via cron | ⬜ Pending Prowler install |

### CWPP — Container Workload Protection

| Component | Status |
|---|---|
| Trivy 0.71 installed on EC2 | ✅ Done |
| Trivy image scan in CI | ✅ Live |
| Trivy filesystem/IaC/secrets scan in CI | ✅ Live |
| SARIF upload to Security tab | ✅ Live |
| Build fails on unfixed CRITICAL CVEs | ✅ Live |
| Daily image rescan for new CVEs | ✅ Live |
| ECR repository (shieldscan-backend) with auto-scan on push | ✅ Provisioned |
| User-facing image scan API (`/scans/image`) | ✅ Code complete |

### Backend Platform

| Component | Status | Owner |
|---|---|---|
| FastAPI app skeleton with auto OpenAPI docs | ✅ Code complete | Kaushik |
| JWT authentication (register / login / me) | ✅ Code complete | Kaushik |
| Postgres 16 in Docker for user accounts | ✅ Provisioned | Kaushik |
| DynamoDB persistence for findings, scans, accounts | ✅ Code complete | Kaushik |
| Dashboard endpoints (summary, recent, 7-day trends) | ✅ Code complete | Kaushik |
| Cross-account AWS connection endpoints | ✅ Code complete | Kaushik |
| systemd service + nginx reverse proxy | ⬜ Pending deploy | Kaushik |
| CORS configured for frontend integration | ✅ Code complete | Kaushik |

### AI Fix Engine

| Component | Status | Owner |
|---|---|---|
| Vector-verified documentation loop | 🟡 In progress | Kaushik |
| RAG over vendor docs for code patch generation | 🟡 In progress | Kaushik |
| Severity triage engine (EPSS-based, not just CVSS) | ⬜ Planned | Kaushik |

### Frontend

| Component | Status |
|---|---|
| React + Vite + TypeScript scaffold | 🟡 In progress |
| Login / register pages | 🟡 In progress |
| Dashboard with severity charts | 🟡 In progress |
| Image scan form | 🟡 In progress |
| AWS account connection wizard | 🟡 In progress |
| S3 + CloudFront deploy | ⬜ Planned |

---

## Tech Stack

### Backend
- Python 3.12 + FastAPI 0.115
- PostgreSQL 16 (Docker) for user accounts
- DynamoDB (AWS) for findings, scans, account links
- SQLAlchemy 2 + psycopg 3
- python-jose + passlib[bcrypt] for JWT
- boto3 for AWS SDK
- uvicorn behind nginx, managed by systemd

### Security Engines
- Trivy 0.71 for container, filesystem, IaC, secret scanning (CWPP)
- Prowler 5 for AWS posture scanning (CSPM)

### AI Layer
- RAG with vector-verified documentation lookup
- Generates ready-to-execute code patches from scanner output

### Infrastructure
- AWS EC2 t3.micro (Ubuntu 26.04, eu-west-3 Paris)
- AWS DynamoDB (Always Free tier, PAY_PER_REQUEST)
- AWS ECR (container registry with auto-scan on push)
- AWS IAM (cross-account role assumption via STS)

### Frontend
- React 18 + Vite + TypeScript
- Tailwind CSS
- axios + @tanstack/react-query
- Recharts for trend visualization

---

## API Reference

The backend exposes a full OpenAPI 3.1 spec, auto-generated and live at `<BASE_URL>/docs` (Swagger UI) and `<BASE_URL>/openapi.json` (machine-readable).

### Endpoints

```
AUTH
POST   /auth/register              { email, password, full_name? }
POST   /auth/login                 { email, password }
GET    /auth/me                    🔒

SCANS (CWPP)
POST   /scans/image                🔒 { image }
GET    /scans                      🔒
GET    /scans/{scan_id}            🔒

AWS ACCOUNTS (CSPM)
GET    /accounts/setup-template    🔒
POST   /accounts                   🔒 { role_arn, external_id, nickname? }
GET    /accounts                   🔒
DELETE /accounts/{account_id}      🔒
POST   /accounts/{account_id}/scan 🔒

FINDINGS
GET    /findings?severity=&source_type=&limit=   🔒

DASHBOARD
GET    /dashboard/summary          🔒
GET    /dashboard/recent           🔒
GET    /dashboard/trends           🔒

META
GET    /                           public
GET    /health                     public
GET    /docs                       Swagger UI
GET    /openapi.json               OpenAPI 3.1 schema

🔒 = requires Authorization: Bearer <jwt>
```

---

## CI/CD

The Trivy CWPP pipeline runs on every commit and pull request. It scans the ShieldScan backend Dockerfile, the entire filesystem for secrets and misconfigurations, and uploads SARIF findings to the Security tab. Builds fail on unfixed CRITICAL vulnerabilities.

A scheduled daily rescan runs against the latest image to catch newly disclosed CVEs in already-merged code.

---

## Testing & Validation with CNAPPgoat

### Overview

ShieldScan validates its detection capabilities against **CNAPPgoat**, an open-source project that provisions vulnerable-by-design cloud infrastructure in AWS. This allows the security team to benchmark ShieldScan's ability to identify real-world misconfigurations and vulnerabilities that attackers can exploit.

### What is CNAPPgoat?

CNAPPgoat is a modular, open-source framework designed to provision vulnerable CNAPP (Cloud-Native Application Protection Platform) scenarios across cloud providers (AWS, Azure, GCP). Unlike general cloud security testing tools like CloudGoat, CNAPPgoat includes atomic and integrated vulnerable scenarios that provide comprehensive coverage of cloud infrastructure configurations and risks.

### Supported Modules

CNAPPgoat provides three CNAPP modules; ShieldScan validates against the following two:

| Module | Coverage | ShieldScan Integration |
|---|---|---|
| **CSPM** | Misconfiguration of cloud infrastructure components (e.g., publicly exposed S3 buckets, overly permissive IAM policies, unencrypted databases) | ✅ Actively scanned by Prowler |
| **CWPP** | Exposure of workloads to vulnerabilities (e.g., running end-of-life OS versions, vulnerable software versions, insecure container configurations) | ✅ Actively scanned by Trivy |
| CIEM | Identity and entitlement management scenarios (privilege escalation, unintended role assumption) | ⬜ Not in current scope |

### Validation Workflow

```
1. Provision CNAPPgoat scenario in isolated AWS sandbox account
   │
   ├─ CSPM scenarios: misconfigured storage, networking, IAM
   └─ CWPP scenarios: vulnerable containers, outdated OS, exposed services
   │
2. Run ShieldScan (Prowler + Trivy) against CNAPPgoat environment
   │
   ├─ Prowler scans AWS infrastructure for CSPM findings
   └─ Trivy scans container images and IaC for CWPP findings
   │
3. Validate detection accuracy
   │
   ├─ Confirm ShieldScan identifies known vulnerabilities
   ├─ Measure false-positive and false-negative rates
   └─ Quantify CSPM and CWPP coverage
   │
4. Document findings in ShieldScan dashboard
   │
5. Destroy CNAPPgoat infrastructure to prevent drift
```

### Testing Environment Setup

- **Sandbox Account**: Completely isolated AWS account, separate from all production environments
- **Isolation**: No shared resources, network connectivity, or data with business infrastructure
- **Repeatability**: Each test scenario can be provisioned and destroyed on-demand via Infrastructure as Code
- **Automation**: CNAPPgoat Terraform modules provision vulnerabilities declaratively

### Key Metrics

| Metric | Purpose |
|---|---|
| **CSPM Coverage** | Percentage of known misconfigurations (Prowler rules) detected in CNAPPgoat scenarios |
| **CWPP Coverage** | Percentage of known vulnerabilities (Trivy) and insecure configs detected in container scenarios |
| **True Positive Rate** | ShieldScan alerts that correspond to actual vulnerabilities in CNAPPgoat |
| **False Positive Rate** | ShieldScan alerts with no corresponding vulnerability (target: < 1% noise) |
| **Detection Latency** | Time from CNAPPgoat provision to ShieldScan finding identification |

### Status & Roadmap

| Phase | Component | Status |
|---|---|---|
| Foundation | CNAPPgoat AWS account setup | ⬜ Planned |
| Foundation | CNAPPgoat CSPM module provisioning | ⬜ Planned |
| Foundation | CNAPPgoat CWPP module provisioning | ⬜ Planned |
| Phase 1 | Automated validation pipeline (trigger Prowler/Trivy on provision) | 🟡 Planned |
| Phase 2 | Coverage report dashboard (% of scenarios detected) | 🟡 Planned |
| Phase 3 | Continuous validation in CI/CD (run tests on every release) | ⬜ Planned |

### References

- **CNAPPgoat Repository**: [GitHub - CNAPPgoat](https://github.com/ermetic-research/cnappgoat)
- **Documentation**: CNAPPgoat modules, scenario descriptions, and destruction procedures
- **Best Practices**: All testing conducted in isolated, non-production AWS accounts only

---

## Roadmap

### Phase 1 — Foundation (current)

- [x] CI/CD pipeline with Trivy + SARIF
- [x] EC2 + DynamoDB + ECR provisioned
- [x] FastAPI backend with auth, scans, findings, accounts, dashboard
- [x] Cross-account IAM role flow
- [ ] Prowler operational on EC2
- [ ] React frontend MVP
- [ ] AI Fix Engine first integration
- [ ] CNAPPgoat sandbox account provisioning
- [ ] Initial CSPM + CWPP validation against CNAPPgoat

### Phase 2 — Hardening

- [ ] HTTPS with Let's Encrypt
- [ ] httpOnly cookie auth instead of localStorage JWT
- [ ] Async scan workers (FastAPI BackgroundTasks → SQS as we scale)
- [ ] Scan history pagination and filtering
- [ ] Daily summary email (SES)
- [ ] Automated CNAPPgoat validation pipeline in CI/CD

### Phase 3 — Intelligence (the differentiator)

- [ ] AI Fix Engine: RAG over vendor docs to generate exact code patches
- [ ] Severity triage engine using EPSS scores (not just CVSS)
- [ ] False-positive reduction layer (< 1% of scanner alerts are real threats)
- [ ] Cross-source correlation (Trivy + Prowler findings on the same resource)
- [ ] CNAPPgoat coverage dashboard (real-time detection metrics)

### Phase 4 — Scale

- [ ] Multi-account AWS organization support
- [ ] Compliance frameworks: CIS, NIST, PCI-DSS, GDPR, HIPAA, SOC2
- [ ] Webhooks for Slack, Teams, Jira
- [ ] OAuth (Google, GitHub) instead of email and password
- [ ] CWPP runtime monitoring (Falco integration)
- [ ] Continuous validation against CNAPPgoat threat library

---

## Team

| Role | Owner |
|---|---|
| CSPM and CWPP infrastructure, AWS deployment | Ilke Cabral | Subhan |
| Backend (FastAPI, auth, DynamoDB persistence) + AI Fix Engine | Kaushik | Ilke | Subhan | Umeruddin |
| React frontend | Kaushik | Umeruddin |
| CNAPP GOAT Implementation | Umeruddin | Kaushik |
| Academic supervision | EPITA M1 Cybersecurity |

---

## Acknowledgements

ShieldScan builds on three open-source projects:

- **Trivy** by Aqua Security — container, IaC, and secret vulnerability scanner
- **Prowler** — AWS, Azure, GCP security posture scanner
- **CNAPPgoat** by Ermetic Research — vulnerable-by-design cloud infrastructure provisioning for CNAPP validation

The research foundation comes from papers on cloud-native security, IAM anomaly detection, CSPM effectiveness studies, and CNAPP threat modeling.

---

ShieldScan — Cloud security developers can actually afford, and actually use.
