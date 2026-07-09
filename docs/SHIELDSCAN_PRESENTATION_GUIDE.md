# ShieldScan — Complete Presentation Guide
**For: EPITA MSc Computer Security | Action Learning Project**
**Hackathon: June 18, 2026**

---

## What Is ShieldScan?

ShieldScan is a lightweight **CNAPP** (Cloud-Native Application Protection Platform). A CNAPP is a unified security tool that protects both your cloud infrastructure settings (CSPM) and your running workloads like containers (CWPP). Think of it like a combination of:

- A security auditor that checks your AWS account for dangerous misconfigurations
- A virus scanner for your container images (finds software vulnerabilities called CVEs)
- An AI assistant that explains what's wrong and how to fix it

The target users are students and early-stage startups who cannot afford enterprise tools like Wiz ($50K+/year) or Prisma Cloud. ShieldScan uses AWS free tier infrastructure and open-source tools, so it can be offered free.

---

## The Stack — What Each Technology Is and Why We Chose It

### Backend: FastAPI (Python)

**What it is:** A modern Python web framework for building APIs.

**Why FastAPI specifically:**
- It is **async-native** — meaning while one long AWS scan is running, the server can still respond to other requests (like "how far along is the scan?"). This is critical for ShieldScan's live progress bar.
- It generates automatic API documentation at `/docs` — go to `http://localhost:8000/docs` in a browser and you see every endpoint with the ability to test them live. Show this to your professor.
- It uses **Pydantic** models for input validation, so if someone sends bad data to an API endpoint, it rejects it automatically with a clear error message.
- It is the most popular Python API framework in 2024/2025, widely used in production at Microsoft, Uber, Netflix.

**Why Python overall:**
- boto3 (the AWS SDK) is Python-native — the best library support for AWS is in Python.
- All the ML/AI libraries (XGBoost, ChromaDB, scikit-learn) are Python.
- The team's primary language.

### Database: SQLite + SQLAlchemy

**What SQLite is:** A file-based SQL database. The entire database is a single file called `shieldscan.db` stored on disk. No separate database server needed.

**Why SQLite:**
- Zero infrastructure cost — fits the free-tier constraint the professor approved.
- Perfect for the current stage (single server, small number of users).
- Can be swapped for PostgreSQL later by changing one line in `.env` — the code is written to be database-agnostic (SQLAlchemy handles this).

**What SQLAlchemy is:** An ORM (Object Relational Mapper). Instead of writing raw SQL like `SELECT * FROM findings WHERE severity = 'HIGH'`, you write Python objects and SQLAlchemy writes the SQL for you. This prevents SQL injection attacks by default.

**Where the database file is:** `app/backend/shieldscan.db` — this is the actual file. See "How to View the Data" section below.

**Three tables:** `users`, `scans`, `findings` (plus `passkey_credentials`).

### Authentication: JWT + bcrypt + Fernet

**JWT (JSON Web Tokens):**
- When a user logs in, the server creates a signed token containing their user ID and email.
- Every subsequent request sends this token in the `Authorization: Bearer <token>` header.
- The server can verify the token's authenticity without touching the database — it just checks the cryptographic signature.
- Why: stateless authentication — the server doesn't need to store sessions, which scales better and is simpler.
- The token expires (configurable in `.env`, default 60 minutes). After expiry the user must log in again.

**bcrypt:**
- Used to hash passwords before storing them in the database.
- bcrypt is intentionally slow (takes ~100ms per verification) — this makes brute-force attacks computationally infeasible.
- The database stores only the hash, never the real password. Even if someone steals the database, they cannot recover passwords.
- Industry standard for password storage since 1999, still recommended in 2025.

**Fernet symmetric encryption:**
- Used specifically for AWS credentials (access key + secret key).
- Unlike passwords, AWS credentials need to be decrypted later (to make actual AWS API calls). So they cannot be hashed — they must be reversibly encrypted.
- Fernet uses AES-128-CBC with HMAC-SHA256 for authenticity. The encryption key comes from `AWS_ENCRYPTION_KEY` in `.env`.
- If someone steals the database but not the `.env` file, the AWS credentials are useless.

### AWS Scanning: boto3

**What boto3 is:** The official AWS SDK for Python. It lets you call any AWS API using Python code.

**Why boto3 directly instead of using AWS Security Hub:**
- AWS Security Hub costs money and requires AWS Config enabled (also costs money).
- Writing checks directly with boto3 gives us full control and zero dependency on paid AWS services.
- It runs anywhere — no agent installation needed on the scanned account.

**How it works:** The user provides their AWS access key ID and secret access key. ShieldScan uses those credentials to call AWS APIs like `iam.list_users()`, `ec2.describe_security_groups()`, `s3.list_buckets()` etc. and interprets the results.

**What permissions are needed:** The IAM user used for scanning needs `SecurityAudit` managed policy — a read-only policy that allows describing resources but never modifying them.

### Container Scanning: Trivy (Aqua Security)

**What Trivy is:** An open-source vulnerability scanner for container images. It is the most widely used container scanning tool, used by GitHub, GitLab, and Docker Hub internally.

**Why Trivy:**
- Free and open-source (Apache 2 license).
- Scans faster than any alternative (Clair, Anchore) — under 60 seconds for most images.
- Detects CVEs across OS packages (Alpine, Debian, Ubuntu) AND application dependencies (pip, npm, Maven, Go modules).
- Zero agent needed — run `trivy image nginx:latest` and get results immediately.
- The CWPP module is currently using mock data (realistic CVE data). The real Trivy integration code is written as comments in `cwpp_service.py` — ready for a teammate to enable.

### AI Assistant: RAG + LLM (Ollama / Groq / Claude)

**What RAG is (Retrieval Augmented Generation):**
- Instead of training a custom AI model on security data (requires GPUs, weeks of training, $10K+ cost), we use an existing LLM and inject relevant security knowledge into each conversation.
- When a user asks a question, the system first searches a knowledge base for relevant security information, then gives that information to the LLM along with the user's scan findings, then the LLM answers.
- This is how most production AI systems work — it's cheaper, faster, and the knowledge can be updated without retraining.

**ChromaDB — the vector database:**
- ChromaDB stores 55 security knowledge documents (CIS AWS Benchmark controls, NIST 800-53, OWASP Top 10, container security guides).
- Each document is stored as a vector embedding — a 384-dimensional numerical representation of the text's meaning.
- When a user asks a question, the question is also converted to a vector, and ChromaDB finds the documents with the most similar meaning (cosine similarity search).
- This is stored in `app/backend/chroma_db/` — a persistent folder that survives restarts.

**Why we chose RAG over fine-tuning:**
- Fine-tuning requires: labeled training data, GPU compute, weeks of training, risk of catastrophic forgetting.
- RAG requires: a knowledge base (text documents), a vector database (ChromaDB), and any LLM API.
- RAG is also more transparent — you can see exactly what knowledge is being used in each response.
- Industry consensus in 2024/2025 is that RAG outperforms fine-tuning for domain-specific factual Q&A tasks.

**Three LLM providers (switchable via `.env`):**
- **Ollama** (default): runs a local LLM on your laptop. Zero API cost. Needs `ollama serve` running.
- **Groq**: cloud API, free tier (14,400 requests/day), uses LLaMA 3.3 70B model, very fast.
- **Claude API** (Anthropic): paid but highest quality. Uses Claude Haiku for speed and cost.
- Switch by changing `AI_PROVIDER=groq` in `.env` — no code changes needed.

**Scope restriction:** The AI is hard-coded with a system prompt that refuses to answer anything outside cloud security. If someone asks "write me a poem," it responds with a fixed refusal message. This is important for a security tool.

### Risk Scoring: XGBoost (currently weighted formula)

**What XGBoost is:** A machine learning model — specifically a gradient boosted decision tree. It is one of the most widely used ML algorithms for structured/tabular data, used in finance, healthcare, and security.

**Current state:** The XGBoost model is not yet trained. A weighted formula is used instead:
- CRITICAL finding = +40 points
- HIGH finding = +20 points
- MEDIUM finding = +8 points
- LOW finding = +2 points
- Total capped at 100.

**Why XGBoost for the final version:**
- A simple weighted formula doesn't account for context — a CRITICAL finding in a dev account is less urgent than the same finding in production.
- XGBoost can learn from features like: number of internet-facing resources, account age, finding combinations, CVSS scores, industry benchmarks.
- The model would be trained on public AWS security benchmark datasets and historical breach data.

### Security Features (Platform Security)

**These are the security measures applied to ShieldScan itself — not just what it checks in AWS.**

- **Rate limiting (slowapi):** Limits how many requests a single IP can make per minute. Prevents brute-force password attacks against the login endpoint.
- **Brute-force lockout:** After 5 failed login attempts, the account is locked for 15 minutes. Stored in the `failed_login_attempts` and `locked_until` columns in the database.
- **TOTP 2FA:** Time-based One-Time Password (like Google Authenticator). Users can enable this for their ShieldScan account. The server stores only the TOTP secret — the 6-digit code is generated on the user's phone.
- **Passkeys / WebAuthn:** Modern passwordless authentication using device biometrics (Face ID, fingerprint). The server stores only the public key fingerprint — never the private key. This is how Google, Apple, and Microsoft now recommend authentication.
- **Email verification:** When a user registers, they receive a 6-digit OTP code to verify their email. Without verification, some features are restricted.
- **Password reset:** Secure token-based reset flow. The token is a 32-byte random hex string stored as SHA-256 hash in the database — even if someone reads the database, they cannot use it.
- **Security headers:** Every HTTP response includes: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`. These protect against common web attacks (clickjacking, MIME sniffing, XSS).
- **CORS:** Currently allows all origins (`*`) for development. Would be restricted to specific domains in production.

### Frontend: React (CDN, no build step)

**Why no build step:**
- The frontend is a single HTML file (`index.html`) that loads React from a CDN using Babel in-browser transpilation.
- No npm, no webpack, no Node.js needed — just a browser and a web server.
- This was a deliberate choice for the project phase: any teammate can open the file, make changes, and see results instantly.
- The downside is it is slower to load than a compiled React app — acceptable for a student project, would be changed for production.

---

## The Full Scan Pipeline — What Happens When You Click "Run Scan"

1. **Frontend** sends `POST /api/scan/run` with the JWT token in the header.

2. **`routers/scans.py`** receives the request, verifies the JWT, identifies the user, and calls `run_full_scan()`.

3. **`scan_manager.py`** is the orchestrator:
   - Creates a `Scan` record in SQLite with `status = RUNNING`.
   - Sets initial progress: "Connecting to AWS account…, 5%"
   - If AWS credentials exist: runs 13 CSPM checks sequentially using `asyncio.to_thread()` (each boto3 call runs in a thread pool, keeping the event loop free).
   - If no AWS credentials: uses `MOCK_FINDINGS` (3 demo findings) with 0.4-second delays between steps to simulate a real scan.

4. **Progress polling** (frontend polls `GET /api/scan/progress` every 2 seconds during the scan):
   - The progress endpoint reads from an in-memory dictionary `_scan_progress[user_id]`.
   - It does NOT touch the database — this is why it stays fast even during the scan.
   - Returns: `{"step": "Checking EBS volume encryption…", "pct": 57, "done": false}`.

5. **CSPM checks** (13 checks via `cspm_service.py`):
   Each check calls AWS APIs, interprets the results, and returns a list of finding dictionaries.

6. **CWPP scan** (`cwpp_service.py`):
   Currently returns 2 mock CVE findings. When enabled, would run `trivy image <image_name>` as a subprocess and parse the JSON output.

7. **Risk scoring** (`risk_scorer.py`):
   Adds up severity weights across all findings, caps at 100.

8. **Database save**:
   Creates one `Finding` row per finding, updates the `Scan` row with `status = COMPLETED`, risk score, and severity counts.

9. **Frontend receives the completed scan**, loads findings from `GET /api/scan/findings`, and displays them in the CSPM and CWPP tabs.

---

## How to View the Data (What's Actually in the Database)

The database is a SQLite file at `app/backend/shieldscan.db`.

### Method 1: SQLite command line (recommended for demo)
```bash
# Navigate to the backend folder
cd "app/backend"

# Open the database
sqlite3 shieldscan.db

# View all tables
.tables

# See all users (DO NOT share screens showing real emails/passwords)
SELECT id, email, aws_connected, aws_region, created_at FROM users;

# See all scans
SELECT id, user_id, status, risk_score, critical_count, high_count, started_at FROM scans;

# See all findings from the latest scan
SELECT finding_id, severity, title, resource FROM findings WHERE scan_id = (SELECT MAX(id) FROM scans);

# See findings by severity
SELECT severity, COUNT(*) as count FROM findings GROUP BY severity;

# Exit
.quit
```

### Method 2: DB Browser for SQLite (visual tool)
- Download free from: https://sqlitebrowser.org
- Open `app/backend/shieldscan.db`
- Browse Tables tab — see all rows visually
- Execute SQL tab — run queries

### Method 3: FastAPI's automatic documentation
- With the backend running, open: `http://localhost:8000/docs`
- This shows every API endpoint with a "Try it out" button
- You can log in, get a JWT token, and test every endpoint directly from the browser

### What each table stores:

**users table:**
- `id` — auto-increment integer primary key
- `email` — unique, indexed
- `hashed_password` — bcrypt hash (60 characters starting with `$2b$`)
- `aws_access_key_enc` — Fernet-encrypted AWS access key (looks like `gAAAAAB...`)
- `aws_secret_key_enc` — Fernet-encrypted AWS secret key
- `aws_connected` — boolean: True if AWS credentials are set and verified
- `totp_enabled` — boolean: True if 2FA is enabled
- `failed_login_attempts` — integer, resets to 0 on successful login

**scans table:**
- `id` — scan number (auto-increment)
- `user_id` — foreign key to users table
- `status` — PENDING / RUNNING / COMPLETED / FAILED
- `risk_score` — float 0.0 to 100.0
- `critical_count`, `high_count`, `medium_count`, `low_count` — denormalized counts for fast dashboard loads
- `started_at`, `completed_at` — datetime stamps

**findings table:**
- `finding_id` — string like "CSPM-S3-PUBLIC-my-bucket" or "CVE-2021-23017"
- `finding_type` — "CSPM" or "CWPP"
- `severity` — "CRITICAL", "HIGH", "MEDIUM", or "LOW"
- `title`, `description`, `fix_recommendation` — text fields
- `resource` — the AWS resource affected (bucket name, security group ID, etc.)
- `is_resolved` — boolean, default False
- `cve_id`, `cvss_score`, `affected_package`, `fixed_version` — CWPP-specific fields, NULL for CSPM findings

---

## How to Read the Backend (Debugging and Monitoring)

### See live backend logs
When you run the server with `uvicorn backend.main:app --reload --port 8000`, every request is printed to the terminal:
```
INFO:     127.0.0.1:52341 - "POST /api/scan/run HTTP/1.1" 202 Accepted
INFO:     CSPM complete: 8 findings across 13 checks
INFO:     Scan #3 complete: score=76.0, total=10 (C=0 H=3 M=4 L=3)
```

Python's `logging` module is used throughout — `logger.info()`, `logger.warning()`, `logger.exception()`. These all print to the terminal during development.

### Trace a specific scan
Every CSPM check logs when it starts. If a check fails (e.g., insufficient IAM permissions), you see a WARNING in the terminal:
```
WARNING: IAM root check failed: An error occurred (AccessDenied)...
WARNING: KMS rotation check failed: ...
```
The check catches the exception, logs it, and returns an empty list — so one failing check does not crash the entire scan.

### Check what the AI is doing
The AI system prompt includes all scan findings and RAG context. To see exactly what is being sent to the LLM, add a `print(system_prompt)` to `ai_service.py` temporarily.

### API testing with curl
```bash
# Health check
curl http://localhost:8000/health

# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","password":"yourpassword"}'
# Returns: {"access_token": "eyJ...", "token_type": "bearer"}

# Get findings (replace TOKEN with the access_token from above)
curl http://localhost:8000/api/scan/findings \
  -H "Authorization: Bearer TOKEN"
```

---

## The 13 CSPM Checks — What Is Checked and Why

| # | Check | AWS API Used | CIS Control | Severity |
|---|-------|-------------|-------------|----------|
| 1 | S3 public access block | `get_public_access_block` | CIS 2.1.5 | HIGH |
| 2 | IAM root active access keys | `get_credential_report` | CIS 1.4 | CRITICAL |
| 3 | IAM root MFA | `get_credential_report` | CIS 1.5 | CRITICAL |
| 4 | IAM users MFA (console + programmatic) | `get_login_profile`, `list_access_keys`, `list_mfa_devices` | CIS 1.10 | HIGH/MEDIUM |
| 5 | IAM admin policy on users | `list_attached_user_policies` | Principle of Least Privilege | HIGH |
| 6 | EC2 open ports (SSH, RDP, databases) | `describe_security_groups` | CIS 5.2, 5.3 | HIGH/MEDIUM |
| 7 | CloudTrail enabled and logging | `describe_trails`, `get_trail_status` | CIS 3.1 | MEDIUM |
| 8 | IAM password policy strength | `get_account_password_policy` | CIS 1.8-1.11 | LOW/MEDIUM |
| 9 | EBS volume encryption | `describe_volumes` | CIS 2.2.1 | MEDIUM |
| 10 | RDS instance encryption | `describe_db_instances` | CIS RDS | HIGH |
| 11 | VPC flow logs enabled | `describe_vpcs`, `describe_flow_logs` | CIS 3.9 | MEDIUM |
| 12 | S3 server access logging | `get_bucket_logging` | CIS 2.1.2 | LOW |
| 13 | KMS key rotation | `list_keys`, `describe_key`, `get_key_rotation_status` | CIS 3.8 | LOW |
| + | GuardDuty status + active findings | `list_detectors`, `list_findings`, `get_findings` | AWS Best Practice | MEDIUM+ |

**CIS = Center for Internet Security AWS Foundations Benchmark v3.0** — the industry standard baseline for AWS security. Used by auditors, compliance teams, and CSPM tools worldwide.

---

## Professor Questions and How to Answer Them

### Q: What is a CNAPP and why did you build one?

CNAPP stands for Cloud-Native Application Protection Platform. It is a category of security tool that combines CSPM (checking cloud configuration) and CWPP (checking running workloads like containers) into a single platform. Gartner coined the term in 2021. We built ShieldScan because existing CNAPPs cost $30K-100K per year — completely inaccessible to students and early-stage startups. We use boto3 (free), Trivy (open-source), and SQLite (free) to cover the same core capabilities at zero infrastructure cost.

### Q: How does the authentication work? Walk me through login.

When a user submits their email and password, the server looks up the user in the `users` table by email. It then calls `bcrypt.checkpw()` which re-hashes the submitted password with the same salt that was used when the hash was created, and compares. If they match, the server creates a JWT (JSON Web Token) — a base64-encoded JSON object signed with HMAC-SHA256 using our secret key. This token contains the user's ID and expiry time. The frontend stores this token in memory (not localStorage, to avoid XSS attacks) and sends it in every subsequent request as `Authorization: Bearer <token>`. The server verifies the signature on every request — if valid, it extracts the user ID and looks up the user. No database session table needed.

### Q: Why did you use JWT instead of sessions?

Sessions require server-side storage — a session table in the database or a Redis cache. JWT is stateless: the token itself contains the user's identity, and the server just verifies the cryptographic signature. This means the server can scale horizontally (multiple instances) without sharing session state. The tradeoff is you cannot instantly invalidate a JWT before it expires — we mitigate this with short expiry times (60 minutes).

### Q: How are AWS credentials stored? What if someone hacks your database?

AWS credentials (access key + secret key) are encrypted with Fernet before being stored. Fernet uses AES-128-CBC for encryption and HMAC-SHA256 to ensure the ciphertext hasn't been tampered with. The encryption key is stored in the `.env` file on the server — never in the database. So an attacker who steals only the database file gets encrypted blobs that are useless without the `.env` key. An attacker who gets both the database AND the `.env` would have the credentials — which is why the `.env` file should have strict file permissions (chmod 600) and never be committed to git.

### Q: What is RAG and why did you use it instead of fine-tuning the AI?

RAG is Retrieval Augmented Generation. We have a knowledge base of 55 security documents (CIS controls, NIST 800-53, OWASP, container security guides) stored in ChromaDB — a vector database. When a user asks a question, ChromaDB converts the question to a vector embedding and finds the 3 most relevant documents using cosine similarity. Those documents are injected into the LLM's system prompt along with the user's actual scan findings. The LLM then answers based on this specific, relevant context. We chose this over fine-tuning because fine-tuning requires a GPU, labeled training data, and weeks of work. RAG can be set up in hours, the knowledge base is easily updated without retraining, and it is less prone to hallucination because answers are grounded in retrieved documents.

### Q: What is a vector database?

A vector database stores documents as numerical vectors (arrays of floating-point numbers) called embeddings. An embedding captures the semantic meaning of text — similar texts have similar vectors. ChromaDB uses a neural embedding model (sentence-transformers) to convert each document to a 384-dimensional vector. When querying, the question is embedded the same way, and the database finds documents with the smallest angle (cosine distance) to the question vector. This allows semantic search — "how do I secure my S3 bucket" will find documents about "Block Public Access" and "bucket policies" even if those exact words aren't in the query.

### Q: Walk me through what happens when a scan is triggered.

[Use the "Full Scan Pipeline" section above — explain each step.]

### Q: How does the progress bar work during a scan?

When the scan starts, `scan_manager.py` stores progress in an in-memory Python dictionary `_scan_progress[user_id]` — not in the database. The key is the user's ID, the value is `{"step": "...", "pct": 57, "done": false}`. While the scan runs, the frontend polls `GET /api/scan/progress` every 2 seconds. That endpoint reads from the in-memory dictionary and returns the current state. This is very fast because there is no database query. We chose in-memory storage here because progress is transient — it only matters during the scan. If the server restarts mid-scan, the progress resets, which is acceptable. The key technical enabler is `asyncio.to_thread()` — each boto3 call runs in a thread pool, so the event loop (which serves HTTP requests) is never blocked waiting for AWS API responses.

### Q: Why use asyncio.to_thread instead of just running everything synchronously?

boto3 is a synchronous library — each API call blocks until AWS responds (can take 1-5 seconds per call). FastAPI is async — its event loop is a single thread that handles many requests by switching between them when they are waiting for I/O. If we called boto3 directly in an async route handler, we would block the entire event loop while waiting for AWS, meaning no other HTTP requests can be served during the scan — including the progress polling requests. `asyncio.to_thread()` runs the blocking boto3 call in a separate thread from the thread pool, so the event loop stays free to handle progress poll requests.

### Q: What is the CIS AWS Benchmark?

CIS stands for Center for Internet Security. The CIS AWS Foundations Benchmark is a set of prescriptive security recommendations for AWS, written by security experts and reviewed by AWS. It has two levels: Level 1 (basic, no cost) and Level 2 (advanced). Our 13 CSPM checks cover most of CIS Level 1. This benchmark is used as the baseline by SOC 2 auditors, compliance teams, and enterprise CSPM tools (including AWS Security Hub). Mapping our checks to CIS controls gives our findings credibility — it shows we are not just guessing what to check, but following an industry-accepted standard.

### Q: What is the difference between CSPM and CWPP?

CSPM (Cloud Security Posture Management) looks at the **configuration** of your cloud infrastructure — IAM settings, security group rules, encryption settings, logging configuration. These are static properties that don't require a running workload. CWPP (Cloud Workload Protection Platform) looks at the **software** running in your cloud — container images, packages, dependencies, and their known vulnerabilities (CVEs). CSPM asks "is your house locked?" CWPP asks "are the locks themselves defective?"

### Q: What is a CVE?

CVE stands for Common Vulnerabilities and Exposures. It is a publicly disclosed security vulnerability in software, tracked in the National Vulnerability Database (NVD). Each CVE has a unique ID like "CVE-2021-44228" (this is Log4Shell — one of the most famous CVEs ever). Each CVE also has a CVSS score (Common Vulnerability Scoring System) from 0.0 to 10.0 indicating severity. Trivy checks every package in a container image against the CVE database and reports which packages have known vulnerabilities and whether a patched version is available.

### Q: How does Trivy work?

Trivy pulls the container image, extracts its filesystem layers, identifies every installed OS package (e.g., Alpine's apk packages, Debian apt packages) and application dependency (pip packages in requirements.txt, npm packages in package.json), and cross-references each with a local copy of the vulnerability database. It returns a JSON report listing each CVE, affected package, installed version, fixed version, severity, and description. ShieldScan's `cwpp_service.py` would parse this JSON and convert each CVE into a finding that matches the same format as CSPM findings, so both types appear in the same dashboard.

### Q: What is the risk score and how is it calculated?

The risk score is a number from 0 to 100 representing the overall security posture of the scanned account. Currently it uses a weighted formula: CRITICAL finding = 40 points, HIGH = 20 points, MEDIUM = 8 points, LOW = 2 points, total capped at 100. So if you have 1 CRITICAL finding (root account has access keys) and 2 HIGH findings (open SSH, no MFA), your score is 40 + 20 + 20 = 80 — classified as "Poor." The formula is in `risk_scorer.py`. The XGBoost ML model is the planned next step — it would take more features as input (account age, number of internet-facing resources, finding combinations) and produce a more nuanced score based on patterns in historical breach data.

### Q: What security measures does ShieldScan itself have? (i.e., how do you protect the platform)

Six layers: (1) bcrypt password hashing — cannot recover passwords from the database. (2) JWT expiry — tokens expire in 60 minutes. (3) Rate limiting — the login endpoint allows maximum 5 requests per minute per IP. (4) Account lockout — 5 failed attempts locks for 15 minutes. (5) TOTP two-factor authentication — optional but available. (6) Passkeys/WebAuthn — passwordless biometric authentication. (7) Fernet encryption of AWS credentials — encrypted at rest with a key that is never in the database. (8) HTTP security headers — protects against clickjacking, MIME sniffing, and XSS.

### Q: Why SQLite and not PostgreSQL?

The professor's constraints specified AWS free tier. SQLite requires zero infrastructure — no RDS instance, no EC2 instance for a database server. It is entirely file-based. For the current scale (a team of 4, demo purposes, tens of users), SQLite is more than adequate. The code is written with SQLAlchemy, which is database-agnostic — switching to PostgreSQL requires only changing `DATABASE_URL` in `.env` from `sqlite:///./shieldscan.db` to `postgresql://user:pass@host/db`. No code changes needed.

### Q: What is your infrastructure and how is it hosted?

Oracle Cloud Always Free tier — Oracle gives two AMD Compute VMs (1 OCPU, 1GB RAM each) permanently free, plus a free load balancer and 20GB block storage. This is more generous than AWS free tier for always-on servers (AWS free EC2 is only 12 months). The backend runs on one VM with uvicorn. The frontend is served as a static HTML file. SQLite database is stored on the block storage volume.

### Q: What would you need to add to make this production-ready?

Honest answer: (1) Multi-region CloudTrail check (current check only scans the configured region). (2) IAM admin via Groups — currently only checks direct policy attachments. (3) Real-time scanning with CloudWatch Events triggers (currently scan-on-demand only). (4) The XGBoost risk model with real training data. (5) Real Trivy integration (currently mock). (6) HTTPS with a real TLS certificate. (7) Replace SQLite with PostgreSQL for concurrent write support. (8) Email service for real email delivery (currently mocked). These are known gaps we deprioritized for the demo.

### Q: What compliance frameworks does ShieldScan cover?

Our 13 CSPM checks map to:
- **CIS AWS Foundations Benchmark v3.0 Level 1** — most controls covered (the standard baseline)
- **OWASP Top 10 2025** — A01 (Broken Access Control → S3/IAM), A02 (Cryptographic Failures → encryption checks), A05 (Security Misconfiguration → most checks), A07 (Auth Failures → MFA checks)
- **NIST SP 800-53 Rev 5** — AC-2 (account management), IA-2 (MFA), AU-2 (event logging via CloudTrail), SC-28 (data at rest encryption)

The compliance tab in the dashboard is currently aspirational — it shows the frameworks but does not yet automatically map findings to specific controls. That is a planned feature.

### Q: You're using a real AWS account for scanning — what if the scan breaks something?

It cannot. The IAM user used for scanning has only the `SecurityAudit` managed policy, which is read-only. Every API call ShieldScan makes is a describe/list/get operation — none modify any resource. `SecurityAudit` explicitly denies all write/delete/modify API calls. This is the standard principle for security scanners: read everything, touch nothing.

---

## Quick Reference — File Map

```
app/
├── backend/
│   ├── main.py              ← FastAPI app, middleware, routes registration
│   ├── database.py          ← SQLite engine, migrations, session factory
│   ├── models.py            ← User, Scan, Finding, PasskeyCredential tables
│   ├── auth.py              ← JWT, bcrypt, Fernet — all auth logic
│   ├── scan_manager.py      ← Scan orchestrator — runs all checks in sequence
│   ├── ai_service.py        ← LLM abstraction (Ollama/Groq/Claude)
│   ├── rag_module.py        ← ChromaDB vector database, 55-doc knowledge base
│   ├── shieldscan.db        ← THE ACTUAL DATABASE FILE (SQLite)
│   ├── chroma_db/           ← ChromaDB persistent storage (vector database)
│   ├── routers/
│   │   ├── auth.py          ← /api/auth/* endpoints (login, register, me)
│   │   ├── scans.py         ← /api/scan/* endpoints (run, findings, history, progress)
│   │   ├── ai.py            ← /api/ai/chat endpoint
│   │   ├── totp.py          ← /api/totp/* (2FA setup and verification)
│   │   ├── passkey.py       ← /api/passkey/* (WebAuthn)
│   │   └── reset.py         ← /api/auth/reset/* (password reset)
│   └── services/
│       ├── cspm_service.py  ← All 13 AWS boto3 checks + MOCK_FINDINGS
│       ├── cwpp_service.py  ← Trivy container scanner (mock mode currently)
│       └── risk_scorer.py   ← Weighted score (XGBoost placeholder)
└── frontend/
    ├── index.html           ← Entire React frontend (single HTML file)
    └── landing.html         ← Public marketing landing page
```

---

## How to Start the Project for Demo

```bash
# 1. Navigate to the project
cd "app/backend"

# 2. Install dependencies (first time only)
pip install -r requirements.txt

# 3. Start the backend
uvicorn backend.main:app --reload --port 8000

# 4. Open the frontend
open app/frontend/index.html   # macOS
# OR double-click index.html in Finder

# 5. API docs (useful to show professor)
# Open in browser: http://localhost:8000/docs
```

The `.env` file must exist in `app/backend/` with at minimum:
```
JWT_SECRET_KEY=any-long-random-string
AWS_ENCRYPTION_KEY=<44-char-base64-Fernet-key>
```
Generate a Fernet key with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
