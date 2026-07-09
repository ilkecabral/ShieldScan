"""
ShieldScan RAG Module
=====================
Retrieves relevant cloud security knowledge to inject into Claude's context per query.

Architecture:
  User question → embed → cosine similarity search in ChromaDB → top-k chunks
  → injected into system prompt → Claude answers with grounded knowledge

Knowledge base: CIS AWS Benchmark controls, AWS security best practices, CVE guides.
Add more docs at runtime with: rag.ingest_document(content, doc_id, metadata)

Install: pip install chromadb
ChromaDB uses all-MiniLM-L6-v2 embeddings locally by default (no API key needed).
"""

import chromadb
from chromadb.utils import embedding_functions

# ── ChromaDB setup ───────────────────────────────────────────────────────────
# Use Client() for in-memory (demo) or PersistentClient("./chroma_db") for prod
_client = chromadb.Client()
_ef = embedding_functions.DefaultEmbeddingFunction()  # local all-MiniLM-L6-v2
_collection = _client.get_or_create_collection(
    name="shieldscan_kb",
    embedding_function=_ef,
    metadata={"hnsw:space": "cosine"},
)

# ── Seed knowledge base ──────────────────────────────────────────────────────
# These documents ground Claude's answers in real AWS/security knowledge.
# In production: load from AWS docs, CIS Benchmark PDFs, NVD CVE feeds.

_SEED_DOCS = [
    {
        "id": "cis-s3-public-access",
        "content": """CIS AWS Benchmark 2.1.1 — S3 Block Public Access
S3 buckets must have Block Public Access enabled at both bucket and account level.
Without this, any IAM misconfiguration or ACL mistake can expose data publicly.
Remediation steps:
1. S3 console → bucket → Permissions tab → Block public access → Edit → enable all 4 checkboxes
2. Also enable at account level: S3 → Block Public Access (for this account)
3. CLI verify: aws s3api get-public-access-block --bucket <bucket-name>
4. For existing public objects: aws s3api put-object-acl --bucket <name> --key <key> --acl private
Risk: Data exfiltration, GDPR/PCI-DSS compliance breach, reputational damage.""",
        "metadata": {"service": "S3", "control": "CIS AWS 2.1.1", "severity": "CRITICAL"},
    },
    {
        "id": "cis-iam-root-key",
        "content": """CIS AWS Benchmark 1.4 — No Root Account Access Keys
Root has unrestricted access to every AWS resource. Active root access keys are a critical risk.
If leaked (e.g. pushed to GitHub), an attacker owns your entire AWS account.
Remediation steps:
1. Log in as root → IAM → Security credentials
2. Under Access keys → Delete every key listed
3. Create an IAM admin user: aws iam create-user --user-name admin
4. Attach policy: aws iam attach-user-policy --user-name admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
5. Enable MFA on root immediately
6. Verify: aws iam get-account-summary | grep AccountAccessKeysPresent → should be 0
Real risk: Complete account takeover, all resources deleted or ransomed.""",
        "metadata": {"service": "IAM", "control": "CIS AWS 1.4", "severity": "CRITICAL"},
    },
    {
        "id": "cis-sg-ssh",
        "content": """CIS AWS Benchmark 5.2 — Restrict SSH (port 22) to Known IPs
Security groups allowing 0.0.0.0/0 on port 22 expose instances to the entire internet.
Automated scanners find open SSH within minutes of an instance being launched.
Remediation steps:
1. EC2 → Security Groups → identify sg-0a1b2c3d4e (web-prod)
2. Inbound rules → Edit → remove the rule with source 0.0.0.0/0 port 22
3. Add a new rule: SSH, port 22, source = your office CIDR or VPN IP
4. Better alternative: remove SSH entirely and use AWS Systems Manager Session Manager
   - No open ports needed, full audit trail, works through NAT
   - aws ssm start-session --target i-0a1b2c3d4e5f
Risk: Brute-force, credential stuffing, exploitation of unpatched SSH.""",
        "metadata": {"service": "EC2", "control": "CIS AWS 5.2", "severity": "HIGH"},
    },
    {
        "id": "cis-cloudtrail",
        "content": """CIS AWS Benchmark 3.1 — Enable CloudTrail in All Regions
CloudTrail logs every AWS API call. Without it you have zero forensic capability after a breach.
An attacker who compromises your account will delete logs first — CloudTrail with S3 log validation detects this.
Remediation steps:
1. CloudTrail console → Create trail → name: shieldscan-trail
2. Enable Apply trail to all regions
3. S3 bucket: create dedicated bucket with restricted policy
4. Enable log file validation (cryptographic hash of each log file)
5. Enable CloudWatch Logs integration for real-time alerting
6. CLI: aws cloudtrail create-trail --name shieldscan-trail --s3-bucket-name <bucket> --is-multi-region-trail --enable-log-file-validation
Risk: No incident response capability, compliance failure (SOC2, ISO27001).""",
        "metadata": {"service": "CloudTrail", "control": "CIS AWS 3.1", "severity": "HIGH"},
    },
    {
        "id": "cis-rds-public",
        "content": """CIS AWS Benchmark 2.3.2 — RDS Must Not Be Publicly Accessible
Database servers should only be reachable from within the VPC, never from the public internet.
Public RDS instances are directly attackable: SQL injection, brute-force, known CVEs.
Remediation steps:
1. RDS console → rds-prod-mysql-01 → Modify
2. Connectivity → Publicly accessible → No
3. Move to private subnet: ensure no route to internet gateway from subnet
4. For admin access: use a bastion host in a public subnet, or SSM port forwarding
5. CLI: aws rds modify-db-instance --db-instance-identifier rds-prod-mysql-01 --no-publicly-accessible --apply-immediately
Risk: Direct database exploitation, data exfiltration, ransomware.""",
        "metadata": {"service": "RDS", "control": "CIS AWS 2.3.2", "severity": "HIGH"},
    },
    {
        "id": "imdsv2",
        "content": """IMDSv2 Migration — Prevent SSRF-based Credential Theft
IMDSv1 allows any HTTP request to http://169.254.169.254/latest/meta-data/ to retrieve IAM credentials.
SSRF vulnerabilities in web apps (common in Spring, Flask, etc.) can steal these credentials remotely.
IMDSv2 requires a PUT request with a session token first — SSRF attacks cannot do PUT requests.
Remediation for i-0a1b2c3d4e5f (webapp-01):
1. aws ec2 modify-instance-metadata-options --instance-id i-0a1b2c3d4e5f --http-tokens required --http-endpoint enabled
2. Or: EC2 → Instance → Actions → Instance settings → Modify instance metadata options → set HttpTokens=required
3. Test: curl -s http://169.254.169.254/latest/meta-data/ should return 401 Unauthorized
4. Update your app code if it reads instance metadata — needs to request token first
Historical impact: Capital One 2019 breach used SSRF + IMDSv1 to steal IAM credentials.""",
        "metadata": {"service": "EC2", "control": "CIS AWS 5.6", "severity": "MEDIUM"},
    },
    {
        "id": "nginx-cve-2023-44487",
        "content": """CVE-2023-44487 — HTTP/2 Rapid Reset DDoS (CVSS 7.5)
A protocol-level flaw in HTTP/2 where clients send RST_STREAM immediately after HEADERS.
This forces servers to allocate and deallocate resources in rapid loops, exhausting CPU/memory.
Used to achieve record 398 million req/s DDoS attacks in 2023 (Google, Cloudflare, AWS all impacted).
Affected: nginx < 1.25.3
Your affected image: nginx:1.21
Remediation:
1. Update Dockerfile: FROM nginx:1.25.3 (or nginx:alpine for smaller image)
2. Rebuild: docker build -t shieldscan-web:latest .
3. Verify: docker run --rm nginx:1.25.3 nginx -v → should show 1.25.3
4. If you cannot upgrade immediately: disable HTTP/2 in nginx.conf by removing `http2` from listen directives
5. Rescan with Trivy: trivy image nginx:1.25.3""",
        "metadata": {"service": "CWPP", "control": "Trivy", "severity": "HIGH"},
    },
    {
        "id": "python-cve-2023-40217",
        "content": """CVE-2023-40217 — Python SSL Module Bypass (CVSS 5.3)
A vulnerability where the ssl.SSLSocket class could bypass certain TLS verification in edge cases.
Affects Python < 3.11.5, < 3.10.13, < 3.9.18, < 3.8.18
Your affected image: python:3.9-slim
Remediation:
1. Update Dockerfile: FROM python:3.12-slim (or python:3.11-slim)
2. python:3.12-slim is smallest and most secure current option
3. Rebuild: docker build -t shieldscan-api:latest .
4. Test: docker run --rm python:3.12-slim python --version
5. Rescan: trivy image python:3.12-slim""",
        "metadata": {"service": "CWPP", "control": "Trivy", "severity": "MEDIUM"},
    },
    {
        "id": "s3-versioning",
        "content": """S3 Versioning — CIS AWS 2.1.3
S3 versioning keeps all versions of every object. Protects against accidental deletion and ransomware.
Without versioning: one delete command wipes a file permanently.
With versioning: deleted objects become delete markers; previous versions are recoverable.
Remediation for s3://shieldscan-backups:
1. aws s3api put-bucket-versioning --bucket shieldscan-backups --versioning-configuration Status=Enabled
2. Or: S3 console → shieldscan-backups → Properties → Bucket Versioning → Enable
3. Optional: Enable MFA Delete for extra protection against malicious deletion
4. Add lifecycle rule to expire old versions: aws s3api put-bucket-lifecycle-configuration ... (keep last 30 days)
Note: Once enabled, versioning can only be suspended, not disabled.""",
        "metadata": {"service": "S3", "control": "CIS AWS 2.1.3", "severity": "MEDIUM"},
    },
]


def _initialize():
    """Ingest seed documents into ChromaDB on startup (idempotent)."""
    existing_ids = set(_collection.get()["ids"])
    new_docs = [d for d in _SEED_DOCS if d["id"] not in existing_ids]
    if new_docs:
        _collection.add(
            ids=[d["id"] for d in new_docs],
            documents=[d["content"] for d in new_docs],
            metadatas=[d["metadata"] for d in new_docs],
        )


_initialize()


def retrieve(query: str, n_results: int = 3) -> str:
    """
    Embed the query and return the top-n most semantically relevant KB chunks.
    Returns a formatted string ready to inject into Claude's system prompt.
    Returns empty string if no relevant results found.
    """
    total = _collection.count()
    if total == 0:
        return ""

    results = _collection.query(
        query_texts=[query],
        n_results=min(n_results, total),
    )

    if not results["documents"] or not results["documents"][0]:
        return ""

    chunks = []
    for i, (doc, meta) in enumerate(zip(results["documents"][0], results["metadatas"][0])):
        header = f"[KB-{i+1}] {meta.get('control', '')} | {meta.get('service', '')} | Severity: {meta.get('severity', '')}"
        chunks.append(f"{header}\n{doc}")

    return "\n\n---\n\n".join(chunks)


def ingest_document(content: str, doc_id: str, metadata: dict = None):
    """
    Add a new document to the knowledge base at runtime.
    Use this to ingest AWS docs pages, CIS Benchmark chapters, new CVE advisories, etc.
    """
    _collection.add(
        ids=[doc_id],
        documents=[content],
        metadatas=[metadata or {}],
    )
    print(f"[RAG] Ingested document: {doc_id}")
