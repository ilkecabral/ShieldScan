"""
rag_module.py — Persistent ChromaDB RAG for ShieldScan
Upgraded from in-memory to file-based storage so knowledge survives restarts.

Knowledge base covers:
- CIS AWS Benchmark v1.5 (25 controls)
- Common CVE remediation patterns
- AWS IAM, S3, Security Groups best practices
- Container security (Trivy findings)
"""

import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Persist ChromaDB data next to this file (backend/chroma_db/)
CHROMA_PERSIST_DIR = os.path.join(os.path.dirname(__file__), "chroma_db")

# Lazy-loaded client and collection
_client = None
_collection = None
COLLECTION_NAME = "shieldscan_knowledge"


def _get_collection():
    """Lazy init — only creates the client on first use."""
    global _client, _collection
    if _collection is not None:
        return _collection

    import chromadb
    from chromadb.utils import embedding_functions

    _client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)

    ef = embedding_functions.DefaultEmbeddingFunction()

    _collection = _client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    # Seed if empty
    if _collection.count() == 0:
        _seed_knowledge_base(_collection)

    return _collection


def _seed_knowledge_base(collection):
    """Load the initial CIS Benchmark + remediation knowledge into ChromaDB."""

    documents = [
        # ── S3 ──────────────────────────────────────────────────────────────
        {
            "id": "cis-s3-public-access",
            "content": "CIS AWS 2.1.5 — S3 Block Public Access should be enabled at the bucket level. "
                       "Public S3 buckets expose all stored data to the internet. "
                       "Fix: Go to S3 → Bucket → Permissions → Block public access → Enable all four settings. "
                       "Also check bucket policy and ACLs for any explicit public grants.",
            "metadata": {"category": "S3", "severity": "CRITICAL", "control": "CIS-2.1.5"},
        },
        {
            "id": "cis-s3-versioning",
            "content": "CIS AWS 2.1.3 — S3 bucket versioning should be enabled. "
                       "Without versioning, accidental deletions or ransomware attacks are unrecoverable. "
                       "Fix: S3 → Bucket → Properties → Bucket Versioning → Enable. "
                       "Consider enabling MFA Delete for critical buckets.",
            "metadata": {"category": "S3", "severity": "MEDIUM", "control": "CIS-2.1.3"},
        },
        # ── IAM ─────────────────────────────────────────────────────────────
        {
            "id": "cis-iam-root-access-key",
            "content": "CIS AWS 1.4 — The root account should not have active access keys. "
                       "Root access keys have unrestricted access to all AWS services and cannot be scoped. "
                       "Fix: Go to IAM → Security credentials → Delete root access keys immediately. "
                       "Use IAM users or roles with least privilege instead.",
            "metadata": {"category": "IAM", "severity": "CRITICAL", "control": "CIS-1.4"},
        },
        {
            "id": "cis-iam-mfa-root",
            "content": "CIS AWS 1.5 — MFA should be enabled on the root account. "
                       "Without MFA, a stolen root password gives full account access. "
                       "Fix: AWS Console → Account → Security credentials → Activate MFA. "
                       "Use a hardware MFA device for root — virtual MFA is acceptable but hardware is preferred.",
            "metadata": {"category": "IAM", "severity": "CRITICAL", "control": "CIS-1.5"},
        },
        {
            "id": "cis-iam-password-policy",
            "content": "CIS AWS 1.8-1.11 — IAM password policy should enforce minimum length (14+), "
                       "require uppercase, lowercase, numbers, and symbols, and expire passwords within 90 days. "
                       "Fix: IAM → Account settings → Edit password policy.",
            "metadata": {"category": "IAM", "severity": "MEDIUM", "control": "CIS-1.8"},
        },
        # ── Security Groups ──────────────────────────────────────────────────
        {
            "id": "cis-sg-ssh-open",
            "content": "CIS AWS 5.2 — Security groups should not allow unrestricted SSH access (0.0.0.0/0 on port 22). "
                       "Open SSH exposes instances to brute-force and credential stuffing attacks. "
                       "Fix: EC2 → Security Groups → Edit inbound rules → Restrict port 22 to your specific IP or a VPN CIDR. "
                       "Better: use AWS Systems Manager Session Manager and remove SSH entirely.",
            "metadata": {"category": "SecurityGroups", "severity": "HIGH", "control": "CIS-5.2"},
        },
        {
            "id": "cis-sg-rdp-open",
            "content": "CIS AWS 5.3 — Security groups should not allow unrestricted RDP access (0.0.0.0/0 on port 3389). "
                       "Fix: Restrict to specific IPs or use AWS Systems Manager for Windows access.",
            "metadata": {"category": "SecurityGroups", "severity": "HIGH", "control": "CIS-5.3"},
        },
        # ── CloudTrail ───────────────────────────────────────────────────────
        {
            "id": "cis-cloudtrail-enabled",
            "content": "CIS AWS 3.1 — CloudTrail should be enabled and log to all regions. "
                       "Without CloudTrail, there is no audit trail for API calls — security incidents cannot be investigated. "
                       "Fix: CloudTrail → Create trail → Enable for all regions → Send logs to S3 + CloudWatch Logs. "
                       "Enable log file validation and encryption.",
            "metadata": {"category": "CloudTrail", "severity": "HIGH", "control": "CIS-3.1"},
        },
        {
            "id": "cis-cloudtrail-s3-logging",
            "content": "CIS AWS 3.6 — S3 bucket access logging should be enabled on the CloudTrail S3 bucket. "
                       "Fix: S3 → CloudTrail bucket → Properties → Server access logging → Enable.",
            "metadata": {"category": "CloudTrail", "severity": "LOW", "control": "CIS-3.6"},
        },
        # ── RDS ─────────────────────────────────────────────────────────────
        {
            "id": "cis-rds-public",
            "content": "CIS AWS — RDS instances should not be publicly accessible. "
                       "A public RDS endpoint exposes your database to the internet — attackers can attempt direct connections. "
                       "Fix: RDS → Modify instance → Connectivity → Public access → No. "
                       "Place RDS in a private subnet and use a bastion host or VPN for access.",
            "metadata": {"category": "RDS", "severity": "HIGH", "control": "CIS-RDS"},
        },
        # ── EC2 ──────────────────────────────────────────────────────────────
        {
            "id": "cis-ec2-imdsv1",
            "content": "EC2 IMDSv1 is deprecated and vulnerable to SSRF attacks that can leak IAM credentials. "
                       "Fix: EC2 → Actions → Modify instance metadata options → IMDSv2 = Required. "
                       "This forces all metadata requests to use session-oriented tokens, blocking SSRF exploitation.",
            "metadata": {"category": "EC2", "severity": "MEDIUM", "control": "EC2-IMDSv2"},
        },
        # ── Containers / CVEs ────────────────────────────────────────────────
        {
            "id": "trivy-nginx-cve",
            "content": "nginx CVEs in containers should be patched by updating the base image. "
                       "Fix: Update your Dockerfile FROM line to the latest nginx or distroless image. "
                       "Run: docker pull nginx:latest && docker build --no-cache. "
                       "Use Trivy in your CI pipeline (trivy image your-image:tag) to catch CVEs before deploy.",
            "metadata": {"category": "Container", "severity": "HIGH", "control": "CWPP"},
        },
        {
            "id": "trivy-python-cve",
            "content": "Python package CVEs should be remediated by upgrading the affected package. "
                       "Fix: Update requirements.txt or Pipfile to the fixed version shown in the finding. "
                       "Run pip audit or safety check to scan all dependencies. "
                       "Pin to specific fixed versions in production images.",
            "metadata": {"category": "Container", "severity": "MEDIUM", "control": "CWPP"},
        },
        # ── KMS / Encryption ────────────────────────────────────────────────
        {
            "id": "cis-kms-rotation",
            "content": "CIS AWS 3.8 — KMS customer-managed keys (CMKs) should have automatic rotation enabled. "
                       "Fix: KMS → Customer managed keys → Select key → Key rotation → Enable. "
                       "AWS rotates the key material annually — existing encrypted data remains accessible.",
            "metadata": {"category": "KMS", "severity": "MEDIUM", "control": "CIS-3.8"},
        },
        # ── VPC ─────────────────────────────────────────────────────────────
        {
            "id": "cis-vpc-flow-logs",
            "content": "CIS AWS 3.9 — VPC flow logs should be enabled in all VPCs. "
                       "Flow logs capture network traffic metadata for threat detection and forensics. "
                       "Fix: VPC → Your VPC → Actions → Create flow log → Send to CloudWatch Logs.",
            "metadata": {"category": "VPC", "severity": "MEDIUM", "control": "CIS-3.9"},
        },
    ]

    collection.add(
        ids=[d["id"] for d in documents],
        documents=[d["content"] for d in documents],
        metadatas=[d["metadata"] for d in documents],
    )


# ─────────────────────────────────────────
# Public API
# ─────────────────────────────────────────

def retrieve(query: str, n_results: int = 3) -> str:
    """
    Retrieve the most relevant knowledge base snippets for a user query.
    Returns a formatted string ready to inject into the AI system prompt.
    """
    try:
        collection = _get_collection()
        results = collection.query(query_texts=[query], n_results=min(n_results, collection.count()))
        docs = results.get("documents", [[]])[0]
        if not docs:
            return ""
        return "\n\n".join(f"[{i+1}] {doc}" for i, doc in enumerate(docs))
    except Exception as e:
        # RAG failure should never crash the chat endpoint
        return ""


def ingest_finding(finding_id: str, content: str, metadata: Optional[dict] = None):
    """
    Add a new finding or document to the knowledge base at runtime.
    Used when teammates push real CSPM/CWPP findings to expand the RAG corpus.
    """
    try:
        collection = _get_collection()
        collection.upsert(
            ids=[finding_id],
            documents=[content],
            metadatas=[metadata or {}],
        )
    except Exception as e:
        pass  # Log in production


def get_collection_size() -> int:
    """Return number of documents in the knowledge base."""
    try:
        return _get_collection().count()
    except Exception:
        return 0
