"""
rag_module.py — Persistent ChromaDB RAG for ShieldScan
Upgraded from in-memory to file-based storage so knowledge survives restarts.

Knowledge base covers (55 entries):
- CIS AWS Foundations Benchmark v3.0 controls (IAM, S3, CloudTrail, VPC, RDS, EC2, KMS)
- OWASP Top 10 2025 — cloud/API security misconfigurations
- NIST SP 800-53 Rev 5 — AC, IA, AU, SC, CM control families
- AWS Security Best Practices (official docs: S3, CloudTrail, VPC, IAM)
- Container security (Trivy CVE remediation, Docker best practices)
- Incident response and forensics patterns
"""

import os
import logging
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Persist ChromaDB data next to this file (backend/chroma_db/)
CHROMA_PERSIST_DIR = os.path.join(os.path.dirname(__file__), "chroma_db")

# Production: set CHROMA_HOST to the ChromaDB container hostname (e.g. "chromadb")
# When set, uses HttpClient (safe for multiple uvicorn workers).
# When unset, falls back to PersistentClient for local dev (single-worker only).
CHROMA_HOST = os.getenv("CHROMA_HOST", "")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8001"))

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

    if CHROMA_HOST:
        # Production mode: ChromaDB running as a separate service.
        # HttpClient is stateless — safe for any number of uvicorn workers.
        logger.info("ChromaDB: connecting to HttpClient at %s:%d", CHROMA_HOST, CHROMA_PORT)
        _client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    else:
        # Development mode: local file-based storage.
        # WARNING: PersistentClient is NOT safe with multiple workers (file lock contention).
        # Set UVICORN_WORKERS=1 in dev or run uvicorn with --workers 1.
        logger.warning(
            "ChromaDB: using PersistentClient at %s — set CHROMA_HOST for multi-worker production",
            CHROMA_PERSIST_DIR,
        )
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
    """
    Load 55 real-world cloud security knowledge chunks into ChromaDB.
    Sources: CIS AWS Benchmark v3.0, AWS official docs, OWASP Top 10 2025,
             NIST SP 800-53 Rev 5, Wiz Academy, Docker/Trivy documentation.
    """

    documents = [

        # ══════════════════════════════════════════════════════════════════════
        # S3 — CIS AWS Foundations Benchmark v3.0 + AWS Official Security Guide
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "cis-s3-public-access-block",
            "content": (
                "CIS AWS 2.1.5 — S3 Block Public Access must be enabled at both bucket and account level. "
                "76% of companies have third-party roles that can exploit public S3 buckets to gain full control. "
                "The AWS Block Public Access feature overrides all bucket policies and ACL rules. "
                "Fix: S3 → Account settings for Block Public Access → Enable all four settings (BlockPublicAcls, "
                "IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets). "
                "Also enforce at org level: AWS Organizations → Service Control Policies → deny s3:PutBucketPublicAccessBlock. "
                "CLI: aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            ),
            "metadata": {"category": "S3", "severity": "CRITICAL", "control": "CIS-2.1.5", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-s3-encryption-at-rest",
            "content": (
                "CIS AWS 2.1.1 — S3 buckets must have server-side encryption enabled for all objects at rest. "
                "S3 automatically encrypts new objects with SSE-S3 (AES-256). For regulated workloads, use "
                "SSE-KMS (AWS KMS-managed keys) for audit trails, or SSE-C (customer-provided keys) for full key control. "
                "Combine encryption with least-privilege IAM: even if bucket access is misconfigured, "
                "encrypted objects are unreadable without the key. "
                "Fix: S3 → Bucket → Properties → Default encryption → SSE-KMS. "
                "Enforce with bucket policy: deny any PutObject request missing the SSE header. "
                "CLI: aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration "
                "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'"
            ),
            "metadata": {"category": "S3", "severity": "HIGH", "control": "CIS-2.1.1", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-s3-versioning",
            "content": (
                "CIS AWS 2.1.3 — S3 bucket versioning should be enabled to protect against accidental deletion and ransomware. "
                "Without versioning, deleted or overwritten objects are gone permanently. "
                "Versioning saves every object change as a new version — you can restore any prior state. "
                "Note: versioning increases storage costs. Use S3 Lifecycle policies to move old versions to Glacier after 90 days. "
                "For critical buckets, also enable MFA Delete — requires MFA to permanently delete any object version. "
                "Fix: S3 → Bucket → Properties → Bucket Versioning → Enable. "
                "CLI: aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled"
            ),
            "metadata": {"category": "S3", "severity": "MEDIUM", "control": "CIS-2.1.3", "source": "CIS AWS v3.0"},
        },
        {
            "id": "s3-access-logging",
            "content": (
                "CIS AWS 2.1.2 — S3 server access logging should be enabled on all buckets containing sensitive data. "
                "Logs record every request (requester, bucket, key, action, timestamp, response status). "
                "Required for compliance standards like PCI-DSS, HIPAA, and SOC 2. "
                "Store logs in a separate, secured bucket with strict ACLs — never log to the same bucket. "
                "Use lifecycle rules to manage log retention and control costs. "
                "Integrate with CloudTrail and CloudWatch for real-time anomaly detection. "
                "Fix: S3 → Bucket → Properties → Server access logging → Enable → specify a log bucket. "
                "CLI: aws s3api put-bucket-logging --bucket BUCKET --bucket-logging-status "
                "'{\"LoggingEnabled\":{\"TargetBucket\":\"LOG-BUCKET\",\"TargetPrefix\":\"logs/\"}}'"
            ),
            "metadata": {"category": "S3", "severity": "MEDIUM", "control": "CIS-2.1.2", "source": "CIS AWS v3.0"},
        },
        {
            "id": "s3-https-enforce",
            "content": (
                "AWS S3 Security Best Practice — Enforce HTTPS-only access for all S3 bucket operations. "
                "Data in transit over HTTP is unencrypted and susceptible to man-in-the-middle attacks. "
                "Fix: Apply a bucket policy that denies all requests where aws:SecureTransport is false. "
                "Bucket policy snippet: {\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\","
                "\"Resource\":\"arn:aws:s3:::BUCKET/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}. "
                "Also audit existing policies to ensure no statements explicitly allow HTTP."
            ),
            "metadata": {"category": "S3", "severity": "HIGH", "control": "S3-HTTPS", "source": "AWS Docs"},
        },
        {
            "id": "s3-object-lock",
            "content": (
                "AWS S3 Object Lock (WORM) prevents objects from being deleted or overwritten for a defined period. "
                "Use Compliance mode for regulatory requirements where even the root account cannot delete objects. "
                "Use Governance mode for operational protection where admins can override with special permissions. "
                "Integrate with AWS Config snapshots to maintain immutable audit trails of S3 bucket policy changes. "
                "Attackers who compromise a bucket cannot tamper with locked logs or backups. "
                "Fix: Enable Object Lock when creating the bucket (cannot be added later). "
                "Set a default retention period under Governance or Compliance mode."
            ),
            "metadata": {"category": "S3", "severity": "MEDIUM", "control": "S3-LOCK", "source": "AWS Docs"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # IAM — CIS AWS Foundations Benchmark v3.0
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "cis-iam-root-access-key",
            "content": (
                "CIS AWS 1.4 — The AWS root account must not have active access keys. "
                "Root access keys have unrestricted access to all AWS services and resources, cannot be scoped with IAM policies. "
                "If compromised, an attacker has complete control of the AWS account including billing and all data. "
                "Fix: IAM Console → Security credentials → Rotate/Delete root access keys immediately. "
                "Use IAM users or roles with least-privilege policies for programmatic access. "
                "CLI check: aws iam get-account-summary | grep AccountAccessKeysPresent — must return 0."
            ),
            "metadata": {"category": "IAM", "severity": "CRITICAL", "control": "CIS-1.4", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-iam-mfa-root",
            "content": (
                "CIS AWS 1.5 — MFA must be enabled on the AWS root account. "
                "Without MFA, a stolen root password gives full, unrestricted account access. "
                "Virtual MFA (Google Authenticator) is the minimum; hardware MFA tokens (YubiKey, AWS-provided device) are preferred. "
                "Hardware MFA is more resistant to phishing and SIM-swap attacks. "
                "Fix: AWS Console → Account → Security credentials → Multi-factor authentication (MFA) → Activate MFA. "
                "CLI check: aws iam get-account-summary | grep AccountMFAEnabled — must return 1."
            ),
            "metadata": {"category": "IAM", "severity": "CRITICAL", "control": "CIS-1.5", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-iam-mfa-console-users",
            "content": (
                "CIS AWS 1.10 — MFA must be enabled for all IAM users that have a console password. "
                "Any user account without MFA is a single-factor credential that can be phished or brute-forced. "
                "Enforce MFA with an IAM policy that denies all actions except iam:CreateVirtualMFADevice and "
                "iam:EnableMFADevice until MFA is configured — this creates a mandatory MFA enrollment flow. "
                "Fix: IAM → Users → Select user → Security credentials → Assigned MFA device → Assign. "
                "Or automate with AWS Config rule: mfa-enabled-for-iam-console-access."
            ),
            "metadata": {"category": "IAM", "severity": "HIGH", "control": "CIS-1.10", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-iam-password-policy",
            "content": (
                "CIS AWS 1.8-1.11 — IAM account password policy must enforce: minimum 14 characters, "
                "require uppercase letters, lowercase letters, numbers, and non-alphanumeric symbols, "
                "prevent password reuse (last 24 passwords), and expire passwords within 90 days. "
                "Weak passwords enable credential stuffing and brute-force attacks. "
                "Fix: IAM → Account settings → Edit password policy. "
                "CLI: aws iam update-account-password-policy --minimum-password-length 14 "
                "--require-symbols --require-numbers --require-uppercase-characters "
                "--require-lowercase-characters --allow-users-to-change-password "
                "--max-password-age 90 --password-reuse-prevention 24"
            ),
            "metadata": {"category": "IAM", "severity": "MEDIUM", "control": "CIS-1.8", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-iam-access-key-rotation",
            "content": (
                "CIS AWS 1.14 — IAM user access keys should be rotated every 90 days. "
                "Long-lived access keys are a major attack vector — if leaked (GitHub, logs, config files), "
                "they remain valid indefinitely unless rotated. "
                "Fix: IAM → Users → Security credentials → Create new access key → Update application → Delete old key. "
                "Automate enforcement with AWS Config rule: access-keys-rotated (maxAccessKeyAge=90). "
                "Better: migrate from IAM user keys to IAM roles and instance profiles — no long-lived credentials needed. "
                "CLI: aws iam list-access-keys --user-name USER to check key ages."
            ),
            "metadata": {"category": "IAM", "severity": "HIGH", "control": "CIS-1.14", "source": "CIS AWS v3.0"},
        },
        {
            "id": "iam-least-privilege",
            "content": (
                "AWS IAM Best Practice — Apply the principle of least privilege to all IAM identities. "
                "Grant only the minimum permissions required for a specific task — avoid wildcard actions (s3:*) "
                "or wildcard resources (arn:aws:s3:::*). "
                "Define specific actions (s3:GetObject, s3:PutObject) on specific resources (arn:aws:s3:::my-bucket/*). "
                "Use IAM Access Analyzer to detect overly permissive policies and unused permissions. "
                "Use AWS Config rule: iam-policy-no-statements-with-admin-access to catch policies granting admin. "
                "Worst case: a compromised service with admin access can read, modify, or delete all AWS data."
            ),
            "metadata": {"category": "IAM", "severity": "HIGH", "control": "IAM-LEASTPRIV", "source": "AWS Docs"},
        },
        {
            "id": "iam-no-inline-policies",
            "content": (
                "CIS AWS 1.16 — IAM policies should be attached to groups or roles, not directly to users. "
                "Inline policies attached to individual users are hard to audit, reuse, or revoke at scale. "
                "Fix: Create IAM groups by job function (e.g., Developers, Auditors, ReadOnly), "
                "attach managed policies to groups, then add users to appropriate groups. "
                "Review with: aws iam list-users | then aws iam list-user-policies --user-name USER for each. "
                "Any inline policies found should be converted to managed policies and attached to groups."
            ),
            "metadata": {"category": "IAM", "severity": "LOW", "control": "CIS-1.16", "source": "CIS AWS v3.0"},
        },
        {
            "id": "iam-unused-credentials",
            "content": (
                "CIS AWS 1.12 — Unused IAM credentials (console access not used in 45 days, unused access keys) "
                "should be disabled or removed. Stale credentials are attack surface — if an account is compromised "
                "later, attackers may find valid but forgotten credentials. "
                "Fix: Download IAM Credential Report (IAM → Credential Report) and check password_last_used and "
                "access_key_last_used_date. Disable users with >45 days of inactivity. "
                "Automate with AWS Config rule: iam-user-unused-credentials-check."
            ),
            "metadata": {"category": "IAM", "severity": "MEDIUM", "control": "CIS-1.12", "source": "CIS AWS v3.0"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # CloudTrail — CIS AWS v3.0 + AWS Official CloudTrail Security Docs
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "cis-cloudtrail-multiregion",
            "content": (
                "CIS AWS 3.1 — CloudTrail must be enabled in all AWS regions and all regions must log to a single trail. "
                "Without multi-region CloudTrail, API activity in non-primary regions goes unlogged — attackers "
                "deliberately use regions you don't monitor to create IAM users, spin up EC2 instances, or exfiltrate data. "
                "Fix: CloudTrail → Create trail → Apply trail to all regions. "
                "All trails created via CloudTrail console are multi-region by default. "
                "Enforce with AWS Config rule: multi-region-cloudtrail-enabled. "
                "Also enable logging of global service events (IAM, STS, CloudFront) which are always logged to us-east-1."
            ),
            "metadata": {"category": "CloudTrail", "severity": "HIGH", "control": "CIS-3.1", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-cloudtrail-log-validation",
            "content": (
                "CIS AWS 3.2 — CloudTrail log file integrity validation should be enabled. "
                "Validated log files are forensically sound — if an attacker modifies, deletes, or forges a log file, "
                "you will detect it. CloudTrail uses SHA-256 for hashing and SHA-256 with RSA for digital signing. "
                "This makes it computationally infeasible to modify log files without detection. "
                "Especially critical for security investigations, SOC 2 audits, and PCI-DSS compliance. "
                "Fix: CloudTrail → Select trail → Edit → Enable log file validation. "
                "CLI: aws cloudtrail update-trail --name TRAIL_NAME --enable-log-file-validation"
            ),
            "metadata": {"category": "CloudTrail", "severity": "LOW", "control": "CIS-3.2", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-cloudtrail-kms-encryption",
            "content": (
                "CIS AWS 3.5 — CloudTrail logs should be encrypted with a KMS customer-managed key (SSE-KMS). "
                "By default, CloudTrail logs stored in S3 use SSE-S3 (AWS-managed keys). "
                "Using a customer-managed KMS key gives you auditability (who decrypted when), "
                "granular access control via key policies, and the ability to revoke access instantly. "
                "Fix: CloudTrail → Edit trail → Log file SSE-KMS encryption → Create or select KMS key. "
                "Restrict the KMS key policy to only allow CloudTrail principal and specific auditor roles to decrypt. "
                "CLI: aws cloudtrail update-trail --name TRAIL --kms-key-id KMS_KEY_ARN"
            ),
            "metadata": {"category": "CloudTrail", "severity": "MEDIUM", "control": "CIS-3.5", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cloudtrail-cloudwatch-integration",
            "content": (
                "AWS CloudTrail Best Practice — Integrate CloudTrail with CloudWatch Logs for real-time alerting. "
                "CloudWatch Logs receives CloudTrail events and lets you create metric filters and alarms for "
                "security-critical events: unauthorized API calls, root account usage, IAM policy changes, "
                "security group changes, S3 bucket policy changes, CloudTrail configuration changes. "
                "CIS AWS 4.x — Create CloudWatch alarms for all 14 CIS monitoring controls. "
                "Fix: CloudTrail → Trail → CloudWatch Logs → Configure → Create or select log group. "
                "Then CloudWatch → Metric filters → Create filter for each event type → Create alarm → SNS notification."
            ),
            "metadata": {"category": "CloudTrail", "severity": "MEDIUM", "control": "CIS-4.x", "source": "AWS Docs"},
        },
        {
            "id": "cloudtrail-dedicated-s3-bucket",
            "content": (
                "AWS CloudTrail Best Practice — Log CloudTrail events to a dedicated, centralized S3 bucket "
                "in a separate log-archive AWS account. "
                "Centralizing logs in an isolated account with strict access controls prevents attackers who "
                "compromise a production account from deleting or modifying their audit trail. "
                "Restrict bucket access to only the CloudTrail service principal and trusted admin roles. "
                "Enable MFA Delete on the log bucket so individual objects require MFA to permanently delete. "
                "Use S3 lifecycle policies to archive logs older than 1 year to Glacier. "
                "Apply the AWSCloudTrail_FullAccess policy only to the minimum number of administrators."
            ),
            "metadata": {"category": "CloudTrail", "severity": "HIGH", "control": "CLOUDTRAIL-BUCKET", "source": "AWS Docs"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # VPC / Networking — CIS AWS v3.0 + AWS VPC Security Docs
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "cis-sg-ssh-open",
            "content": (
                "CIS AWS 5.2 — Security groups must not allow unrestricted SSH access (0.0.0.0/0 or ::/0 on port 22). "
                "Open SSH exposes instances to brute-force attacks, credential stuffing, and zero-day SSH exploits. "
                "Fix: EC2 → Security Groups → Edit inbound rules → Change port 22 source from 0.0.0.0/0 to "
                "your office IP CIDR or a VPN CIDR. "
                "Best practice: Remove SSH entirely and use AWS Systems Manager Session Manager for shell access — "
                "no open ports needed, all sessions logged to CloudTrail. "
                "CLI: aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0"
            ),
            "metadata": {"category": "SecurityGroups", "severity": "HIGH", "control": "CIS-5.2", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-sg-rdp-open",
            "content": (
                "CIS AWS 5.3 — Security groups must not allow unrestricted RDP access (0.0.0.0/0 on port 3389). "
                "Open RDP is one of the most commonly exploited attack vectors — ransomware groups routinely scan "
                "for exposed port 3389 and use credential spraying or BlueKeep-class exploits. "
                "Fix: EC2 → Security Groups → Edit inbound rules → Restrict port 3389 to specific IP ranges or VPN CIDR. "
                "Prefer AWS Systems Manager Fleet Manager for Windows remote desktop — no open RDP port required."
            ),
            "metadata": {"category": "SecurityGroups", "severity": "HIGH", "control": "CIS-5.3", "source": "CIS AWS v3.0"},
        },
        {
            "id": "cis-vpc-flow-logs",
            "content": (
                "CIS AWS 3.9 — VPC flow logs should be enabled in all VPCs to capture network traffic metadata. "
                "Flow logs record source IP, destination IP, port, protocol, bytes, action (ACCEPT/REJECT) for every flow. "
                "Critical for forensics, threat hunting, and detecting lateral movement or data exfiltration. "
                "Flow logs do NOT capture packet contents — only metadata. "
                "Fix: VPC → Your VPCs → Select VPC → Actions → Create flow log → Destination: CloudWatch Logs or S3. "
                "Use VPC Block Public Access (AWS Nov 2024 feature) for account-level control that blocks "
                "all internet gateway traffic — strongest VPC isolation available. "
                "CLI: aws ec2 create-flow-logs --resource-type VPC --resource-ids VPC_ID "
                "--traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name VPCFlowLogs"
            ),
            "metadata": {"category": "VPC", "severity": "MEDIUM", "control": "CIS-3.9", "source": "CIS AWS v3.0"},
        },
        {
            "id": "vpc-default-sg-restrict",
            "content": (
                "CIS AWS 5.4 — The default security group of every VPC should restrict all inbound and outbound traffic. "
                "Default security groups are attached to new EC2 instances if no other SG is specified — "
                "a misconfigured instance using the default SG may inherit overly permissive rules. "
                "Fix: EC2 → Security Groups → Find default SG for each VPC → Edit inbound rules → Remove all rules. "
                "Edit outbound rules → Remove all rules. "
                "Then enforce by tagging and building a detective control with AWS Config: vpc-default-security-group-closed."
            ),
            "metadata": {"category": "VPC", "severity": "MEDIUM", "control": "CIS-5.4", "source": "CIS AWS v3.0"},
        },
        {
            "id": "vpc-nacl-best-practices",
            "content": (
                "AWS VPC NACLs (Network ACLs) are stateless subnet-level firewalls that provide a second layer of defense. "
                "Unlike security groups, NACLs require explicit ALLOW and DENY rules for both inbound and outbound traffic. "
                "Best practices: Start with DENY ALL rule at the end of the table. "
                "Add explicit ALLOW rules only for required traffic. "
                "Place DENY rules earlier in the rule table than ALLOW rules for the same port ranges. "
                "Use NACLs to block known malicious IP ranges at the subnet boundary. "
                "Combine with security groups: security groups for instance-level control, NACLs for subnet-level control. "
                "VPC Block Public Access (2024): account-level block that overrides even permissive NACLs and SGs."
            ),
            "metadata": {"category": "VPC", "severity": "MEDIUM", "control": "VPC-NACL", "source": "AWS Docs"},
        },
        {
            "id": "vpc-no-direct-ec2-public",
            "content": (
                "AWS Security Best Practice — EC2 instances should not have public IP addresses unless they are "
                "intentional public-facing services (load balancers, NAT gateways, bastion hosts). "
                "Public IPs expose instances directly to internet scanning and exploit attempts. "
                "Fix: Launch EC2 instances in private subnets. Route outbound traffic through a NAT gateway. "
                "Use an Application Load Balancer in a public subnet as the internet-facing entry point. "
                "For management access, use AWS Systems Manager Session Manager — no public IP needed. "
                "Detect violations with AWS Config: ec2-instance-no-public-ip."
            ),
            "metadata": {"category": "VPC", "severity": "HIGH", "control": "VPC-EC2-PUBLIC", "source": "AWS Docs"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # RDS
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "cis-rds-no-public",
            "content": (
                "CIS AWS — RDS instances must not be publicly accessible. "
                "A public RDS endpoint is directly reachable from the internet — attackers can attempt connections "
                "with default credentials, run credential stuffing attacks, or exploit unpatched database engine CVEs. "
                "Fix: RDS → Modify instance → Connectivity → Public access → No. "
                "Move RDS to a private subnet (no route to internet gateway). "
                "Access the database from application servers in the same VPC, or through a bastion host or VPN. "
                "CLI: aws rds modify-db-instance --db-instance-identifier DB_ID --no-publicly-accessible"
            ),
            "metadata": {"category": "RDS", "severity": "HIGH", "control": "CIS-RDS-PUBLIC", "source": "CIS AWS v3.0"},
        },
        {
            "id": "rds-encryption-at-rest",
            "content": (
                "CIS AWS — RDS instances should have encryption at rest enabled using AWS KMS. "
                "Unencrypted RDS snapshots can be shared or copied, exposing all data in the snapshot. "
                "RDS encryption uses AES-256 and encrypts the underlying storage, automated backups, "
                "read replicas, and snapshots. Encryption must be enabled at instance creation — "
                "it cannot be enabled on an existing unencrypted instance. "
                "Fix for existing unencrypted instance: Create encrypted snapshot → Restore from encrypted snapshot → "
                "Update connection strings → Delete original instance. "
                "CLI: aws rds create-db-instance ... --storage-encrypted --kms-key-id KMS_KEY_ARN"
            ),
            "metadata": {"category": "RDS", "severity": "HIGH", "control": "RDS-ENCRYPT", "source": "AWS Docs"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # EC2 / Compute
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "cis-ec2-imdsv2",
            "content": (
                "EC2 IMDSv1 is deprecated and vulnerable to Server-Side Request Forgery (SSRF) attacks. "
                "SSRF lets an attacker trick the application into requesting the EC2 metadata endpoint "
                "(http://169.254.169.254/latest/meta-data/iam/security-credentials/) and retrieve temporary IAM credentials. "
                "IMDSv2 requires session-oriented tokens — each metadata request requires a PUT to get a token first, "
                "which SSRF attacks cannot replicate (PUT requests are not followed by SSRF). "
                "Fix: EC2 → Actions → Modify instance metadata options → IMDSv2 → Required. "
                "Set hop limit to 1 to prevent metadata access from containers inside the instance. "
                "CLI: aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required --http-hop-limit 1"
            ),
            "metadata": {"category": "EC2", "severity": "MEDIUM", "control": "EC2-IMDSv2", "source": "AWS Docs"},
        },
        {
            "id": "cis-ebs-encryption",
            "content": (
                "CIS AWS 2.2.1 — EBS volume encryption should be enabled by default for all new volumes. "
                "Unencrypted EBS volumes can be snapshotted and shared, exposing all data. "
                "Enable account-level default encryption so every new EBS volume is encrypted automatically. "
                "This applies to root volumes, data volumes, and snapshots created from those volumes. "
                "Fix: EC2 → Settings → EBS encryption → Enable → Select default KMS key. "
                "CLI: aws ec2 enable-ebs-encryption-by-default. "
                "For existing unencrypted volumes: Create encrypted snapshot from the volume → Create new volume from snapshot → "
                "Detach old volume → Attach new encrypted volume."
            ),
            "metadata": {"category": "EC2", "severity": "MEDIUM", "control": "CIS-2.2.1", "source": "CIS AWS v3.0"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # KMS
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "cis-kms-key-rotation",
            "content": (
                "CIS AWS 3.8 — KMS customer-managed keys (CMKs) should have automatic annual rotation enabled. "
                "Regular key rotation limits the blast radius if a key is compromised — "
                "data encrypted with previous key material remains accessible (AWS retains old key material for decryption) "
                "but new data uses the new key. "
                "AWS automatically creates new key material annually; old material is kept for decryption only. "
                "Fix: KMS → Customer managed keys → Select key → Key rotation → Enable. "
                "CLI: aws kms enable-key-rotation --key-id KEY_ID. "
                "Note: AWS-managed keys rotate automatically every 3 years and cannot be manually rotated."
            ),
            "metadata": {"category": "KMS", "severity": "MEDIUM", "control": "CIS-3.8", "source": "CIS AWS v3.0"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # GuardDuty / Security Hub / Config
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "aws-guardduty-enable",
            "content": (
                "AWS GuardDuty — Threat detection service that should be enabled in all AWS accounts and regions. "
                "GuardDuty uses ML models to analyze CloudTrail, VPC flow logs, and DNS logs to detect: "
                "credential exfiltration (EC2 role credentials used from external IP), "
                "crypto mining (EC2 instances communicating with mining pools), "
                "lateral movement (IAM user accessing services they've never used), "
                "data exfiltration (large S3 data transfers to external destinations). "
                "Fix: GuardDuty → Enable → Enable for all regions (use AWS Organizations for multi-account). "
                "Critical: Enable GuardDuty Runtime Monitoring for EKS/ECS container threat detection. "
                "Integrate GuardDuty findings with Security Hub for centralized alerting."
            ),
            "metadata": {"category": "Monitoring", "severity": "HIGH", "control": "GUARDDUTY", "source": "AWS Docs"},
        },
        {
            "id": "aws-security-hub",
            "content": (
                "AWS Security Hub — Centralized CSPM and compliance service that aggregates findings from "
                "GuardDuty, Inspector, Macie, Firewall Manager, IAM Access Analyzer, and third-party tools. "
                "Security Hub continuously evaluates your environment against CIS AWS Foundations Benchmark, "
                "PCI-DSS, NIST SP 800-53, and AWS Foundational Security Best Practices. "
                "Each finding has a severity score (CRITICAL/HIGH/MEDIUM/LOW) and a normalized ASFF format. "
                "Fix: Security Hub → Enable → Enable all security standards → Review and remediate findings. "
                "Use automated response with EventBridge + Lambda to auto-remediate common findings. "
                "Enable Cross-Region aggregation to see all findings in one region."
            ),
            "metadata": {"category": "Monitoring", "severity": "HIGH", "control": "SECURITYHUB", "source": "AWS Docs"},
        },
        {
            "id": "aws-config-compliance",
            "content": (
                "AWS Config — Service that continuously records resource configuration history and evaluates "
                "compliance against managed and custom rules. "
                "Key rules for CNAPP: s3-bucket-public-read-prohibited, iam-user-mfa-enabled, "
                "restricted-ssh, cloud-trail-encryption-enabled, guardduty-enabled-centralized, "
                "ec2-instance-no-public-ip, rds-instance-public-access-check, ebs-snapshot-public-restorable-check. "
                "AWS Config integrates with Security Hub — non-compliant findings appear as Security Hub findings. "
                "Fix: Config → Conformance packs → Deploy CIS AWS Foundations Benchmark pack for automated remediation."
            ),
            "metadata": {"category": "Monitoring", "severity": "MEDIUM", "control": "AWSCONFIG", "source": "AWS Docs"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # Container Security — Docker / Trivy / CVE Remediation
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "trivy-nginx-cve",
            "content": (
                "nginx container CVEs — Common CVEs in nginx images include CVE-2023-44487 (HTTP/2 Rapid Reset DoS), "
                "CVE-2022-41741/41742 (mp4/f4f module heap corruption), and various OpenSSL vulnerabilities. "
                "Trivy scan: trivy image nginx:latest → lists all CVEs with severity and fixed versions. "
                "Fix: Update Dockerfile FROM nginx:1.27-alpine (latest stable, Alpine-based for smaller attack surface). "
                "Rebuild with --no-cache to force fresh layer pulls. "
                "Pin to exact version tags (nginx:1.27.2-alpine) not 'latest' in production for reproducibility. "
                "Run trivy image after rebuild to confirm CVEs are resolved. "
                "Enable Trivy in CI: add 'trivy image --exit-code 1 --severity CRITICAL,HIGH myimage:tag' to pipeline."
            ),
            "metadata": {"category": "Container", "severity": "HIGH", "control": "CWPP-NGINX", "source": "Trivy Docs"},
        },
        {
            "id": "trivy-python-cve",
            "content": (
                "Python package CVEs in containers — Common findings: urllib3 (CVE-2023-45803 SSRF), "
                "cryptography (CVE-2023-49083 NULL pointer dereference), requests (CVE-2023-32681 header leakage). "
                "Trivy identifies CVEs per package with fixed versions. "
                "Fix: Update requirements.txt or Pipfile: change 'urllib3>=1.26.5' to the fixed version listed in the finding. "
                "Run: pip install --upgrade PACKAGE_NAME or pin to fixed: PACKAGE==FIXED_VERSION. "
                "Use pip-audit or safety check in CI: safety check --full-report. "
                "For production images, rebuild with --no-cache after updating requirements. "
                "Re-run trivy to confirm all CRITICAL and HIGH CVEs are resolved before deploying."
            ),
            "metadata": {"category": "Container", "severity": "MEDIUM", "control": "CWPP-PYTHON", "source": "Trivy Docs"},
        },
        {
            "id": "container-base-image-security",
            "content": (
                "Docker container security — Base image selection and maintenance is the most impactful "
                "container security practice. "
                "Use minimal base images: Alpine Linux (5MB) has far fewer packages than ubuntu:latest (~200MB) — "
                "fewer packages means fewer CVEs. Use distroless images (gcr.io/distroless) for zero-shell attack surface. "
                "Pin base images to exact version tags: FROM python:3.11.9-alpine3.20 not FROM python:alpine. "
                "Pin to specific version tags ensures reproducible builds and prevents surprise CVE introduction on rebuild. "
                "Scan base image before use: trivy image python:3.11.9-alpine3.20. "
                "Update base images monthly and rebuild all derived images — most container CVEs come from the base layer."
            ),
            "metadata": {"category": "Container", "severity": "HIGH", "control": "CONTAINER-BASE", "source": "Docker Docs"},
        },
        {
            "id": "container-no-root-user",
            "content": (
                "Docker Security — Containers must not run as root. "
                "If a process in the container is compromised, running as root gives the attacker potential to escape "
                "the container (via kernel vulnerabilities or misconfigured mounts) and access the host. "
                "Fix: Add to Dockerfile: RUN addgroup -S appgroup && adduser -S appuser -G appgroup then USER appuser. "
                "Use --security-opt=no-new-privileges flag at runtime. "
                "In Kubernetes/ECS: set securityContext.runAsNonRoot: true and securityContext.runAsUser: 1000. "
                "Scan with Trivy: it flags CRITICAL severity for containers running as root. "
                "Use read-only root filesystems: --read-only flag or readOnlyRootFilesystem: true in K8s."
            ),
            "metadata": {"category": "Container", "severity": "HIGH", "control": "CONTAINER-ROOT", "source": "Docker Docs"},
        },
        {
            "id": "container-no-secrets-in-image",
            "content": (
                "Docker Security — Never embed secrets (API keys, passwords, certificates) in container images. "
                "Images pushed to registries are accessible to anyone with pull permissions — layer contents are readable. "
                "Even if you delete a secret in a later layer, it remains in the intermediate layer and is extractable. "
                "Fix: Use environment variables injected at runtime (Docker: --env, K8s: secretKeyRef). "
                "Use AWS Secrets Manager or Parameter Store: retrieve secrets at container start via IAM role. "
                "Use Docker BuildKit secrets (--mount=type=secret) for build-time secrets that never touch image layers. "
                "Scan images with: trivy image --scanners secret myimage:tag to detect accidentally included secrets."
            ),
            "metadata": {"category": "Container", "severity": "CRITICAL", "control": "CONTAINER-SECRETS", "source": "Docker Docs"},
        },
        {
            "id": "trivy-ci-integration",
            "content": (
                "Trivy CI/CD Integration — Integrate Trivy scanning into your CI pipeline for shift-left security. "
                "Run on every build: trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed myimage:tag. "
                "exit-code 1 fails the pipeline if CRITICAL or HIGH CVEs with available fixes are found. "
                "--ignore-unfixed skips CVEs with no patch yet (reduces noise). "
                "For GitHub Actions: use aquasecurity/trivy-action@master. "
                "Generate SBOM (Software Bill of Materials): trivy image --format cyclonedx --output sbom.json myimage:tag. "
                "Trivy also scans: file systems (trivy fs .), git repos (trivy repo URL), config files "
                "(Dockerfile, Kubernetes manifests, Terraform — trivy config ./). "
                "Store results as SARIF: trivy image --format sarif --output results.sarif for GitHub Security tab."
            ),
            "metadata": {"category": "Container", "severity": "MEDIUM", "control": "TRIVY-CI", "source": "Trivy Docs"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # OWASP Top 10 2025 — Cloud / API Security Context
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "owasp-a01-broken-access-control",
            "content": (
                "OWASP A01:2021/2025 — Broken Access Control (most common web/API vulnerability). "
                "In cloud contexts: S3 buckets publicly accessible without auth, "
                "IAM roles with wildcard permissions, API endpoints without authorization checks. "
                "Attackers access S3 files directly via URL without authentication when ACLs allow public read. "
                "Fix: Enforce S3 Block Public Access at account level. Apply least-privilege IAM. "
                "Implement resource-based policies (bucket policies) that explicitly deny all principals except specific ARNs. "
                "Use IAM Access Analyzer to find publicly accessible resources and overly permissive cross-account access. "
                "API Gateway: enable Cognito or JWT authorizer on every endpoint — never expose unauthenticated routes."
            ),
            "metadata": {"category": "OWASP", "severity": "CRITICAL", "control": "OWASP-A01", "source": "OWASP 2025"},
        },
        {
            "id": "owasp-a02-cryptographic-failures",
            "content": (
                "OWASP A02:2021/2025 — Cryptographic Failures (data exposure via weak or missing encryption). "
                "Cloud examples: S3 buckets without SSE, RDS instances without encryption at rest, "
                "data transmitted over HTTP instead of HTTPS, secrets stored in plaintext in environment variables. "
                "Fix: Enable SSE-KMS on all S3 buckets. Enable RDS encryption at creation. "
                "Enforce HTTPS with bucket policies and API Gateway TLS settings. "
                "Store secrets in AWS Secrets Manager or Systems Manager Parameter Store (SecureString type). "
                "Rotate secrets automatically using Secrets Manager rotation Lambda functions. "
                "Avoid MD5 and SHA-1 for security-critical hashing — use SHA-256 or stronger."
            ),
            "metadata": {"category": "OWASP", "severity": "HIGH", "control": "OWASP-A02", "source": "OWASP 2025"},
        },
        {
            "id": "owasp-a05-security-misconfiguration",
            "content": (
                "OWASP A05 → A02 in 2025 — Security Misconfiguration (now #2, up from #5 in 2021, affecting 3% of apps). "
                "Most common cloud misconfigurations: S3 public access, default VPC security group open, "
                "EC2 SSH/RDP open to 0.0.0.0/0, IAM admin policies attached to users, CloudTrail disabled, "
                "GuardDuty not enabled, logging disabled, no MFA on root/console users. "
                "Fix: Apply CIS AWS Foundations Benchmark Level 1 controls as baseline. "
                "Implement AWS Config conformance packs for continuous compliance monitoring. "
                "Use AWS Security Hub to aggregate misconfiguration findings across all accounts. "
                "Run trivy config . to scan IaC (Terraform, CloudFormation) for misconfigurations before deploy. "
                "Enable AWS Config with automatic remediation via Systems Manager Automation."
            ),
            "metadata": {"category": "OWASP", "severity": "HIGH", "control": "OWASP-A05", "source": "OWASP 2025"},
        },
        {
            "id": "owasp-a06-vulnerable-components",
            "content": (
                "OWASP A06:2021/2025 — Vulnerable and Outdated Components. "
                "In cloud-native apps: container base images with unpatched CVEs (nginx, python, alpine), "
                "outdated Python/Node dependencies with known exploits, Lambda layers with old library versions. "
                "Log4Shell (CVE-2021-44228) was an A06 vulnerability that affected millions of servers. "
                "Fix: Scan all container images with Trivy in CI/CD. "
                "Use Dependabot or Renovate to automatically open PRs for dependency updates. "
                "Enable Amazon Inspector for continuous EC2 and ECR vulnerability scanning. "
                "For Lambda: use Lambda layers and update them monthly. "
                "Maintain an SBOM (Software Bill of Materials) for every deployed artifact."
            ),
            "metadata": {"category": "OWASP", "severity": "HIGH", "control": "OWASP-A06", "source": "OWASP 2025"},
        },
        {
            "id": "owasp-a07-auth-failures",
            "content": (
                "OWASP A07:2021/2025 — Identification and Authentication Failures. "
                "Cloud examples: IAM users without MFA, API keys in source code (GitHub secrets), "
                "JWT tokens without expiry, long-lived access keys not rotated, default credentials not changed. "
                "GitHub Secret Scanning found over 10 million secrets exposed in public repos in 2023. "
                "Fix: Enable MFA for all console users (CIS 1.10). Rotate IAM access keys every 90 days (CIS 1.14). "
                "Use IAM roles instead of long-lived access keys for EC2, Lambda, ECS workloads. "
                "Run git-secrets or truffleHog in pre-commit hooks to prevent secrets being committed. "
                "Enable GitHub Advanced Security Secret Scanning on all repositories."
            ),
            "metadata": {"category": "OWASP", "severity": "HIGH", "control": "OWASP-A07", "source": "OWASP 2025"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # NIST SP 800-53 Rev 5 — AC, IA, AU, SC Control Families
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "nist-ac-access-control",
            "content": (
                "NIST SP 800-53 Rev 5 — AC (Access Control) Family (26 controls). "
                "AC-2 (Account Management): maintain inventory of IAM accounts, remove/disable inactive accounts within 45 days. "
                "AC-3 (Access Enforcement): enforce least-privilege via IAM policies, bucket policies, resource-based policies. "
                "AC-6 (Least Privilege): grant only minimum permissions required — avoid s3:* or iam:* wildcards. "
                "AC-17 (Remote Access): require MFA for all remote access (console and API). "
                "AC-19 (Access for Mobile Devices): control access from mobile/BYOD through conditional access policies. "
                "In AWS context: implement AC-2/3/6 via IAM policies + permission boundaries + AWS Organizations SCPs. "
                "Implement AC-17 with IAM MFA enforcement policies and AWS SSO with MFA required."
            ),
            "metadata": {"category": "NIST", "severity": "HIGH", "control": "NIST-AC", "source": "NIST 800-53 Rev 5"},
        },
        {
            "id": "nist-ia-identification-authentication",
            "content": (
                "NIST SP 800-53 Rev 5 — IA (Identification and Authentication) Family. "
                "IA-2: Multi-factor authentication for all organizational users (console + API). "
                "IA-3: Device identification — use IAM roles for EC2/Lambda not shared credentials. "
                "IA-5 (Authenticator Management): rotate IAM access keys every 90 days, minimum 14-char passwords. "
                "IA-8: Non-organizational user authentication — control cross-account role assumptions with external ID. "
                "In AWS context: AWS IAM Identity Center (SSO) with MFA required satisfies IA-2. "
                "Use IAM roles with trust policies and external ID conditions for cross-account access (IA-8). "
                "AWS Certificate Manager handles machine-to-machine authentication with TLS certificates."
            ),
            "metadata": {"category": "NIST", "severity": "HIGH", "control": "NIST-IA", "source": "NIST 800-53 Rev 5"},
        },
        {
            "id": "nist-au-audit-accountability",
            "content": (
                "NIST SP 800-53 Rev 5 — AU (Audit and Accountability) Family. "
                "AU-2 (Event Logging): log authentication events, privilege escalation, admin actions, data access. "
                "AU-3 (Content of Audit Records): each log must include timestamp, user, action, resource, outcome. "
                "AU-6 (Audit Review, Analysis, Reporting): review logs weekly, alert on anomalies. "
                "AU-9 (Protection of Audit Information): protect logs from modification or deletion (CloudTrail log validation). "
                "AU-11 (Audit Record Retention): retain logs for at least 90 days online, 1 year archived. "
                "In AWS: CloudTrail (API logs) + CloudWatch Logs (application logs) + VPC Flow Logs (network logs) "
                "covers AU-2/3. S3 versioning + Object Lock covers AU-9. Lifecycle policies to Glacier covers AU-11."
            ),
            "metadata": {"category": "NIST", "severity": "MEDIUM", "control": "NIST-AU", "source": "NIST 800-53 Rev 5"},
        },
        {
            "id": "nist-sc-system-communications",
            "content": (
                "NIST SP 800-53 Rev 5 — SC (System and Communications Protection) Family. "
                "SC-5 (Denial of Service Protection): use AWS Shield Standard (free) and Shield Advanced for DDoS protection. "
                "SC-7 (Boundary Protection): implement VPC with public/private subnet separation, NACLs, security groups. "
                "SC-8 (Transmission Confidentiality/Integrity): enforce TLS 1.2+ for all data in transit. "
                "SC-12 (Cryptographic Key Management): use AWS KMS with automatic rotation. "
                "SC-28 (Protection of Information at Rest): enable SSE-KMS on S3, RDS, EBS, DynamoDB. "
                "In AWS: AWS WAF + Shield covers SC-5. VPC architecture covers SC-7. "
                "ACM-managed TLS certificates cover SC-8. AWS KMS covers SC-12/28."
            ),
            "metadata": {"category": "NIST", "severity": "HIGH", "control": "NIST-SC", "source": "NIST 800-53 Rev 5"},
        },
        {
            "id": "nist-cm-configuration-management",
            "content": (
                "NIST SP 800-53 Rev 5 — CM (Configuration Management) Family. "
                "CM-2 (Baseline Configuration): define and maintain secure baseline configs for all AWS services. "
                "CM-6 (Configuration Settings): enforce CIS AWS Benchmark settings as configuration baseline. "
                "CM-7 (Least Functionality): disable unused AWS services and regions (AWS Organizations SCPs). "
                "CM-8 (Information System Component Inventory): AWS Config maintains a continuous inventory of all resources. "
                "In AWS: AWS Config conformance packs implement CM-2/6. "
                "AWS Organizations SCPs implement CM-7 (deny specific services/regions). "
                "AWS Systems Manager Inventory implements CM-8 for EC2 instances."
            ),
            "metadata": {"category": "NIST", "severity": "MEDIUM", "control": "NIST-CM", "source": "NIST 800-53 Rev 5"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # Incident Response
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "incident-response-compromised-iam",
            "content": (
                "Incident Response — Compromised IAM credentials procedure. "
                "Signs of compromise: CloudTrail shows API calls from unexpected IPs, unusual regions, or new services; "
                "GuardDuty finding: UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B or "
                "CredentialAccess:IAMUser/AnomalousBehavior. "
                "Immediate steps: "
                "1. Revoke all active sessions: aws iam delete-login-profile --user-name USER. "
                "2. Deactivate access keys: aws iam update-access-key --access-key-id KEY --status Inactive. "
                "3. Attach deny-all policy to block further actions while investigating. "
                "4. Check CloudTrail for all API calls made with the compromised credentials (last 90 days). "
                "5. Look for: new IAM users created, S3 buckets modified, EC2 instances launched, route53 changes. "
                "6. Rotate all secrets and keys that the compromised user had access to."
            ),
            "metadata": {"category": "IncidentResponse", "severity": "CRITICAL", "control": "IR-IAM", "source": "AWS Security"},
        },
        {
            "id": "incident-response-data-exfiltration-s3",
            "content": (
                "Incident Response — S3 data exfiltration indicators and response. "
                "Indicators: GuardDuty finding Exfiltration:S3/ObjectRead.Unusual or "
                "Policy:S3/BucketBlockPublicAccessDisabled; "
                "large GetObject API calls from unfamiliar IPs in CloudTrail; "
                "S3 access logs showing bulk downloads. "
                "Immediate steps: "
                "1. Enable S3 Block Public Access immediately (aws s3api put-public-access-block). "
                "2. Review and revoke bucket policies that allow external access. "
                "3. Check CloudTrail S3 data events for the list of objects accessed and by whom. "
                "4. Enable S3 Object Lock on critical buckets to prevent further modification. "
                "5. Use Macie to scan remaining bucket contents and identify what data was exposed. "
                "6. Notify stakeholders per your breach notification policy (GDPR: 72 hours)."
            ),
            "metadata": {"category": "IncidentResponse", "severity": "CRITICAL", "control": "IR-S3", "source": "AWS Security"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # Cloud-Native / Zero Trust Architecture
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "zero-trust-cloud",
            "content": (
                "Zero Trust Security Model for cloud — 'never trust, always verify.' "
                "Traditional perimeter-based security assumes everything inside the VPC is safe. "
                "Zero Trust assumes breach: verify every request regardless of network origin. "
                "AWS implementation: "
                "1. Identity: enforce MFA for all users, use short-lived temporary credentials (STS AssumeRole). "
                "2. Network: micro-segment with security groups, use VPC endpoints for AWS service access (no internet). "
                "3. Workloads: run containers as non-root, use IMDSv2, scan all images with Trivy. "
                "4. Data: encrypt all data at rest (SSE-KMS) and in transit (TLS 1.2+). "
                "5. Visibility: CloudTrail + GuardDuty + Security Hub for continuous monitoring. "
                "6. Automation: AWS Config + EventBridge + Lambda for auto-remediation of violations."
            ),
            "metadata": {"category": "Architecture", "severity": "HIGH", "control": "ZEROTRUST", "source": "NIST 800-207"},
        },
        {
            "id": "shared-responsibility-model",
            "content": (
                "AWS Shared Responsibility Model — defines security ownership boundaries between AWS and customers. "
                "AWS is responsible FOR the cloud: physical infrastructure, hypervisor, managed service availability. "
                "Customer is responsible IN the cloud: OS patching (EC2), application security, IAM configuration, "
                "data encryption, network security (security groups, NACLs), logging and monitoring. "
                "Common misunderstanding: customers assume AWS secures S3 data — it does not secure your bucket ACLs or policies. "
                "AWS manages: global infrastructure, regions, AZs, edge locations, hardware, firmware, hypervisor. "
                "Customer manages: guest OS (EC2), application stack, identity/access, network config, encryption. "
                "For managed services (RDS, Lambda): AWS manages OS/runtime; customer manages IAM, security groups, app code."
            ),
            "metadata": {"category": "Architecture", "severity": "HIGH", "control": "SHARED-RESP", "source": "AWS Docs"},
        },

        # ══════════════════════════════════════════════════════════════════════
        # ShieldScan-Specific (CNAPP context, RAG tuning)
        # ══════════════════════════════════════════════════════════════════════
        {
            "id": "cnapp-cspm-explanation",
            "content": (
                "CSPM (Cloud Security Posture Management) — continuously monitors cloud infrastructure configurations "
                "against security benchmarks (CIS, NIST, SOC 2, PCI-DSS). "
                "CSPM detects: S3 buckets publicly accessible, IAM users without MFA, security groups with open SSH/RDP, "
                "CloudTrail disabled, unencrypted RDS/EBS, root account with active access keys. "
                "ShieldScan CSPM uses boto3 to query AWS APIs and compare findings against CIS AWS Benchmark v3.0. "
                "Risk scoring: CRITICAL=40 pts, HIGH=20 pts, MEDIUM=8 pts, LOW=2 pts, capped at 100. "
                "CSPM is detective (finds existing misconfigs) not preventive — pair with SCPs for prevention. "
                "Typical CSPM finding lifecycle: Detected → Triaged → Remediated → Verified → Closed."
            ),
            "metadata": {"category": "CNAPP", "severity": "INFO", "control": "CSPM-OVERVIEW", "source": "ShieldScan"},
        },
        {
            "id": "cnapp-cwpp-explanation",
            "content": (
                "CWPP (Cloud Workload Protection Platform) — secures running workloads: containers, VMs, serverless. "
                "ShieldScan CWPP uses Trivy to scan container images for CVEs (software vulnerabilities). "
                "Trivy scans: OS packages (alpine/debian/ubuntu), application dependencies (pip, npm, maven), "
                "container config (running as root, secrets in image), IaC config (Dockerfile, K8s manifests). "
                "CVE severity: CRITICAL (CVSS 9.0-10), HIGH (7.0-8.9), MEDIUM (4.0-6.9), LOW (0.1-3.9). "
                "CWPP finding example: CVE-2023-44487 in nginx:1.24 (HTTP/2 Rapid Reset DoS), severity HIGH, "
                "fix: update to nginx:1.25.3. "
                "Remediation priority: always fix CRITICAL first, then HIGH; MEDIUM/LOW can be batched."
            ),
            "metadata": {"category": "CNAPP", "severity": "INFO", "control": "CWPP-OVERVIEW", "source": "ShieldScan"},
        },
        {
            "id": "cnapp-risk-scoring",
            "content": (
                "ShieldScan Risk Score — composite security posture score (0-100, lower is better). "
                "Formula: score += CRITICAL×40 + HIGH×20 + MEDIUM×8 + LOW×2, capped at 100. "
                "Score interpretation: 0-20 (Good — minimal exposure), 21-50 (Fair — some issues to address), "
                "51-80 (Poor — significant risk), 81-100 (Critical — immediate action required). "
                "Risk factors: asset criticality (production vs dev), exposure (internet-facing vs internal), "
                "CVSS score (technical exploitability), fix availability (patch exists vs no fix). "
                "Future: XGBoost ML model will weight factors dynamically based on historical breach data. "
                "Comparison: AWS Security Hub uses 0-100 security score (inverted — higher is better)."
            ),
            "metadata": {"category": "CNAPP", "severity": "INFO", "control": "RISK-SCORE", "source": "ShieldScan"},
        },
        {
            "id": "iam-access-analyzer",
            "content": (
                "AWS IAM Access Analyzer — automatically identifies resource policies that grant access to "
                "external principals (outside your AWS account or organization). "
                "Detects: S3 buckets accessible from external accounts, IAM roles assumable by external accounts, "
                "KMS keys with external access, Lambda functions with external resource-based policies. "
                "Access Analyzer uses formal verification (Zelkova satisfiability solver) not heuristics. "
                "Fix: IAM → Access Analyzer → Review active findings → Update policies to remove unintended external access. "
                "Enable organization-level analyzer to catch cross-account access issues across all accounts. "
                "Integrate findings with Security Hub for centralized tracking and SLA enforcement."
            ),
            "metadata": {"category": "IAM", "severity": "HIGH", "control": "IAM-ANALYZER", "source": "AWS Docs"},
        },
        {
            "id": "secrets-management-aws",
            "content": (
                "AWS Secrets Management — never hardcode credentials; use managed secret stores. "
                "AWS Secrets Manager: stores database passwords, API keys, OAuth tokens with automatic rotation. "
                "AWS Systems Manager Parameter Store (SecureString): lighter-weight option for config values and secrets. "
                "Best practices: use IAM roles to grant applications access to specific secrets — not hardcoded keys. "
                "Enable automatic rotation with Lambda rotation functions (Secrets Manager native for RDS, Redshift, DocumentDB). "
                "Audit secret access with CloudTrail: every GetSecretValue call is logged. "
                "Detect hardcoded secrets in code: git-secrets, truffleHog, Checkov, Semgrep. "
                "Trivy secret scanning: trivy image --scanners secret finds secrets accidentally baked into container layers."
            ),
            "metadata": {"category": "IAM", "severity": "CRITICAL", "control": "SECRETS-MGMT", "source": "AWS Docs"},
        },
    ]

    # Batch add all documents to ChromaDB
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
    except Exception:
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
    except Exception:
        pass  # Log in production


def get_collection_size() -> int:
    """Return number of documents in the knowledge base."""
    try:
        return _get_collection().count()
    except Exception:
        return 0
