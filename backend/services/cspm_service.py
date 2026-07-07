"""
cspm_service.py — Cloud Security Posture Management
Owner: [Teammate 1]

Scans AWS account for misconfigurations using boto3.
Checks: S3, IAM, Security Groups, RDS, CloudTrail, EC2, VPC, KMS.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INTERFACE CONTRACT — do not change the function signature.
scan_manager.py calls run_cspm_scan() and expects this exact return shape.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Expected return: list of dicts, each with these keys:
    {
        "finding_id":        str,   # e.g. "CSPM-001"
        "finding_type":      str,   # always "CSPM"
        "severity":          str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        "title":             str,   # short description
        "description":       str,   # detailed explanation
        "resource":          str,   # AWS resource ID or ARN
        "region":            str,   # e.g. "us-east-1"
        "fix_recommendation":str,   # how to fix it
    }
"""

# ── Mock data (used until real implementation is ready) ──────────────────────
# scan_manager.py uses this mock when USE_MOCK_CSPM = True
MOCK_FINDINGS = [
    {
        "finding_id": "CSPM-001",
        "finding_type": "CSPM",
        "severity": "CRITICAL",
        "title": "S3 bucket is publicly accessible",
        "description": "S3 bucket 'my-app-data' has public access enabled, exposing all objects to the internet.",
        "resource": "arn:aws:s3:::my-app-data",
        "region": "us-east-1",
        "fix_recommendation": "Enable S3 Block Public Access on the bucket. Go to S3 → Bucket → Permissions → Block public access.",
    },
    {
        "finding_id": "CSPM-002",
        "finding_type": "CSPM",
        "severity": "CRITICAL",
        "title": "Root account has active access keys",
        "description": "The AWS root account has active programmatic access keys. Root keys have unrestricted access.",
        "resource": "arn:aws:iam::123456789:root",
        "region": "global",
        "fix_recommendation": "Delete root access keys immediately from IAM → Security credentials.",
    },
    {
        "finding_id": "CSPM-003",
        "finding_type": "CSPM",
        "severity": "HIGH",
        "title": "Security group allows unrestricted SSH (port 22)",
        "description": "Security group 'sg-0abc123' allows inbound SSH from 0.0.0.0/0 (entire internet).",
        "resource": "sg-0abc123def456",
        "region": "us-east-1",
        "fix_recommendation": "Restrict port 22 to your specific IP or corporate VPN CIDR in the security group inbound rules.",
    },
]


# ── Real implementation (Teammate 1 fills this in) ───────────────────────────

USE_MOCK_CSPM = True  # Set to False once real implementation is ready


def run_cspm_scan(
    aws_access_key: str,
    aws_secret_key: str,
    region: str = "us-east-1",
) -> list[dict]:
    """
    Run a CSPM scan against an AWS account.

    Args:
        aws_access_key: Decrypted AWS access key ID
        aws_secret_key: Decrypted AWS secret access key
        region: AWS region to scan (default: us-east-1)

    Returns:
        List of finding dicts matching the contract above.
    """
    if USE_MOCK_CSPM:
        return MOCK_FINDINGS

    # ── TODO: Teammate 1 implements below ────────────────────────────────────
    # import boto3
    #
    # session = boto3.Session(
    #     aws_access_key_id=aws_access_key,
    #     aws_secret_access_key=aws_secret_key,
    #     region_name=region,
    # )
    #
    # findings = []
    # findings += _check_s3(session)
    # findings += _check_iam(session)
    # findings += _check_security_groups(session, region)
    # findings += _check_cloudtrail(session)
    # findings += _check_rds(session, region)
    # return findings
    raise NotImplementedError("Real CSPM implementation pending — set USE_MOCK_CSPM = True to use mock data")
