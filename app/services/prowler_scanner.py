import json
import subprocess
from enum import Enum
from pathlib import Path
from uuid import uuid4


class ScanCategory(str, Enum):
    S3 = "s3"
    IAM = "iam"
    EC2 = "ec2"
    RDS = "rds"
    VPC = "vpc"
    ALL = "all"


# Map categories to Prowler service groups
CATEGORY_TO_SERVICES = {
    ScanCategory.S3: ["s3"],
    ScanCategory.IAM: ["iam", "accessanalyzer"],
    ScanCategory.EC2: ["ec2", "securityhub"],
    ScanCategory.RDS: ["rds"],
    ScanCategory.VPC: ["vpc", "networkfirewall"],
    ScanCategory.ALL: [],
}


class ProwlerScanError(Exception):
    pass


REPORTS_DIR = Path("prowler-reports")
REPORTS_DIR.mkdir(exist_ok=True)


def run_prowler_scan(
    role_arn: str,
    category: ScanCategory = ScanCategory.ALL,
    severity: str = "critical high",
    region: str = "us-east-1",
) -> dict:
    """
    Runs a Prowler CSPM scan against an AWS account via cross-account role assumption.
    
    Args:
        role_arn: ARN of the read-only IAM role in the target account
        category: Which AWS service category to scan
        severity: Space-separated severity levels to include
        region: AWS region to scan
    """
    scan_id = str(uuid4())
    output_dir = REPORTS_DIR / scan_id
    output_dir.mkdir(exist_ok=True)

    cmd = [
        "prowler", "aws",
        "--role", role_arn,
        "--output-formats", "json-ocsf",
        "--output-directory", str(output_dir),
        "--severity", severity,
        "--region", region,
        "--status", "FAIL",
    ]

    services = CATEGORY_TO_SERVICES.get(category, [])
    if services:
        cmd.extend(["--services"] + services)

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode not in (0, 1, 2):
        raise ProwlerScanError(f"Prowler failed: {result.stderr}")

    findings = []
    for json_file in output_dir.glob("*.json"):
        with open(json_file) as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    findings.extend(data)
                else:
                    findings.append(data)
            except json.JSONDecodeError:
                continue

    summary = {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL"),
        "high": sum(1 for f in findings if f.get("severity", "").upper() == "HIGH"),
        "medium": sum(1 for f in findings if f.get("severity", "").upper() == "MEDIUM"),
    }

    return {
        "scan_id": scan_id,
        "category": category.value,
        "role_arn": role_arn,
        "region": region,
        "report_dir": str(output_dir),
        "summary": summary,
        "findings": findings,
    }
