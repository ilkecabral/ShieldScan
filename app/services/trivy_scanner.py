import json
import subprocess
from enum import Enum
from pathlib import Path
from uuid import uuid4


class ScanType(str, Enum):
    IMAGE = "image"
    FS = "fs"
    CONFIG = "config"


class TrivyScanError(Exception):
    pass


REPORTS_DIR = Path("trivy-reports")
REPORTS_DIR.mkdir(exist_ok=True)


def run_trivy_scan(target: str, scan_type: ScanType, severity: str = "HIGH,CRITICAL") -> dict:
    """
    Runs a Trivy scan against a target and returns the parsed JSON report.
    target examples:
      - image scan: "myapp:latest"
      - fs scan: "./app"
      - config scan: "./infra/terraform"
    """
    scan_id = str(uuid4())
    output_file = REPORTS_DIR / f"{scan_type.value}-{scan_id}.json"

    cmd = [
        "trivy", scan_type.value,
        "--format", "json",
        "--output", str(output_file),
        "--severity", severity,
        target,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode not in (0, 1):
        raise TrivyScanError(f"Trivy failed: {result.stderr}")

    with open(output_file) as f:
        report = json.load(f)

    return {
        "scan_id": scan_id,
        "scan_type": scan_type.value,
        "target": target,
        "report_path": str(output_file),
        "results": report,
    }
