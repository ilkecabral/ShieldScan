"""
cwpp_service.py — Cloud Workload Protection Platform
Owner: [Teammate 2]

Scans container images for CVEs using Trivy.
Trivy must be installed on the system: https://aquasecurity.github.io/trivy

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INTERFACE CONTRACT — do not change the function signature.
scan_manager.py calls run_cwpp_scan() and expects this exact return shape.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Expected return: list of dicts, each with these keys:
    {
        "finding_id":        str,   # CVE ID e.g. "CVE-2024-1234"
        "finding_type":      str,   # always "CWPP"
        "severity":          str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        "title":             str,   # short description
        "description":       str,   # detailed explanation
        "resource":          str,   # container image name
        "region":            str,   # "container" (not AWS region)
        "fix_recommendation":str,   # how to fix it
        "cve_id":            str,   # same as finding_id for CVEs
        "cvss_score":        float, # CVSS score 0.0-10.0
        "affected_package":  str,   # e.g. "nginx:1.18.0"
        "fixed_version":     str,   # e.g. "1.19.0"
    }
"""

# ── Mock data (used until real implementation is ready) ──────────────────────
MOCK_FINDINGS = [
    {
        "finding_id": "CVE-2021-23017",
        "finding_type": "CWPP",
        "severity": "HIGH",
        "title": "nginx: Off-by-one in DNS resolver",
        "description": "A security issue in nginx resolver was identified that allows an attacker to cause memory disclosure or a 1-byte overwrite, which can result in a crash.",
        "resource": "nginx:1.18-alpine",
        "region": "container",
        "fix_recommendation": "Update nginx base image to 1.21.0 or later in your Dockerfile.",
        "cve_id": "CVE-2021-23017",
        "cvss_score": 7.7,
        "affected_package": "nginx:1.18.0",
        "fixed_version": "1.21.0",
    },
    {
        "finding_id": "CVE-2023-25139",
        "finding_type": "CWPP",
        "severity": "MEDIUM",
        "title": "python: sprintf buffer overflow",
        "description": "Python 3.x through 3.10 has an issue in sprintf in Objects/longobject.c that can lead to a buffer overflow.",
        "resource": "python:3.10-slim",
        "region": "container",
        "fix_recommendation": "Update Python base image to 3.11.2 or later.",
        "cve_id": "CVE-2023-25139",
        "cvss_score": 5.5,
        "affected_package": "python:3.10.0",
        "fixed_version": "3.11.2",
    },
]


# ── Real implementation (Teammate 2 fills this in) ───────────────────────────

USE_MOCK_CWPP = True  # Set to False once real implementation is ready


def run_cwpp_scan(image_name: str) -> list[dict]:
    """
    Scan a container image for CVEs using Trivy.

    Args:
        image_name: Docker image name + tag, e.g. "nginx:1.18-alpine"

    Returns:
        List of finding dicts matching the contract above.

    Requires:
        Trivy installed: brew install trivy  OR  apt install trivy
    """
    if USE_MOCK_CWPP:
        return MOCK_FINDINGS

    # ── TODO: Teammate 2 implements below ────────────────────────────────────
    # import subprocess, json
    #
    # result = subprocess.run(
    #     ["trivy", "image", "--format", "json", "--quiet", image_name],
    #     capture_output=True, text=True
    # )
    # trivy_output = json.loads(result.stdout)
    # findings = []
    # for result_item in trivy_output.get("Results", []):
    #     for vuln in result_item.get("Vulnerabilities", []):
    #         findings.append({
    #             "finding_id": vuln["VulnerabilityID"],
    #             "finding_type": "CWPP",
    #             "severity": vuln["Severity"],
    #             "title": vuln.get("Title", vuln["VulnerabilityID"]),
    #             "description": vuln.get("Description", ""),
    #             "resource": image_name,
    #             "region": "container",
    #             "fix_recommendation": f"Update {vuln['PkgName']} to {vuln.get('FixedVersion', 'latest')}",
    #             "cve_id": vuln["VulnerabilityID"],
    #             "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
    #             "affected_package": f"{vuln['PkgName']}:{vuln['InstalledVersion']}",
    #             "fixed_version": vuln.get("FixedVersion", "unknown"),
    #         })
    # return findings
    raise NotImplementedError("Real CWPP implementation pending — set USE_MOCK_CWPP = True to use mock data")
