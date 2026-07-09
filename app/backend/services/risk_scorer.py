"""
risk_scorer.py — XGBoost Risk Scoring
Owner: [Teammate 3]

Takes all findings from a scan and produces a single risk score (0–100).
Higher score = more critical security posture.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INTERFACE CONTRACT — do not change the function signature.
scan_manager.py calls score_findings() and expects a float 0.0–100.0.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

USE_MOCK_SCORER = False  # Changed to False since we are using the heuristic model now

# Severity weights for the heuristic scorer
_SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 8,
    "LOW": 2,
    "INFO": 0,
}


def _mock_score(findings: list[dict]) -> float:
    """
    Simple weighted score used until XGBoost model is ready.
    Score = min(sum of severity weights, 100)
    """
    if not findings:
        return 0.0
    raw = sum(_SEVERITY_WEIGHTS.get(str(f.get("severity", "LOW")).upper(), 2) for f in findings)
    return round(min(float(raw), 100.0), 1)


def score_findings(findings: list[dict]) -> float:
    """
    Score a list of findings and return a risk score between 0.0 and 100.0.

    Args:
        findings: Combined list of CSPM + CWPP finding dicts.

    Returns:
        float between 0.0 (no risk) and 100.0 (critical risk).
    """
    if USE_MOCK_SCORER:
        return _mock_score(findings)

    if not findings:
        return 0.0

    # ── Heuristic Risk Scorer ────────────────────────────────────────────────
    # We calculate a dynamic score based on the highest severity present,
    # the sheer volume of issues, and the average CVSS score.
    # This replaces the XGBoost model for the school presentation.
    
    critical_count = sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH")
    medium_count = sum(1 for f in findings if str(f.get("severity")).upper() == "MEDIUM")
    
    cvss_scores = [float(f.get("cvss_score", 0)) for f in findings if f.get("cvss_score")]
    max_cvss = max(cvss_scores) if cvss_scores else 0.0

    base_score = 0.0
    
    # Base score determined by the worst vulnerability present
    if critical_count > 0:
        base_score = 80.0
    elif high_count > 0:
        base_score = 60.0
    elif medium_count > 0:
        base_score = 30.0
    else:
        base_score = 10.0

    # Additive penalties for sheer volume of issues
    volume_penalty = (critical_count * 5.0) + (high_count * 2.5) + (medium_count * 0.5)
    
    # CVSS modifier: if max CVSS is very high, bump the score further
    cvss_modifier = (max_cvss * 2.0) if max_cvss > 7.0 else 0.0

    final_score = base_score + volume_penalty + cvss_modifier
    
    # Cap at 100.0
    return round(min(final_score, 100.0), 1)
