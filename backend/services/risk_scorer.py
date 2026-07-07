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

USE_MOCK_SCORER = True  # Set to False once XGBoost model is ready

# Severity weights for the mock scorer
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
    raw = sum(_SEVERITY_WEIGHTS.get(f.get("severity", "LOW"), 2) for f in findings)
    return round(min(float(raw), 100.0), 1)


def score_findings(findings: list[dict]) -> float:
    """
    Score a list of findings and return a risk score between 0.0 and 100.0.

    Args:
        findings: Combined list of CSPM + CWPP finding dicts.
                  Each dict has at minimum: finding_id, severity, finding_type.

    Returns:
        float between 0.0 (no risk) and 100.0 (critical risk).
    """
    if USE_MOCK_SCORER:
        return _mock_score(findings)

    # ── TODO: Teammate 3 implements below ────────────────────────────────────
    # import xgboost as xgb
    # import numpy as np
    #
    # Feature engineering from findings list:
    # - critical_count, high_count, medium_count, low_count
    # - cspm_count, cwpp_count
    # - max_cvss_score
    # - has_public_s3, has_open_ssh, has_root_key (bool flags)
    #
    # model = xgb.Booster()
    # model.load_model("services/risk_model.json")
    # features = _extract_features(findings)
    # dmatrix = xgb.DMatrix(np.array([features]))
    # score = float(model.predict(dmatrix)[0])
    # return round(min(max(score, 0.0), 100.0), 1)
    raise NotImplementedError("XGBoost scorer pending — set USE_MOCK_SCORER = True to use weighted mock")
