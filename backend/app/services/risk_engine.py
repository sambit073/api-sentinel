"""
Centralized Risk Scoring Engine.

Accepts a DetectionResult and converts it to a structured risk assessment.
Keeps scoring logic completely separate from detection logic.
"""
from __future__ import annotations
from typing import Any, Optional

from app.services.detection.base import DetectionResult


# ── Severity thresholds ──────────────────────────────────────────────────────
def score_to_severity(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


# ── Threat-type weight multipliers ───────────────────────────────────────────
# Allows the risk engine to up/down-weight certain threat categories
_THREAT_WEIGHTS: dict[str, float] = {
    "BOLA":          1.0,
    "SQL_INJECTION":  0.95,
    "BROKEN_AUTH":   0.85,
    "RATE_ABUSE":    0.92,   # raised: confirmed burst scores HIGH/CRITICAL
    "SENSITIVE_DATA": 0.80,
    "NORMAL":        0.0,
}


def calculate_risk(result: DetectionResult) -> dict[str, Any]:
    """
    Convert a DetectionResult into a final risk assessment dict.

    Returns:
        {
          "risk_score": float,
          "severity": str,
          "threat_type": str,
          "action": str,          # determined by response_engine
          "reason": str,
          "evidence": dict | None,
          "remediation": str | None,
        }
    """
    if not result.detected:
        return {
            "risk_score": 0.0,
            "severity": "LOW",
            "threat_type": "NONE",
            "action": "ALLOW",
            "reason": result.reason,
            "evidence": None,
            "remediation": None,
        }

    weight = _THREAT_WEIGHTS.get(result.threat_type, 1.0)
    raw_score = result.base_risk_score * weight

    # Clamp to [0, 100]
    risk_score = max(0.0, min(100.0, raw_score))
    severity = score_to_severity(risk_score)

    return {
        "risk_score": round(risk_score, 1),
        "severity": severity,
        "threat_type": result.threat_type,
        "action": None,          # to be filled by response_engine
        "reason": result.reason,
        "evidence": result.evidence,
        "remediation": result.remediation,
    }
