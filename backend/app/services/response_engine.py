"""
Response / Action Decision Engine.

Decides what action to take based on the risk score and severity.
Completely separate from risk calculation so policies can be changed independently.
"""
from __future__ import annotations
from typing import Any


# ── Action thresholds ────────────────────────────────────────────────────────
_BLOCK_THRESHOLD     = 80   # CRITICAL  → BLOCK
_CHALLENGE_THRESHOLD = 60   # HIGH      → CHALLENGE
_MONITOR_THRESHOLD   = 30   # MEDIUM    → MONITOR
# Below 30                  # LOW       → ALLOW


def decide_action(risk_assessment: dict[str, Any]) -> str:
    """
    Given a risk assessment dict (from risk_engine.calculate_risk),
    return the appropriate response action string.

    Actions:
        BLOCK      – request is rejected; connection may be terminated
        CHALLENGE  – MFA / CAPTCHA challenge is injected before proceeding
        MONITOR    – request is allowed but logged with elevated alerting
        ALLOW      – request proceeds normally
    """
    risk_score: float = risk_assessment.get("risk_score", 0.0)

    if risk_score >= _BLOCK_THRESHOLD:
        return "BLOCK"
    if risk_score >= _CHALLENGE_THRESHOLD:
        return "CHALLENGE"
    if risk_score >= _MONITOR_THRESHOLD:
        return "MONITOR"
    return "ALLOW"


def apply_action(risk_assessment: dict[str, Any]) -> dict[str, Any]:
    """
    Mutates risk_assessment in-place: fills the 'action' field.
    Returns the updated dict for convenience.
    """
    risk_assessment["action"] = decide_action(risk_assessment)
    return risk_assessment
