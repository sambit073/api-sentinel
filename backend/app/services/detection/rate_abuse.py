"""
Rate Abuse / Brute Force Detector.

Uses a simple in-memory sliding-window counter per (source_ip, endpoint).
For a production system this would be backed by Redis.

Detects:
- Rapid repeated requests to the same endpoint from one IP
- High volume of 401/403 responses (credential stuffing)
- Abnormal request velocity
"""
from __future__ import annotations
import time
from collections import defaultdict, deque
from typing import Any

from app.services.detection.base import BaseDetector, DetectionResult

# Configuration
_WINDOW_SECONDS = 60          # look-back window
_THRESHOLD_GENERAL = 60       # requests/min before flagging
_THRESHOLD_AUTH = 10          # auth-failure requests/min before flagging


class _SlidingWindow:
    """Simple in-process sliding-window request tracker."""

    def __init__(self):
        self._store: dict[str, deque[float]] = defaultdict(deque)

    def record(self, key: str) -> int:
        """Record a request and return the current count within the window."""
        now = time.time()
        dq = self._store[key]
        dq.append(now)
        cutoff = now - _WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)


_window = _SlidingWindow()


class RateAbuseDetector(BaseDetector):
    @property
    def threat_type(self) -> str:
        return "RATE_ABUSE"

    def detect(self, request: dict[str, Any]) -> DetectionResult:
        source_ip: str = request.get("source_ip", "0.0.0.0")
        endpoint: str = request.get("endpoint", "/")
        status_code: int = request.get("status_code", 200)

        general_key = f"{source_ip}::{endpoint}"
        auth_key = f"{source_ip}::auth_fail"

        general_count = _window.record(general_key)
        auth_fail_count = 0
        if status_code in (401, 403):
            auth_fail_count = _window.record(auth_key)

        evidence: dict[str, Any] = {
            "source_ip": source_ip,
            "endpoint": endpoint,
            "time_window_seconds": _WINDOW_SECONDS,
            "requests_in_window": general_count,
        }
        if auth_fail_count > 0:
            evidence["auth_failures_in_window"] = auth_fail_count

        reasons: list[str] = []

        if general_count > _THRESHOLD_GENERAL:
            reasons.append(
                f"{general_count} requests to '{endpoint}' from {source_ip} "
                f"within {_WINDOW_SECONDS} seconds — exceeds the threshold of {_THRESHOLD_GENERAL}."
            )

        if auth_fail_count > _THRESHOLD_AUTH:
            reasons.append(
                f"{auth_fail_count} failed authentication attempts detected from {source_ip} "
                f"to '{endpoint}' within {_WINDOW_SECONDS} seconds, indicating possible "
                f"brute-force or credential-stuffing activity."
            )

        detected = len(reasons) > 0

        # Scale risk proportionally to how far over threshold we are
        if detected:
            excess_ratio = max(
                general_count / _THRESHOLD_GENERAL,
                auth_fail_count / max(_THRESHOLD_AUTH, 1),
            )
            base_risk = min(excess_ratio * 70, 92)   # cap at 92; weight in risk_engine scales final score
            confidence = min(excess_ratio * 0.55, 1.0)
        else:
            base_risk = 0.0
            confidence = 0.0

        return DetectionResult(
            detected=detected,
            threat_type=self.threat_type,
            confidence=confidence,
            base_risk_score=base_risk,
            reason=" ".join(reasons) if reasons else "Request rate within normal limits.",
            evidence=evidence if detected else None,
            remediation=(
                "Apply per-IP rate limiting on authentication endpoints (e.g. max 5 attempts/min). "
                "Introduce progressive delays after repeated failures (exponential back-off). "
                "Temporarily block the source IP after exceeding the failure threshold. "
                "Require CAPTCHA or step-up MFA after a configurable number of failures. "
                "Monitor and alert on sustained patterns of authentication failures across IPs."
            ) if detected else None,
        )

