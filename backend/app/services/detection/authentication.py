"""
Broken Authentication Detector.

Detects:
- Multiple failed login attempts from the same IP
- Missing or malformed Authorization headers on protected routes
- Use of known weak/default credentials
"""
from __future__ import annotations
import re
from typing import Any

from app.services.detection.base import BaseDetector, DetectionResult

# Protected endpoints that require an Authorization header
_PROTECTED_PATHS = {
    "/api/admin", "/api/users", "/api/profile",
    "/api/settings", "/api/payments", "/api/orders",
}

_WEAK_CREDENTIALS = {"admin", "password", "123456", "test", "guest", "root"}


class AuthenticationDetector(BaseDetector):
    @property
    def threat_type(self) -> str:
        return "BROKEN_AUTH"

    def detect(self, request: dict[str, Any]) -> DetectionResult:
        endpoint: str = request.get("endpoint", "")
        headers: dict = request.get("headers") or {}
        body: dict = request.get("body") or {}
        status_code: int = request.get("status_code", 200)

        evidence: dict[str, Any] = {}
        reasons: list[str] = []

        # Check 1 – missing auth header on a protected route
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        is_protected = any(endpoint.startswith(p) for p in _PROTECTED_PATHS)
        if is_protected and not auth_header:
            reasons.append("Missing Authorization header on a protected endpoint.")
            evidence["missing_auth_header"] = True

        # Check 2 – malformed bearer token
        if auth_header and not re.match(r"^Bearer\s+\S{10,}$", auth_header):
            reasons.append("Malformed or suspiciously short Authorization token.")
            evidence["malformed_token"] = auth_header[:30]

        # Check 3 – weak credentials in request body
        username = str(body.get("username", "")).lower()
        password = str(body.get("password", "")).lower()
        if username in _WEAK_CREDENTIALS or password in _WEAK_CREDENTIALS:
            reasons.append("Weak or default credential values detected.")
            evidence["weak_credential"] = {"username": username}

        # Check 4 – 401/403 on a login endpoint signals a failed auth attempt
        if status_code in (401, 403) and "login" in endpoint:
            reasons.append("Authentication failure response code on login endpoint.")
            evidence["status_code"] = status_code

        detected = len(reasons) > 0
        confidence = min(len(reasons) * 0.5, 1.0)
        base_risk = confidence * 75  # max 75 for broken auth

        return DetectionResult(
            detected=detected,
            threat_type=self.threat_type,
            confidence=confidence,
            base_risk_score=base_risk,
            reason=" ".join(reasons) if reasons else "No broken authentication indicators found.",
            evidence=evidence if detected else None,
            remediation=(
                "Enforce strong authentication on all protected routes. "
                "Use long-lived, cryptographically signed tokens. "
                "Implement account lockout after repeated failures."
            ) if detected else None,
        )
