"""
Sensitive Data Exposure Detector.

Detects:
- API responses that appear to leak PII (SSN, credit card, etc.)
- Requests that target known data-heavy endpoints with overly broad queries
- Presence of sensitive field names in request/response bodies
"""
from __future__ import annotations
import re
from typing import Any

from app.services.detection.base import BaseDetector, DetectionResult

_PII_PATTERNS = {
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
}

_SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "ssn", "social_security", "credit_card", "cc_number", "cvv",
    "private_key", "access_token", "refresh_token",
}

_SENSITIVE_ENDPOINTS = {
    "/api/users", "/api/admin", "/api/payments",
    "/api/export", "/api/dump", "/api/backup",
}


def _flatten_keys(data: Any) -> set[str]:
    """Recursively collect all dict keys."""
    keys: set[str] = set()
    if isinstance(data, dict):
        for k, v in data.items():
            keys.add(k.lower())
            keys |= _flatten_keys(v)
    elif isinstance(data, (list, tuple)):
        for item in data:
            keys |= _flatten_keys(item)
    return keys


class SensitiveDataDetector(BaseDetector):
    @property
    def threat_type(self) -> str:
        return "SENSITIVE_DATA"

    def detect(self, request: dict[str, Any]) -> DetectionResult:
        endpoint: str = request.get("endpoint", "")
        params: dict = request.get("params") or {}
        body: dict = request.get("body") or {}

        evidence: dict[str, Any] = {}
        reasons: list[str] = []

        # Combine all content for scanning
        content_str = str(params) + " " + str(body)

        # Check 1 – PII patterns in content
        for pii_type, pattern in _PII_PATTERNS.items():
            match = pattern.search(content_str)
            if match:
                reasons.append(f"Potential {pii_type.replace('_', ' ').upper()} pattern detected in request content.")
                evidence[pii_type] = "REDACTED"

        # Check 2 – sensitive field names in body/params keys
        all_keys = _flatten_keys(body) | _flatten_keys(params)
        exposed_fields = all_keys & _SENSITIVE_FIELD_NAMES
        if exposed_fields:
            reasons.append(f"Sensitive field names present in request: {', '.join(sorted(exposed_fields))}.")
            evidence["sensitive_fields"] = list(sorted(exposed_fields))

        # Check 3 – access to a known sensitive endpoint
        if any(endpoint.startswith(p) for p in _SENSITIVE_ENDPOINTS):
            reasons.append(f"Request targets a sensitive data endpoint: {endpoint}.")
            evidence["sensitive_endpoint"] = endpoint

        detected = len(reasons) > 0
        confidence = min(len(reasons) * 0.3, 1.0)
        base_risk = confidence * 80

        return DetectionResult(
            detected=detected,
            threat_type=self.threat_type,
            confidence=confidence,
            base_risk_score=base_risk,
            reason=" ".join(reasons) if reasons else "No sensitive data exposure indicators found.",
            evidence=evidence if detected else None,
            remediation=(
                "Never expose raw PII in API responses or logs. "
                "Apply field-level encryption for sensitive data at rest. "
                "Implement response filtering to strip sensitive fields for unprivileged clients."
            ) if detected else None,
        )
