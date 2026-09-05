"""
SQL / NoSQL Injection Detector.

Detects common injection payloads in:
- Query parameters
- Request body fields
- URL path segments
"""
from __future__ import annotations
import re
from typing import Any

from app.services.detection.base import BaseDetector, DetectionResult

# Classic SQL injection patterns
_SQL_PATTERNS = [
    re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|EXECUTE)\b)", re.IGNORECASE),
    re.compile(r"(--|;|/\*|\*/|xp_)", re.IGNORECASE),
    re.compile(r"('\s*(OR|AND)\s*'?\d)", re.IGNORECASE),
    re.compile(r"(1\s*=\s*1|'OR'\s*'1'\s*=\s*'1)", re.IGNORECASE),
    re.compile(r"SLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
]

# NoSQL injection patterns
_NOSQL_PATTERNS = [
    re.compile(r"\$where\s*:", re.IGNORECASE),
    re.compile(r"\$gt\s*:", re.IGNORECASE),
    re.compile(r"\$ne\s*:", re.IGNORECASE),
    re.compile(r"mapReduce", re.IGNORECASE),
]


def _flatten_values(data: Any) -> list[str]:
    """Recursively extract string values from a dict/list for scanning."""
    results: list[str] = []
    if isinstance(data, str):
        results.append(data)
    elif isinstance(data, dict):
        for v in data.values():
            results.extend(_flatten_values(v))
    elif isinstance(data, (list, tuple)):
        for item in data:
            results.extend(_flatten_values(item))
    return results


class InjectionDetector(BaseDetector):
    @property
    def threat_type(self) -> str:
        return "SQL_INJECTION"

    def detect(self, request: dict[str, Any]) -> DetectionResult:
        params: dict = request.get("params") or {}
        body: dict = request.get("body") or {}
        endpoint: str = request.get("endpoint", "")

        candidates = _flatten_values(params) + _flatten_values(body) + [endpoint]

        evidence: dict[str, Any] = {}
        matched_patterns: list[str] = []

        for value in candidates:
            for pattern in _SQL_PATTERNS:
                m = pattern.search(value)
                if m:
                    matched_patterns.append(f"SQL pattern '{m.group()}' in value: {value[:80]}")
                    evidence.setdefault("sql_matches", []).append(value[:80])

            for pattern in _NOSQL_PATTERNS:
                m = pattern.search(value)
                if m:
                    matched_patterns.append(f"NoSQL pattern '{m.group()}' detected.")
                    evidence.setdefault("nosql_matches", []).append(value[:80])

        detected = len(matched_patterns) > 0
        confidence = min(len(matched_patterns) * 0.35, 1.0)
        base_risk = confidence * 90

        return DetectionResult(
            detected=detected,
            threat_type=self.threat_type,
            confidence=confidence,
            base_risk_score=base_risk,
            reason="; ".join(matched_patterns[:3]) if matched_patterns else "No injection indicators found.",
            evidence=evidence if detected else None,
            remediation=(
                "Use parameterised queries or prepared statements exclusively. "
                "Validate and sanitise all user-supplied input server-side. "
                "Apply the principle of least privilege to database accounts."
            ) if detected else None,
        )
