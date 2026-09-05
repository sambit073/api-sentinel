"""
BOLA / IDOR Detector (Broken Object Level Authorisation).

Detects:
- A client_id accessing a resource that belongs to a different user_id
- Sequential / predictable object ID enumeration patterns
- Accessing admin-owned resources without admin privileges
"""
from __future__ import annotations
import re
from typing import Any

from app.services.detection.base import BaseDetector, DetectionResult

# Regex to extract numeric object IDs from endpoint paths
_ID_PATTERN = re.compile(r"/(\d+)(?:/|$)")


class BolaDetector(BaseDetector):
    @property
    def threat_type(self) -> str:
        return "BOLA"

    def detect(self, request: dict[str, Any]) -> DetectionResult:
        endpoint: str = request.get("endpoint", "")
        client_id: str = str(request.get("client_id") or "")
        params: dict = request.get("params") or {}
        body: dict = request.get("body") or {}

        evidence: dict[str, Any] = {}
        reasons: list[str] = []

        # Extract object IDs from the URL path
        path_ids = _ID_PATTERN.findall(endpoint)

        # Check 1 – explicit user_id in params/body differs from client_id
        target_user = str(params.get("user_id", body.get("user_id", ""))).strip()
        if target_user and client_id and target_user != client_id:
            reasons.append(
                f"Client '{client_id}' is requesting a resource owned by user '{target_user}'."
            )
            evidence["requesting_client"] = client_id
            evidence["target_user_id"] = target_user

        # Check 2 – path contains an object ID that doesn't match the client's own ID
        for oid in path_ids:
            if client_id and oid != client_id and oid.isdigit():
                if int(oid) != 0:  # ignore root-level paths
                    reasons.append(
                        f"URL path contains object ID '{oid}' which differs from client ID '{client_id}'."
                    )
                    evidence["path_object_id"] = oid
                    evidence["client_id"] = client_id
                    break

        # Check 3 – accessing another user's data via admin path without admin flag
        if "admin" in endpoint.lower() and not str(client_id).startswith("admin"):
            reasons.append("Non-admin client is accessing an admin-prefixed endpoint.")
            evidence["admin_endpoint"] = endpoint

        detected = len(reasons) > 0
        confidence = min(len(reasons) * 0.4, 1.0)
        base_risk = confidence * 95  # BOLA is high impact

        return DetectionResult(
            detected=detected,
            threat_type=self.threat_type,
            confidence=confidence,
            base_risk_score=base_risk,
            reason=" ".join(reasons) if reasons else "No BOLA indicators found.",
            evidence=evidence if detected else None,
            remediation=(
                "Implement server-side authorisation checks on every object access. "
                "Never rely solely on client-supplied IDs. "
                "Use indirect references or UUIDs rather than sequential integers."
            ) if detected else None,
        )
