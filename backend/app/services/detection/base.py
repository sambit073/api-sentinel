"""
Abstract base class for all detection modules.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Any


@dataclass
class DetectionResult:
    """Returned by every detector."""
    detected: bool
    threat_type: str
    confidence: float        # 0.0–1.0
    base_risk_score: float   # 0–100 suggested score before final engine normalisation
    reason: str
    evidence: Optional[dict[str, Any]] = None
    remediation: Optional[str] = None


class BaseDetector(ABC):
    """
    All detectors implement this interface.
    Each detector is responsible for ONE threat category only.
    """

    @property
    @abstractmethod
    def threat_type(self) -> str:
        """Unique identifier for the threat this detector handles."""
        ...

    @abstractmethod
    def detect(self, request: dict[str, Any]) -> DetectionResult:
        """
        Analyse a normalised request dict and return a DetectionResult.

        The request dict contains at minimum:
            method, endpoint, source_ip, client_id,
            headers, params, body
        """
        ...
