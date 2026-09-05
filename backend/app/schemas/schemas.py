"""
Pydantic schemas for request/response validation.
"""
from __future__ import annotations
import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict


# ──────────────────────────────────────────────
# API Request schemas
# ──────────────────────────────────────────────

class ApiRequestBase(BaseModel):
    method: str
    endpoint: str
    source_ip: str
    client_id: Optional[str] = None
    status_code: int
    response_time_ms: float
    request_params: Optional[str] = None
    request_body: Optional[str] = None
    threat_type: Optional[str] = None
    risk_score: Optional[float] = None
    severity: Optional[str] = None
    action: Optional[str] = None


class ApiRequestOut(ApiRequestBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime.datetime


# ──────────────────────────────────────────────
# Security Event schemas
# ──────────────────────────────────────────────

class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    request_id: int
    timestamp: datetime.datetime
    threat_type: str
    severity: str
    risk_score: float
    action: str
    reason: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None

    # Enrichment from joined request
    method: Optional[str] = None
    endpoint: Optional[str] = None
    source_ip: Optional[str] = None
    client_id: Optional[str] = None


# ──────────────────────────────────────────────
# Endpoint schemas
# ──────────────────────────────────────────────

class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    path: str
    methods: str
    total_requests: int
    threat_count: int
    avg_risk_score: float
    security_status: str
    last_seen: Optional[datetime.datetime] = None


# ──────────────────────────────────────────────
# Dashboard summary
# ──────────────────────────────────────────────

class DashboardSummary(BaseModel):
    total_requests: int
    threats_detected: int
    requests_blocked: int
    critical_threats: int
    api_security_score: int
    protection_status: str
    traffic_over_time: list[dict[str, Any]]
    severity_distribution: list[dict[str, Any]]
    threat_type_distribution: list[dict[str, Any]]
    recent_events: list[dict[str, Any]]


# ──────────────────────────────────────────────
# Simulate / Analyze
# ──────────────────────────────────────────────

class SimulateRequest(BaseModel):
    scenario: str  # BOLA, SQL_INJECTION, BRUTE_FORCE, BROKEN_AUTH, SENSITIVE_DATA, NORMAL


class AnalyzeRequest(BaseModel):
    method: str
    endpoint: str
    source_ip: str
    client_id: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    params: Optional[dict[str, Any]] = None
    body: Optional[dict[str, Any]] = None


class RiskResult(BaseModel):
    risk_score: float
    severity: str
    threat_type: str
    action: str
    reason: str
    evidence: Optional[dict[str, Any]] = None
    remediation: Optional[str] = None
