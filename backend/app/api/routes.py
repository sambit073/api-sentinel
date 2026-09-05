"""
All API route handlers for API Sentinel.
"""
from __future__ import annotations
import datetime
import json
import random
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.models import ApiRequest, SecurityEvent, Endpoint
from app.schemas.schemas import (
    ApiRequestOut, SecurityEventOut, EndpointOut,
    DashboardSummary, SimulateRequest, AnalyzeRequest, RiskResult,
)
from app.services.detection import (
    AuthenticationDetector, BolaDetector, InjectionDetector,
    RateAbuseDetector, SensitiveDataDetector,
)
from app.services.risk_engine import calculate_risk
from app.services.response_engine import apply_action

router = APIRouter()

# ── Detector registry ─────────────────────────────────────────────────────────
_DETECTORS = [
    AuthenticationDetector(),
    BolaDetector(),
    InjectionDetector(),
    RateAbuseDetector(),
    SensitiveDataDetector(),
]


def _run_pipeline(request_dict: dict[str, Any]) -> dict[str, Any]:
    """Run all detectors, pick the highest-risk result, score it, decide action."""
    best_result = None
    best_risk: dict[str, Any] = {"risk_score": 0.0}

    for detector in _DETECTORS:
        result = detector.detect(request_dict)
        if result.detected:
            risk = calculate_risk(result)
            if risk["risk_score"] > best_risk.get("risk_score", 0):
                best_result = result
                best_risk = risk

    if best_result is None:
        # No threat detected
        from app.services.detection.base import DetectionResult
        dummy = DetectionResult(
            detected=False, threat_type="NONE",
            confidence=0, base_risk_score=0,
            reason="No threat indicators found."
        )
        best_risk = calculate_risk(dummy)

    apply_action(best_risk)
    return best_risk


# ── Simulate scenario payloads ────────────────────────────────────────────────
_SCENARIO_MAP: dict[str, dict[str, Any]] = {
    "BOLA": {
        "method": "GET",
        "endpoint": "/api/users/42",
        "source_ip": "185.220.101.42",
        "client_id": "user_99",
        "headers": {},
        "params": {"user_id": "42"},
        "body": {},
        "status_code": 200,
        "response_time_ms": 85.0,
    },
    "SQL_INJECTION": {
        "method": "GET",
        "endpoint": "/api/search",
        "source_ip": "45.33.32.156",
        "client_id": "anonymous",
        "headers": {},
        "params": {"q": "' OR '1'='1; DROP TABLE users--"},
        "body": {},
        "status_code": 400,
        "response_time_ms": 22.0,
    },
    "BRUTE_FORCE": {
        "method": "POST",
        "endpoint": "/api/login",
        "source_ip": "198.51.100.7",
        "client_id": "anonymous",
        "headers": {},
        "params": {},
        "body": {"username": "admin", "password": "password123"},
        "status_code": 401,
        "response_time_ms": 310.0,
    },
    "BROKEN_AUTH": {
        "method": "GET",
        "endpoint": "/api/admin",
        "source_ip": "203.0.113.99",
        "client_id": "admin_guest",   # starts with "admin" so BOLA check 3 skips; malformed token still flags BROKEN_AUTH
        "headers": {"Authorization": "Bearer bad"},
        "params": {},
        "body": {},
        "status_code": 403,
        "response_time_ms": 55.0,
    },
    "SENSITIVE_DATA": {
        "method": "POST",
        "endpoint": "/api/payments",
        "source_ip": "192.168.1.99",
        "client_id": "user_99",
        "headers": {},
        "params": {},
        "body": {"ssn": "123-45-6789", "credit_card": "4111111111111111", "cvv": "999"},
        "status_code": 200,
        "response_time_ms": 145.0,
    },
    "NORMAL": {
        "method": "GET",
        "endpoint": "/api/products",
        "source_ip": "192.168.1.10",
        "client_id": "user_1",
        "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid"},
        "params": {"page": "1"},
        "body": {},
        "status_code": 200,
        "response_time_ms": 68.0,
    },
}


# ── Health ─────────────────────────────────────────────────────────────────────
@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "API Sentinel",
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }


# ── Dashboard Summary ─────────────────────────────────────────────────────────
@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db)):
    total_requests = db.query(ApiRequest).count()
    threats_detected = db.query(SecurityEvent).count()
    requests_blocked = db.query(ApiRequest).filter(ApiRequest.action == "BLOCK").count()
    critical_threats = db.query(SecurityEvent).filter(SecurityEvent.severity == "CRITICAL").count()

    # Security score: starts at 100, penalised by threat ratio and critical count
    # Uses softer weighting so demo data produces a meaningful (non-zero) score
    threat_ratio = threats_detected / max(total_requests, 1)
    penalty = (threat_ratio * 60) + (critical_threats * 0.5)
    api_security_score = max(10, round(100 - penalty))
    api_security_score = min(api_security_score, 100)

    protection_status = (
        "CRITICAL" if api_security_score < 40 else
        "AT_RISK"  if api_security_score < 70 else
        "PROTECTED"
    )

    # Traffic over time — last 24 hours in 1-hour buckets
    now = datetime.datetime.utcnow()
    traffic_over_time = []
    for h in range(23, -1, -1):
        bucket_start = now - datetime.timedelta(hours=h + 1)
        bucket_end   = now - datetime.timedelta(hours=h)
        label = bucket_end.strftime("%H:%M")
        count = db.query(ApiRequest).filter(
            ApiRequest.timestamp >= bucket_start,
            ApiRequest.timestamp < bucket_end,
        ).count()
        threat_count = db.query(ApiRequest).filter(
            ApiRequest.timestamp >= bucket_start,
            ApiRequest.timestamp < bucket_end,
            ApiRequest.threat_type.isnot(None),
        ).count()
        traffic_over_time.append({"time": label, "requests": count, "threats": threat_count})

    # Severity distribution
    severity_counts = (
        db.query(SecurityEvent.severity, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.severity)
        .all()
    )
    severity_distribution = [
        {"name": s, "value": c} for s, c in severity_counts
    ]

    # Threat type distribution
    type_counts = (
        db.query(SecurityEvent.threat_type, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.threat_type)
        .all()
    )
    threat_type_distribution = [
        {"name": t, "value": c} for t, c in type_counts
    ]

    # Recent events (last 10)
    recent = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
        .all()
    )
    recent_events = []
    for evt in recent:
        req = evt.request
        recent_events.append({
            "id": evt.id,
            "severity": evt.severity,
            "threat_type": evt.threat_type,
            "endpoint": req.endpoint if req else "",
            "timestamp": evt.timestamp.isoformat(),
            "risk_score": evt.risk_score,
            "action": evt.action,
            "source_ip": req.source_ip if req else "",
        })

    return DashboardSummary(
        total_requests=total_requests,
        threats_detected=threats_detected,
        requests_blocked=requests_blocked,
        critical_threats=critical_threats,
        api_security_score=api_security_score,
        protection_status=protection_status,
        traffic_over_time=traffic_over_time,
        severity_distribution=severity_distribution,
        threat_type_distribution=threat_type_distribution,
        recent_events=recent_events,
    )


# ── Requests ──────────────────────────────────────────────────────────────────
@router.get("/requests")
def list_requests(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    method: str | None = None,
    action: str | None = None,
    has_threat: bool | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(ApiRequest).order_by(ApiRequest.timestamp.desc())

    if severity:
        q = q.filter(ApiRequest.severity == severity.upper())
    if method:
        q = q.filter(ApiRequest.method == method.upper())
    if action:
        q = q.filter(ApiRequest.action == action.upper())
    if has_threat is True:
        q = q.filter(ApiRequest.threat_type.isnot(None))
    elif has_threat is False:
        q = q.filter(ApiRequest.threat_type.is_(None))

    total = q.count()
    items = q.offset(offset).limit(limit).all()

    return {
        "total": total,
        "items": [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat(),
                "method": r.method,
                "endpoint": r.endpoint,
                "source_ip": r.source_ip,
                "client_id": r.client_id,
                "status_code": r.status_code,
                "response_time_ms": r.response_time_ms,
                "threat_type": r.threat_type,
                "risk_score": r.risk_score,
                "severity": r.severity,
                "action": r.action,
            }
            for r in items
        ],
    }


# ── Threats ───────────────────────────────────────────────────────────────────
@router.get("/threats")
def list_threats(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    threat_type: str | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc())

    if severity:
        q = q.filter(SecurityEvent.severity == severity.upper())
    if threat_type:
        q = q.filter(SecurityEvent.threat_type == threat_type.upper())

    total = q.count()
    items = q.offset(offset).limit(limit).all()

    results = []
    for evt in items:
        req = evt.request
        results.append({
            "id": evt.id,
            "request_id": evt.request_id,
            "timestamp": evt.timestamp.isoformat(),
            "threat_type": evt.threat_type,
            "severity": evt.severity,
            "risk_score": evt.risk_score,
            "action": evt.action,
            "reason": evt.reason,
            "evidence": json.loads(evt.evidence) if evt.evidence else None,
            "remediation": evt.remediation,
            "method": req.method if req else None,
            "endpoint": req.endpoint if req else None,
            "source_ip": req.source_ip if req else None,
            "client_id": req.client_id if req else None,
            "status_code": req.status_code if req else None,
            "response_time_ms": req.response_time_ms if req else None,
        })

    return {"total": total, "items": results}


@router.get("/threats/{threat_id}")
def get_threat(threat_id: int, db: Session = Depends(get_db)):
    evt = db.query(SecurityEvent).filter(SecurityEvent.id == threat_id).first()
    if not evt:
        raise HTTPException(status_code=404, detail="Threat not found")
    req = evt.request
    return {
        "id": evt.id,
        "request_id": evt.request_id,
        "timestamp": evt.timestamp.isoformat(),
        "threat_type": evt.threat_type,
        "severity": evt.severity,
        "risk_score": evt.risk_score,
        "action": evt.action,
        "reason": evt.reason,
        "evidence": json.loads(evt.evidence) if evt.evidence else None,
        "remediation": evt.remediation,
        "method": req.method if req else None,
        "endpoint": req.endpoint if req else None,
        "source_ip": req.source_ip if req else None,
        "client_id": req.client_id if req else None,
        "status_code": req.status_code if req else None,
        "response_time_ms": req.response_time_ms if req else None,
        "request_params": json.loads(req.request_params) if req and req.request_params else None,
        "request_body": json.loads(req.request_body) if req and req.request_body else None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.get("/endpoints")
def list_endpoints(db: Session = Depends(get_db)):
    endpoints = db.query(Endpoint).order_by(Endpoint.total_requests.desc()).all()
    return {
        "items": [
            {
                "id": e.id,
                "path": e.path,
                "methods": e.methods.split(","),
                "total_requests": e.total_requests,
                "threat_count": e.threat_count,
                "avg_risk_score": round(e.avg_risk_score, 1),
                "security_status": e.security_status,
                "last_seen": e.last_seen.isoformat() if e.last_seen else None,
            }
            for e in endpoints
        ]
    }


# ── How many times each scenario fires through the pipeline ──────────────────
# BRUTE_FORCE needs N repeated requests so the sliding window accumulates
# to exceed _THRESHOLD_AUTH (10 auth failures/min) before the detector fires.
_SCENARIO_REPEAT: dict[str, int] = {
    "BRUTE_FORCE": 15,  # 15 failed logins within 60s → triggers RATE_ABUSE
}


# ── Simulate ──────────────────────────────────────────────────────────────────
@router.post("/simulate")
def simulate_attack(payload: SimulateRequest, db: Session = Depends(get_db)):
    scenario = payload.scenario.upper()
    if scenario not in _SCENARIO_MAP:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario: {scenario}. Valid: {list(_SCENARIO_MAP.keys())}",
        )

    request_dict = dict(_SCENARIO_MAP[scenario])
    num_repeats = _SCENARIO_REPEAT.get(scenario, 1)

    final_risk: dict[str, Any] = {}
    final_req_obj: ApiRequest | None = None

    now = datetime.datetime.utcnow()

    for attempt in range(num_repeats):
        # Run full detection pipeline for this attempt
        risk = _run_pipeline(request_dict)

        # Timestamp: spread attempts ~2–4 seconds apart so they look realistic
        ts = now - datetime.timedelta(seconds=(num_repeats - 1 - attempt) * 3)

        # Persist each request to DB
        req_obj = ApiRequest(
            timestamp=ts,
            method=request_dict["method"],
            endpoint=request_dict["endpoint"],
            source_ip=request_dict["source_ip"],
            client_id=request_dict.get("client_id"),
            status_code=request_dict["status_code"],
            response_time_ms=request_dict["response_time_ms"],
            request_params=json.dumps(request_dict.get("params")) if request_dict.get("params") else None,
            request_body=json.dumps(request_dict.get("body")) if request_dict.get("body") else None,
            threat_type=risk["threat_type"] if risk["threat_type"] != "NONE" else None,
            risk_score=risk["risk_score"],
            severity=risk["severity"],
            action=risk["action"],
        )
        db.add(req_obj)
        db.flush()

        if risk["threat_type"] != "NONE":
            evt = SecurityEvent(
                request_id=req_obj.id,
                timestamp=ts,
                threat_type=risk["threat_type"],
                severity=risk["severity"],
                risk_score=risk["risk_score"],
                action=risk["action"],
                reason=risk["reason"],
                evidence=json.dumps(risk["evidence"]) if risk.get("evidence") else None,
                remediation=risk.get("remediation"),
            )
            db.add(evt)

        final_risk = risk
        final_req_obj = req_obj

    # Update or create endpoint record (once, after all attempts)
    ep = db.query(Endpoint).filter(Endpoint.path == request_dict["endpoint"]).first()
    if ep is None:
        ep = Endpoint(path=request_dict["endpoint"], methods=request_dict["method"])
        db.add(ep)
        db.flush()
    ep.total_requests += num_repeats
    if final_risk.get("threat_type") not in (None, "NONE"):
        ep.threat_count += num_repeats
    # Recalculate avg risk from all attempts (approximation: use final score)
    ep.avg_risk_score = (
        (ep.avg_risk_score * max(ep.total_requests - num_repeats, 0) + final_risk["risk_score"] * num_repeats)
        / ep.total_requests
    )
    ep.last_seen = now
    ep.security_status = (
        "CRITICAL" if ep.avg_risk_score >= 60 else
        "AT_RISK"  if ep.avg_risk_score >= 30 else
        "HEALTHY"
    )

    db.commit()

    return {
        "scenario": scenario,
        "attempts": num_repeats,
        "request": {
            "method": request_dict["method"],
            "endpoint": request_dict["endpoint"],
            "source_ip": request_dict["source_ip"],
            "client_id": request_dict.get("client_id"),
            "params": request_dict.get("params"),
            "body": request_dict.get("body"),
        },
        "result": final_risk,
        "request_id": final_req_obj.id if final_req_obj else None,
    }


# ── Analyze ───────────────────────────────────────────────────────────────────
@router.post("/analyze", response_model=RiskResult)
def analyze_request(payload: AnalyzeRequest):
    request_dict = {
        "method": payload.method,
        "endpoint": payload.endpoint,
        "source_ip": payload.source_ip,
        "client_id": payload.client_id,
        "headers": payload.headers or {},
        "params": payload.params or {},
        "body": payload.body or {},
        "status_code": 200,
        "response_time_ms": 100.0,
    }
    risk = _run_pipeline(request_dict)
    return RiskResult(**risk)
