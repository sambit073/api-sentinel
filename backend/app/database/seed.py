"""
Database seeder — creates realistic demo data for API Sentinel.
Run once at startup if the database is empty.
"""
from __future__ import annotations
import datetime
import json
import random

from sqlalchemy.orm import Session

from app.models.models import ApiRequest, SecurityEvent, Endpoint

# ── Realistic endpoint catalogue ─────────────────────────────────────────────
ENDPOINT_CATALOGUE = [
    ("/api/login",          ["POST"],   True),
    ("/api/logout",         ["POST"],   False),
    ("/api/users/1",        ["GET"],    True),
    ("/api/users/2",        ["GET"],    True),
    ("/api/users/42",       ["GET"],    True),
    ("/api/users/99",       ["GET"],    True),
    ("/api/products",       ["GET"],    False),
    ("/api/products/1",     ["GET"],    False),
    ("/api/search",         ["GET"],    False),
    ("/api/admin",          ["GET"],    True),
    ("/api/admin/users",    ["GET"],    True),
    ("/api/payments",       ["POST"],   True),
    ("/api/orders",         ["GET"],    True),
    ("/api/orders/55",      ["GET"],    True),
    ("/api/profile",        ["GET"],    True),
    ("/api/health",         ["GET"],    False),
]

NORMAL_IPS     = ["192.168.1.10", "10.0.0.5", "172.16.0.20", "203.0.113.5"]
ATTACKER_IPS   = ["185.220.101.42", "45.33.32.156", "198.51.100.7", "203.0.113.99"]
CLIENT_IDS     = ["user_1", "user_2", "user_3", "user_42", "admin_1"]
ATTACKER_USERS = ["user_99", "guest", "anonymous"]


def _rand_ts(days_back: int = 7) -> datetime.datetime:
    """Random timestamp within the last `days_back` days."""
    seconds_back = random.randint(0, days_back * 24 * 3600)
    return datetime.datetime.utcnow() - datetime.timedelta(seconds=seconds_back)


# ── Individual scenario builders ─────────────────────────────────────────────

def _normal(ts: datetime.datetime) -> dict:
    ep, methods, _ = random.choice(ENDPOINT_CATALOGUE[:10])
    return dict(
        timestamp=ts,
        method=random.choice(methods),
        endpoint=ep,
        source_ip=random.choice(NORMAL_IPS),
        client_id=random.choice(CLIENT_IDS),
        status_code=random.choice([200, 200, 200, 201, 204]),
        response_time_ms=round(random.uniform(20, 180), 2),
        request_params=None,
        request_body=None,
        threat_type=None,
        risk_score=round(random.uniform(0, 15), 1),
        severity="LOW",
        action="ALLOW",
    )


def _bola(ts: datetime.datetime) -> tuple[dict, dict]:
    victim_id = random.choice(["1", "2", "3", "42"])
    attacker = random.choice(ATTACKER_USERS)
    ep = f"/api/users/{victim_id}"
    score = round(random.uniform(82, 96), 1)
    req = dict(
        timestamp=ts,
        method="GET",
        endpoint=ep,
        source_ip=random.choice(ATTACKER_IPS),
        client_id=attacker,
        status_code=200,
        response_time_ms=round(random.uniform(40, 120), 2),
        request_params=json.dumps({"user_id": victim_id}),
        request_body=None,
        threat_type="BOLA",
        risk_score=score,
        severity="CRITICAL",
        action="BLOCK",
    )
    evt = dict(
        threat_type="BOLA",
        severity="CRITICAL",
        risk_score=score,
        action="BLOCK",
        reason=f"Client '{attacker}' attempted to access a resource belonging to user '{victim_id}'.",
        evidence=json.dumps({"requesting_client": attacker, "target_user_id": victim_id, "endpoint": ep}),
        remediation="Enforce server-side ownership checks on every object access. Use UUIDs instead of sequential IDs.",
    )
    return req, evt


def _sql_injection(ts: datetime.datetime) -> tuple[dict, dict]:
    payloads = [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "UNION SELECT password FROM users--",
        "admin'--",
        "' OR 1=1--",
        "SLEEP(5)--",
    ]
    payload = random.choice(payloads)
    ep = random.choice(["/api/search", "/api/login", "/api/products"])
    score = round(random.uniform(75, 92), 1)
    req = dict(
        timestamp=ts,
        method="GET" if ep == "/api/search" else "POST",
        endpoint=ep,
        source_ip=random.choice(ATTACKER_IPS),
        client_id=random.choice(ATTACKER_USERS),
        status_code=400,
        response_time_ms=round(random.uniform(10, 80), 2),
        request_params=json.dumps({"q": payload}),
        request_body=json.dumps({"username": payload, "password": "anything"}),
        threat_type="SQL_INJECTION",
        risk_score=score,
        severity="HIGH" if score < 80 else "CRITICAL",
        action="BLOCK",
    )
    evt = dict(
        threat_type="SQL_INJECTION",
        severity=req["severity"],
        risk_score=score,
        action="BLOCK",
        reason=f"SQL injection pattern detected in request: '{payload[:60]}'.",
        evidence=json.dumps({"payload": payload, "endpoint": ep}),
        remediation="Use parameterised queries. Validate and sanitise all user-supplied input. Apply WAF rules.",
    )
    return req, evt


def _brute_force(ts: datetime.datetime) -> tuple[dict, dict]:
    attacker_ip = random.choice(ATTACKER_IPS)
    score = round(random.uniform(65, 85), 1)
    req = dict(
        timestamp=ts,
        method="POST",
        endpoint="/api/login",
        source_ip=attacker_ip,
        client_id="anonymous",
        status_code=401,
        response_time_ms=round(random.uniform(200, 600), 2),
        request_params=None,
        request_body=json.dumps({"username": "admin", "password": "guess123"}),
        threat_type="RATE_ABUSE",
        risk_score=score,
        severity="HIGH" if score < 80 else "CRITICAL",
        action="BLOCK",
    )
    evt = dict(
        threat_type="RATE_ABUSE",
        severity=req["severity"],
        risk_score=score,
        action="BLOCK",
        reason=f"IP {attacker_ip} triggered repeated authentication failures (brute-force pattern).",
        evidence=json.dumps({"source_ip": attacker_ip, "endpoint": "/api/login", "auth_failures_per_minute": random.randint(15, 60)}),
        remediation="Enable rate limiting per IP. Enforce account lockout after 5 failures. Add CAPTCHA on login.",
    )
    return req, evt


def _broken_auth(ts: datetime.datetime) -> tuple[dict, dict]:
    ep = random.choice(["/api/admin", "/api/profile", "/api/payments"])
    score = round(random.uniform(55, 78), 1)
    req = dict(
        timestamp=ts,
        method="GET",
        endpoint=ep,
        source_ip=random.choice(ATTACKER_IPS),
        client_id="user_99",
        status_code=403,
        response_time_ms=round(random.uniform(30, 100), 2),
        request_params=None,
        request_body=None,
        threat_type="BROKEN_AUTH",
        risk_score=score,
        severity="MEDIUM" if score < 60 else "HIGH",
        action="CHALLENGE",
    )
    evt = dict(
        threat_type="BROKEN_AUTH",
        severity=req["severity"],
        risk_score=score,
        action="CHALLENGE",
        reason=f"Missing or malformed Authorization token on protected endpoint '{ep}'.",
        evidence=json.dumps({"endpoint": ep, "missing_auth_header": True}),
        remediation="Enforce JWT/OAuth2 on all protected routes. Use short-lived tokens with refresh rotation.",
    )
    return req, evt


def _sensitive_data(ts: datetime.datetime) -> tuple[dict, dict]:
    ep = random.choice(["/api/users/42", "/api/payments", "/api/admin/users"])
    score = round(random.uniform(60, 80), 1)
    req = dict(
        timestamp=ts,
        method="GET",
        endpoint=ep,
        source_ip=random.choice(ATTACKER_IPS + NORMAL_IPS),
        client_id=random.choice(ATTACKER_USERS),
        status_code=200,
        response_time_ms=round(random.uniform(50, 200), 2),
        request_params=None,
        request_body=json.dumps({"ssn": "123-45-6789", "credit_card": "4111111111111111"}),
        threat_type="SENSITIVE_DATA",
        risk_score=score,
        severity="HIGH",
        action="MONITOR",
    )
    evt = dict(
        threat_type="SENSITIVE_DATA",
        severity="HIGH",
        risk_score=score,
        action="MONITOR",
        reason="Potential PII (SSN, credit card number) detected in request body targeting a sensitive endpoint.",
        evidence=json.dumps({"sensitive_fields": ["ssn", "credit_card"], "endpoint": ep}),
        remediation="Apply field-level encryption. Strip PII from logs and responses. Restrict access to sensitive endpoints.",
    )
    return req, evt


# ── Main seeder ───────────────────────────────────────────────────────────────

def seed_database(db: Session) -> None:
    """Populate the database with realistic demo data if it is empty."""
    if db.query(ApiRequest).count() > 0:
        return   # Already seeded

    print("Seeding database with demo data...")

    # 1. Endpoints
    for path, methods, _ in ENDPOINT_CATALOGUE:
        ep = Endpoint(
            path=path,
            methods=",".join(methods),
            total_requests=0,
            threat_count=0,
            avg_risk_score=0.0,
            security_status="HEALTHY",
            last_seen=datetime.datetime.utcnow() - datetime.timedelta(minutes=random.randint(1, 60)),
        )
        db.add(ep)
    db.commit()

    endpoint_map: dict[str, Endpoint] = {
        ep.path: ep for ep in db.query(Endpoint).all()
    }

    # 2. Requests — mix of normal and attack scenarios
    scenarios = (
        [("normal",         80)] +
        [("bola",           25)] +
        [("sql_injection",  20)] +
        [("brute_force",    20)] +
        [("broken_auth",    15)] +
        [("sensitive_data", 10)]
    )

    request_objects: list[ApiRequest] = []
    event_payloads: list[tuple[int, dict]] = []   # (request_index, evt_dict)

    for scenario, count in scenarios:
        for _ in range(count):
            ts = _rand_ts(days_back=7)

            if scenario == "normal":
                rd = _normal(ts)
                req_obj = ApiRequest(**rd)
                db.add(req_obj)
                request_objects.append(req_obj)
            else:
                builders = {
                    "bola":           _bola,
                    "sql_injection":  _sql_injection,
                    "brute_force":    _brute_force,
                    "broken_auth":    _broken_auth,
                    "sensitive_data": _sensitive_data,
                }
                rd, evd = builders[scenario](ts)
                req_obj = ApiRequest(**rd)
                db.add(req_obj)
                request_objects.append(req_obj)
                event_payloads.append((len(request_objects) - 1, evd))

    db.flush()  # assign IDs without committing

    # 3. Security events
    for req_idx, evd in event_payloads:
        req_obj = request_objects[req_idx]
        event = SecurityEvent(
            request_id=req_obj.id,
            timestamp=req_obj.timestamp,
            **evd,
        )
        db.add(event)

    db.flush()

    # 4. Update endpoint stats
    for req_obj in request_objects:
        path = req_obj.endpoint
        # normalise paths like /api/users/42 → /api/users/:id
        import re
        norm = re.sub(r"/\d+", "/:id", path)
        ep = endpoint_map.get(path) or endpoint_map.get(norm)
        if ep is None:
            # find closest match
            for k in endpoint_map:
                if path.startswith(k):
                    ep = endpoint_map[k]
                    break
        if ep is None:
            continue
        ep.total_requests += 1
        if req_obj.threat_type:
            ep.threat_count += 1
        if req_obj.risk_score is not None:
            ep.avg_risk_score = (
                (ep.avg_risk_score * (ep.total_requests - 1) + req_obj.risk_score)
                / ep.total_requests
            )
        if req_obj.timestamp and (ep.last_seen is None or req_obj.timestamp > ep.last_seen):
            ep.last_seen = req_obj.timestamp

    # Compute security status for each endpoint
    for ep in endpoint_map.values():
        if ep.avg_risk_score >= 60:
            ep.security_status = "CRITICAL"
        elif ep.avg_risk_score >= 30:
            ep.security_status = "AT_RISK"
        else:
            ep.security_status = "HEALTHY"

    db.commit()
    print(f"Seeded {len(request_objects)} requests and {len(event_payloads)} security events.")
