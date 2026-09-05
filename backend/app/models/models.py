"""
SQLAlchemy ORM models for API Sentinel.
"""
import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.database.connection import Base


class ApiRequest(Base):
    __tablename__ = "api_requests"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    method = Column(String(10), nullable=False)
    endpoint = Column(String(255), nullable=False, index=True)
    source_ip = Column(String(50), nullable=False)
    client_id = Column(String(100), nullable=True)
    status_code = Column(Integer, nullable=False)
    response_time_ms = Column(Float, nullable=False)
    request_params = Column(Text, nullable=True)  # JSON string
    request_body = Column(Text, nullable=True)    # JSON string

    # Risk fields (may be null for benign requests)
    threat_type = Column(String(100), nullable=True)
    risk_score = Column(Float, nullable=True)
    severity = Column(String(20), nullable=True)   # LOW / MEDIUM / HIGH / CRITICAL
    action = Column(String(20), nullable=True)     # ALLOW / MONITOR / CHALLENGE / BLOCK

    security_event = relationship("SecurityEvent", back_populates="request", uselist=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("api_requests.id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    threat_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    risk_score = Column(Float, nullable=False)
    action = Column(String(20), nullable=False)
    reason = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)        # JSON string
    remediation = Column(Text, nullable=True)

    request = relationship("ApiRequest", back_populates="security_event")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    path = Column(String(255), unique=True, nullable=False, index=True)
    methods = Column(String(100), nullable=False, default="GET")  # comma-separated
    total_requests = Column(Integer, default=0)
    threat_count = Column(Integer, default=0)
    avg_risk_score = Column(Float, default=0.0)
    security_status = Column(String(20), default="HEALTHY")  # HEALTHY / AT_RISK / CRITICAL
    last_seen = Column(DateTime, nullable=True)
