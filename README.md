# API Sentinel

API Security Detection, Risk Scoring, and Automated Response Platform — built for a cybersecurity hackathon demonstration.

---

## Problem

Modern APIs are the primary attack surface for web applications, yet most organisations lack real-time visibility into malicious API traffic. Threats such as BOLA/IDOR, SQL injection, brute-force attacks, broken authentication, and sensitive data exposure are routinely missed until after a breach.

## Solution

API Sentinel is a full-stack security platform that:

1. Collects and analyses API request traffic in real time.
2. Runs each request through a modular detection engine covering the top API threat categories.
3. Calculates a risk score (0–100) via a centralised risk engine.
4. Decides an automated response action (ALLOW / MONITOR / CHALLENGE / BLOCK).
5. Presents findings on a professional SOC-style security dashboard.
6. Provides an interactive attack simulator for live demonstrations.

---

## Architecture

```
API Request
    ↓
Request Collector (FastAPI endpoint)
    ↓
Detection Engine (5 independent modules)
    ↓
Threat Classification
    ↓
Risk Scoring Engine  ──→  0–100 score + severity
    ↓
Response Engine      ──→  ALLOW / MONITOR / CHALLENGE / BLOCK
    ↓
SQLite persistence
    ↓
React Dashboard
```

### Detection Modules

| Module | Threat |
|--------|--------|
| `authentication.py` | Broken Authentication — missing/malformed tokens, weak credentials, auth failures |
| `bola.py` | BOLA / IDOR — cross-user resource access, path ID enumeration |
| `injection.py` | SQL / NoSQL Injection — pattern matching on params and body |
| `rate_abuse.py` | Rate Abuse / Brute Force — sliding-window request counter per IP+endpoint |
| `sensitive_data.py` | Sensitive Data Exposure — PII patterns, sensitive field names |

Each detector implements `BaseDetector` and is completely independent — detectors can be added, removed, or modified without touching other modules.

### Risk Engine

- Accepts a `DetectionResult` from any detector.
- Applies threat-category weight multipliers.
- Returns a normalised score (0–100) and severity label.

### Response Engine

- Reads only the final risk score.
- BLOCK ≥ 80 · CHALLENGE ≥ 60 · MONITOR ≥ 30 · ALLOW < 30

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite 5, Tailwind CSS 3, React Router 6, Recharts 2, Lucide React |
| Backend | Python 3.11+, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy 2 |
| Database | SQLite (file-based, auto-initialised) |

---

## Folder Structure

```
api-sentinel/
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app, lifespan, CORS
│   │   ├── config.py             # Settings (env-driven)
│   │   ├── api/
│   │   │   └── routes.py         # All 7 REST endpoints
│   │   ├── database/
│   │   │   ├── connection.py     # SQLAlchemy engine + session
│   │   │   └── seed.py           # Demo data seeder (~170 records)
│   │   ├── models/
│   │   │   └── models.py         # ApiRequest, SecurityEvent, Endpoint
│   │   ├── schemas/
│   │   │   └── schemas.py        # Pydantic request/response schemas
│   │   ├── services/
│   │   │   ├── detection/
│   │   │   │   ├── base.py
│   │   │   │   ├── authentication.py
│   │   │   │   ├── bola.py
│   │   │   │   ├── injection.py
│   │   │   │   ├── rate_abuse.py
│   │   │   │   └── sensitive_data.py
│   │   │   ├── risk_engine.py
│   │   │   └── response_engine.py
│   │   └── utils/
│   ├── requirements.txt
│   └── .venv/                    # created by setup
├── frontend/
│   ├── src/
│   │   ├── App.jsx               # Sidebar layout + routing
│   │   ├── main.jsx
│   │   ├── index.css             # Tailwind + global styles
│   │   ├── config/api.js         # Backend URL config
│   │   ├── services/api.js       # API client
│   │   ├── components/ui.jsx     # Shared UI primitives
│   │   └── pages/
│   │       ├── Overview.jsx
│   │       ├── LiveTraffic.jsx
│   │       ├── Threats.jsx
│   │       ├── Endpoints.jsx
│   │       └── Simulator.jsx
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── .env.example
├── .gitignore
└── README.md
```

---

## Setup

### Prerequisites

- Python 3.11 or higher
- Node.js 18 or higher

### Backend

```bash
cd api-sentinel/backend

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start server (database is created and seeded automatically)
uvicorn app.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

### Frontend

```bash
cd api-sentinel/frontend

# Copy env file (optional — defaults to localhost:8000)
cp .env.example .env

# Install dependencies
npm install

# Start dev server
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Service health check |
| GET | `/api/dashboard/summary` | Stats, charts, recent events |
| GET | `/api/requests` | All API requests (filterable) |
| GET | `/api/threats` | Security events (filterable) |
| GET | `/api/threats/{id}` | Single threat detail |
| GET | `/api/endpoints` | Endpoint security posture |
| POST | `/api/simulate` | Run an attack simulation scenario |
| POST | `/api/analyze` | Analyse an arbitrary request |

### Simulate Scenarios

```bash
curl -X POST http://localhost:8000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"scenario": "BOLA"}'
```

Valid scenarios: `BOLA`, `SQL_INJECTION`, `BRUTE_FORCE`, `BROKEN_AUTH`, `SENSITIVE_DATA`, `NORMAL`

---

## Risk Scoring

| Range | Severity | Action |
|-------|----------|--------|
| 80–100 | CRITICAL | BLOCK |
| 60–79 | HIGH | CHALLENGE |
| 30–59 | MEDIUM | MONITOR |
| 0–29 | LOW | ALLOW |

---

## Attack Simulator

The Attack Simulator page sends pre-defined payloads to the backend, runs them through the full detection pipeline, and displays:

- Threat type detected
- Risk score and severity
- Action taken
- Detection reason
- Evidence captured
- Recommended remediation

All simulated requests are stored in the database and appear in the Live Traffic, Threats, and Overview pages, so dashboard data updates in real time during a demonstration.

---

## Seeded Demo Data

On first startup the backend seeds approximately 170 requests:

- 80 normal requests
- 25 BOLA/IDOR attempts
- 20 SQL injection attempts
- 20 brute-force / rate-abuse events
- 15 broken authentication events
- 10 sensitive data exposure events

---

## Notes

- No external APIs are required — all data is simulated locally.
- No authentication is implemented (prototype scope).
- The rate-abuse detector uses an in-process sliding window; a production system would use Redis.
- The SQLite database file (`api_sentinel.db`) is created in the `backend/` directory.
