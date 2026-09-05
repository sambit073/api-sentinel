import { useState } from 'react';
import { Zap, ShieldAlert, Database, RefreshCw, Users, Eye, CheckCircle } from 'lucide-react';
import { api } from '../services/api';
import { SeverityBadge, ActionBadge, RiskScore, Card } from '../components/ui';

const SCENARIOS = [
  {
    id: 'BOLA',
    label: 'BOLA / IDOR',
    icon: Users,
    color: 'text-purple-400',
    bg: 'bg-purple-500/10 border-purple-500/30 hover:border-purple-500/60',
    activeBg: 'bg-purple-500/20 border-purple-400',
    desc: 'Client attempts to access a resource belonging to another user.',
    payload: { method: 'GET', endpoint: '/api/users/42', clientId: 'user_99', params: { user_id: '42' } },
  },
  {
    id: 'SQL_INJECTION',
    label: 'SQL Injection',
    icon: Database,
    color: 'text-red-400',
    bg: 'bg-red-500/10 border-red-500/30 hover:border-red-500/60',
    activeBg: 'bg-red-500/20 border-red-400',
    desc: "Malicious SQL payload injected via search parameter.",
    payload: { method: 'GET', endpoint: '/api/search', params: { q: "' OR '1'='1; DROP TABLE users--" } },
  },
  {
    id: 'BRUTE_FORCE',
    label: 'Brute Force',
    icon: RefreshCw,
    color: 'text-orange-400',
    bg: 'bg-orange-500/10 border-orange-500/30 hover:border-orange-500/60',
    activeBg: 'bg-orange-500/20 border-orange-400',
    desc: '15 failed login attempts from the same IP within 60 seconds — triggers rate-abuse detection.',
    payload: { method: 'POST', endpoint: '/api/login', body: { username: 'admin', password: 'guess123' }, note: '×15 attempts' },
  },
  {
    id: 'BROKEN_AUTH',
    label: 'Broken Authentication',
    icon: ShieldAlert,
    color: 'text-yellow-400',
    bg: 'bg-yellow-500/10 border-yellow-500/30 hover:border-yellow-500/60',
    activeBg: 'bg-yellow-500/20 border-yellow-400',
    desc: 'Accessing a protected endpoint with a malformed or missing token.',
    payload: { method: 'GET', endpoint: '/api/admin', headers: { Authorization: 'Bearer bad' } },
  },
  {
    id: 'SENSITIVE_DATA',
    label: 'Sensitive Data Exposure',
    icon: Eye,
    color: 'text-cyan-400',
    bg: 'bg-cyan-500/10 border-cyan-500/30 hover:border-cyan-500/60',
    activeBg: 'bg-cyan-500/20 border-cyan-400',
    desc: 'Request containing raw PII (SSN, credit card) sent to a sensitive endpoint.',
    payload: { method: 'POST', endpoint: '/api/payments', body: { ssn: '123-45-6789', credit_card: '4111111111111111' } },
  },
  {
    id: 'NORMAL',
    label: 'Normal Request',
    icon: CheckCircle,
    color: 'text-green-400',
    bg: 'bg-green-500/10 border-green-500/30 hover:border-green-500/60',
    activeBg: 'bg-green-500/20 border-green-400',
    desc: 'Standard legitimate API request — should be allowed through.',
    payload: { method: 'GET', endpoint: '/api/products', params: { page: 1 } },
  },
];

function DetectionDecision({ risk, request, attempts }) {
  if (!risk) return null;
  const ev = risk.evidence || {};
  const points = [];

  if (risk.threat_type === 'RATE_ABUSE') {
    if (attempts || ev.recent_count) {
      points.push({ label: 'Repeated Attempts', value: `${attempts || ev.recent_count || 15} failed login attempts` });
    }
    points.push({ label: 'Source Identification', value: `Same source IP (${request?.source_ip || ev.source_ip || '203.0.113.10'})` });
    if (ev.window_seconds) {
      points.push({ label: 'Detection Window', value: `${ev.window_seconds}-second sliding window` });
    }
    if (ev.threshold) {
      points.push({ label: 'Threshold Exceeded', value: `Rate limit threshold (${ev.threshold} req/min) exceeded` });
    }
  } else if (risk.threat_type === 'BOLA') {
    if (ev.client_id || request?.client_id) {
      points.push({ label: 'Authenticated Client', value: `Client ID: ${ev.client_id || request?.client_id}` });
    }
    if (ev.requested_resource_owner || request?.params?.user_id) {
      points.push({ label: 'Target Resource Owner', value: `User ID: ${ev.requested_resource_owner || request?.params?.user_id}` });
    }
    points.push({ label: 'Access Violation', value: 'Client attempted to access unowned user resource' });
  } else if (risk.threat_type === 'SQL_INJECTION') {
    if (ev.pattern_matched || request?.params?.q) {
      points.push({ label: 'Matched Pattern', value: `SQL syntax: "${ev.pattern_matched || request?.params?.q}"` });
    }
    points.push({ label: 'Vector', value: 'Unsanitized input parameter contains SQL control characters' });
  } else if (risk.threat_type === 'BROKEN_AUTH') {
    if (ev.malformed_token || request?.headers?.Authorization) {
      points.push({ label: 'Token Analysis', value: `Invalid bearer token: "${ev.malformed_token || request?.headers?.Authorization}"` });
    }
    points.push({ label: 'Auth Anomaly', value: 'Protected endpoint access attempted without valid bearer token' });
  } else if (risk.threat_type === 'SENSITIVE_DATA') {
    if (ev.sensitive_fields) {
      const fields = Array.isArray(ev.sensitive_fields) ? ev.sensitive_fields.join(', ') : ev.sensitive_fields;
      points.push({ label: 'Exposed Fields', value: `PII parameters detected: ${fields}` });
    }
    if (ev.sensitive_endpoint || request?.endpoint) {
      points.push({ label: 'Target Route', value: `Sensitive endpoint: ${ev.sensitive_endpoint || request?.endpoint}` });
    }
    points.push({ label: 'Data Severity', value: 'Unencrypted sensitive identifiers in request payload' });
  } else {
    points.push({ label: 'Security Heuristics', value: 'Passed all signature and pattern matching checks' });
    points.push({ label: 'Behavioral Analysis', value: 'No rate anomalies or access violations detected' });
  }

  points.push({ label: 'Calculated Risk', value: `${Math.round(risk.risk_score)} / 100 (${risk.severity || 'LOW'})` });
  points.push({ label: 'Policy Response', value: risk.action || 'ALLOW' });

  return (
    <div className="mb-4 p-4 bg-slate-900/90 border border-slate-700/60 rounded-xl space-y-3">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <span className="text-xs font-bold text-cyan-400 tracking-wider uppercase flex items-center gap-1.5">
          <Zap size={14} /> WHY WAS THIS DETECTED? — DETECTION DECISION
        </span>
        <span className="text-[11px] text-slate-400 font-mono">Verdict: {risk.threat_type || 'CLEAN'}</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
        {points.map((p, idx) => (
          <div key={idx} className="flex items-start gap-2 p-2 rounded bg-slate-950/70 border border-slate-800/80">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1 flex-shrink-0" />
            <div>
              <span className="font-semibold text-slate-300">{p.label}: </span>
              <span className="text-slate-400 font-mono">{p.value}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ResultPanel({ result, scenario }) {
  if (!result) return null;
  const { request, result: risk, attempts } = result;
  const detected = risk.threat_type && risk.threat_type !== 'NONE';

  return (
    <Card className={`p-5 border-2 ${
      detected ? 'border-red-500/40 bg-red-500/5' : 'border-green-500/40 bg-green-500/5'
    }`}>
      {/* Title */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          {detected ? (
            <div className="flex items-center gap-2">
              <ShieldAlert size={20} className="text-red-400" />
              <span className="text-base font-bold text-red-400">THREAT DETECTED</span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <CheckCircle size={20} className="text-green-400" />
              <span className="text-base font-bold text-green-400">REQUEST ALLOWED</span>
            </div>
          )}
        </div>
        {attempts && attempts > 1 && (
          <span className="text-xs bg-orange-500/15 text-orange-400 border border-orange-500/30 px-2 py-1 rounded-full font-mono">
            {attempts} simulated attempts
          </span>
        )}
      </div>

      {/* Verdict grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        <div className="p-3 bg-slate-900/60 rounded-lg">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Threat Type</p>
          <p className="text-sm font-bold text-white">
            {risk.threat_type === 'NONE' ? 'None' : risk.threat_type?.replace(/_/g, ' ')}
          </p>
        </div>
        <div className="p-3 bg-slate-900/60 rounded-lg">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Risk Score</p>
          <RiskScore score={risk.risk_score} />
        </div>
        <div className="p-3 bg-slate-900/60 rounded-lg">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Severity</p>
          <SeverityBadge severity={risk.severity} />
        </div>
        <div className="p-3 bg-slate-900/60 rounded-lg">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Action</p>
          <ActionBadge action={risk.action} />
        </div>
      </div>

      {/* WHY WAS THIS DETECTED? */}
      <DetectionDecision risk={risk} request={request} attempts={attempts} />

      {/* Reason */}
      <div className="mb-4">
        <p className="text-xs text-slate-500 uppercase tracking-wide mb-1.5">Detection Reason</p>
        <div className={`p-3 rounded-lg border text-sm text-slate-300 leading-relaxed
          ${detected ? 'bg-red-500/5 border-red-500/20' : 'bg-green-500/5 border-green-500/20'}`}>
          {risk.reason}
        </div>
      </div>

      {/* Request details */}
      <div>
        <p className="text-xs text-slate-500 uppercase tracking-wide mb-1.5">Simulated Request</p>
        <pre className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-300 overflow-x-auto font-mono">
{JSON.stringify(request, null, 2)}
        </pre>
      </div>

      {/* Evidence */}
      {risk.evidence && (
        <div className="mt-4">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1.5">Raw Evidence Payload</p>
          <pre className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-300 overflow-x-auto font-mono">
{JSON.stringify(risk.evidence, null, 2)}
          </pre>
        </div>
      )}

      {/* Remediation */}
      {risk.remediation && (
        <div className="mt-4 p-3 bg-cyan-500/5 border border-cyan-500/20 rounded-lg">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Remediation</p>
          <p className="text-sm text-cyan-300">{risk.remediation}</p>
        </div>
      )}
    </Card>
  );
}

export default function Simulator() {
  const [activeScenario, setActiveScenario] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const runScenario = async (scenarioId) => {
    setActiveScenario(scenarioId);
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const data = await api.simulate(scenarioId);
      setResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <Zap size={20} className="text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Attack Simulator</h1>
        </div>
        <p className="text-slate-400 text-sm">
          Simulate real attack scenarios against the detection engine. Results are persisted and appear in the dashboard.
        </p>
      </div>

      {/* Scenario cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {SCENARIOS.map(({ id, label, icon: Icon, color, bg, activeBg, desc, payload }) => (
          <button
            key={id}
            onClick={() => runScenario(id)}
            disabled={loading}
            className={`text-left p-4 rounded-xl border transition-all duration-200 disabled:opacity-50 disabled:cursor-wait
              ${activeScenario === id ? activeBg : bg}`}
          >
            <div className="flex items-start gap-3">
              <div className={`p-2 rounded-lg bg-slate-800/60 ${color}`}>
                {loading && activeScenario === id
                  ? <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  : <Icon size={16} />
                }
              </div>
              <div className="flex-1 min-w-0">
                <p className={`text-sm font-bold mb-0.5 ${activeScenario === id ? color : 'text-white'}`}>
                  {label}
                </p>
                <p className="text-xs text-slate-500 leading-relaxed">{desc}</p>
              </div>
            </div>
            <div className="mt-3 pt-3 border-t border-slate-700/40">
              <p className="text-xs font-mono text-slate-600 truncate">
                {payload.method} {payload.endpoint}
              </p>
            </div>
          </button>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm">
          Error: {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <Card className="p-8 flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm text-slate-400">Running detection pipeline…</p>
          <p className="text-xs text-slate-600">Analyzing request → detecting threats → scoring risk → deciding action</p>
        </Card>
      )}

      {/* Result */}
      {!loading && result && <ResultPanel result={result} scenario={activeScenario} />}

      {/* Help text */}
      {!result && !loading && !error && (
        <Card className="p-8 text-center">
          <Zap size={32} className="text-slate-700 mx-auto mb-3" />
          <p className="text-slate-500 text-sm">Select an attack scenario above to run the detection pipeline.</p>
          <p className="text-slate-600 text-xs mt-1">Results are saved to the database and appear in the Overview and Threats pages.</p>
        </Card>
      )}
    </div>
  );
}
