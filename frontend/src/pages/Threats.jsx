import { useState, useEffect, useMemo } from 'react';
import { X, ChevronRight, Shield, AlertTriangle, Layers } from 'lucide-react';
import { api } from '../services/api';
import { SeverityBadge, ActionBadge, RiskScore, MethodBadge, Card, LoadingSpinner, EmptyState } from '../components/ui';

function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function formatThreatType(t) {
  return t.replace(/_/g, ' ');
}

const REMEDIATION_STEPS = {
  BOLA: [
    'Implement server-side authorisation checks on every object access.',
    'Never rely on client-supplied IDs to determine ownership.',
    'Use UUIDs or indirect references instead of sequential integers.',
    'Log and alert on all cross-user resource access attempts.',
  ],
  SQL_INJECTION: [
    'Use parameterised queries or prepared statements exclusively.',
    'Validate and sanitise all user-supplied input server-side.',
    'Apply the principle of least privilege to database accounts.',
    'Deploy a Web Application Firewall with injection rule sets.',
  ],
  RATE_ABUSE: [
    'Implement per-IP and per-token rate limiting.',
    'Add exponential back-off after repeated authentication failures.',
    'Use CAPTCHA or step-up MFA challenges after threshold violations.',
    'Monitor for distributed patterns across multiple IPs.',
  ],
  BROKEN_AUTH: [
    'Enforce JWT or OAuth 2.0 on all protected routes.',
    'Use short-lived access tokens with secure refresh rotation.',
    'Implement account lockout after 5 consecutive failures.',
    'Require MFA for high-privilege operations.',
  ],
  SENSITIVE_DATA: [
    'Apply field-level encryption for sensitive data at rest.',
    'Strip PII from API responses for unprivileged clients.',
    'Never log raw sensitive fields (SSN, card numbers, passwords).',
    'Apply data masking in responses (e.g., show only last 4 digits).',
  ],
};

function ThreatDetail({ threat, onClose }) {
  const steps = REMEDIATION_STEPS[threat.threat_type] || [];

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div className="flex-1 bg-slate-950/70 backdrop-blur-sm" onClick={onClose} />
      {/* Panel */}
      <div className="w-full max-w-xl bg-slate-900 border-l border-slate-700/60 flex flex-col overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <AlertTriangle size={18} className="text-orange-400" />
            <h2 className="text-base font-bold text-white">Threat Investigation</h2>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
            <X size={18} />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {/* Grouped Incident Banner */}
          {threat.attemptCount > 1 && (
            <div className="p-3 bg-orange-500/10 border border-orange-500/30 rounded-lg flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 text-orange-300 font-medium">
                <Layers size={16} className="text-orange-400 flex-shrink-0" />
                <span>Grouped Incident: {threat.attemptCount} repeated rate abuse attempts consolidated from IP {threat.source_ip}</span>
              </div>
            </div>
          )}

          {/* Verdict */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 bg-slate-800/60 rounded-lg border border-slate-700/40">
              <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Threat Type</p>
              <p className="text-sm font-bold text-white">{formatThreatType(threat.threat_type)}</p>
            </div>
            <div className="p-3 bg-slate-800/60 rounded-lg border border-slate-700/40">
              <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Peak Risk Score</p>
              <RiskScore score={threat.risk_score} />
            </div>
            <div className="p-3 bg-slate-800/60 rounded-lg border border-slate-700/40">
              <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Severity</p>
              <SeverityBadge severity={threat.severity} />
            </div>
            <div className="p-3 bg-slate-800/60 rounded-lg border border-slate-700/40">
              <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Action Taken</p>
              <ActionBadge action={threat.action} />
            </div>
          </div>

          {/* Request details */}
          <div>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Request Details</h3>
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2 font-mono text-xs">
              <div className="flex gap-2">
                <span className="text-slate-500 w-24 flex-shrink-0">Method</span>
                {threat.method && <MethodBadge method={threat.method} />}
              </div>
              <div className="flex gap-2">
                <span className="text-slate-500 w-24 flex-shrink-0">Endpoint</span>
                <span className="text-cyan-400">{threat.endpoint}</span>
              </div>
              <div className="flex gap-2">
                <span className="text-slate-500 w-24 flex-shrink-0">Source IP</span>
                <span className="text-slate-300">{threat.source_ip}</span>
              </div>
              {threat.attemptCount > 1 && (
                <div className="flex gap-2">
                  <span className="text-slate-500 w-24 flex-shrink-0">Attempts</span>
                  <span className="text-orange-400 font-bold">{threat.attemptCount} events</span>
                </div>
              )}
              {threat.client_id && (
                <div className="flex gap-2">
                  <span className="text-slate-500 w-24 flex-shrink-0">Client ID</span>
                  <span className="text-slate-300">{threat.client_id}</span>
                </div>
              )}
              <div className="flex gap-2">
                <span className="text-slate-500 w-24 flex-shrink-0">Latest Time</span>
                <span className="text-slate-300">{new Date(threat.timestamp).toLocaleString()}</span>
              </div>
              {threat.status_code && (
                <div className="flex gap-2">
                  <span className="text-slate-500 w-24 flex-shrink-0">Status</span>
                  <span className={threat.status_code < 400 ? 'text-green-400' : 'text-red-400'}>{threat.status_code}</span>
                </div>
              )}
            </div>
          </div>

          {/* Why detected */}
          <div>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Detection Reason</h3>
            <div className="p-3 bg-orange-500/5 border border-orange-500/20 rounded-lg">
              <p className="text-sm text-slate-300 leading-relaxed">{threat.reason}</p>
            </div>
          </div>

          {/* Evidence */}
          {threat.evidence && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Evidence</h3>
              <pre className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-300 overflow-x-auto font-mono">
                {JSON.stringify(threat.evidence, null, 2)}
              </pre>
            </div>
          )}

          {/* Remediation */}
          <div>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">
              Recommended Remediation
            </h3>
            <div className="space-y-2">
              {steps.length > 0 ? steps.map((step, i) => (
                <div key={i} className="flex gap-2 items-start">
                  <Shield size={12} className="text-cyan-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-slate-300">{step}</p>
                </div>
              )) : (
                <p className="text-xs text-slate-400">{threat.remediation}</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Threats() {
  const [threats, setThreats] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const load = async () => {
    try {
      const params = {
        limit: 200,
        ...(severityFilter !== 'ALL' && { severity: severityFilter }),
      };
      const data = await api.getThreats(params);
      setThreats(data.items);
      setTotal(data.total);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    load();
  }, [severityFilter]);

  // Consolidate repeated RATE_ABUSE events from same source IP & endpoint
  const displayThreats = useMemo(() => {
    const grouped = [];
    for (const t of threats) {
      if (t.threat_type === 'RATE_ABUSE') {
        const tTime = new Date(t.timestamp).getTime();
        const matchIndex = grouped.findIndex(g =>
          g.isGrouped &&
          g.threat_type === 'RATE_ABUSE' &&
          g.source_ip === t.source_ip &&
          g.endpoint === t.endpoint &&
          Math.abs(new Date(g.latestTimestamp).getTime() - tTime) < 600000 // 10 min window
        );

        if (matchIndex >= 0) {
          const group = grouped[matchIndex];
          group.events.push(t);
          group.attemptCount += 1;
          if (t.risk_score > group.risk_score) group.risk_score = t.risk_score;
          if (tTime > new Date(group.latestTimestamp).getTime()) {
            group.latestTimestamp = t.timestamp;
            group.timestamp = t.timestamp;
            group.action = t.action;
            group.severity = t.severity;
          }
          continue;
        } else {
          grouped.push({
            ...t,
            isGrouped: true,
            attemptCount: 1,
            latestTimestamp: t.timestamp,
            events: [t],
          });
          continue;
        }
      }

      grouped.push({
        ...t,
        isGrouped: false,
        attemptCount: 1,
        events: [t],
      });
    }

    return grouped;
  }, [threats]);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-white">Threats</h1>
        <p className="text-slate-400 text-sm mt-0.5">{total} security events detected — click any row to investigate</p>
      </div>

      {/* Severity filter */}
      <Card className="p-4">
        <div className="flex gap-1">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
            <button key={s} onClick={() => setSeverityFilter(s)}
              className={`filter-btn ${severityFilter === s ? 'filter-btn-active' : 'filter-btn-inactive'}`}>
              {s}
            </button>
          ))}
        </div>
      </Card>

      {/* Threats table */}
      <Card className="overflow-hidden">
        {loading ? <LoadingSpinner /> : error ? (
          <div className="p-6 text-red-400 text-sm">{error}</div>
        ) : displayThreats.length === 0 ? <EmptyState message="No threats detected" /> : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900/60 border-b border-slate-800">
                <tr>
                  {['Severity', 'Threat Type', 'Endpoint', 'Source IP', 'Risk', 'Action', 'Time', ''].map(h => (
                    <th key={h} className="table-header">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayThreats.map(t => (
                  <tr key={t.id}
                    className="table-row cursor-pointer"
                    onClick={() => setSelected(t)}
                  >
                    <td className="table-cell"><SeverityBadge severity={t.severity} /></td>
                    <td className="table-cell font-semibold text-slate-200">
                      <div className="flex items-center gap-2">
                        <span>{formatThreatType(t.threat_type)}</span>
                        {t.attemptCount > 1 && (
                          <span className="text-[10px] bg-orange-500/15 text-orange-400 border border-orange-500/30 px-1.5 py-0.5 rounded font-mono font-medium">
                            {t.attemptCount} attempts
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="table-cell font-mono text-xs text-cyan-400 max-w-[180px] truncate">{t.endpoint}</td>
                    <td className="table-cell font-mono text-xs text-slate-400">{t.source_ip}</td>
                    <td className="table-cell"><RiskScore score={t.risk_score} /></td>
                    <td className="table-cell"><ActionBadge action={t.action} /></td>
                    <td className="table-cell text-xs text-slate-500">{timeAgo(t.timestamp)}</td>
                    <td className="table-cell text-slate-600"><ChevronRight size={14} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selected && <ThreatDetail threat={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
