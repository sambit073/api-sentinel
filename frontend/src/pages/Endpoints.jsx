import { useState, useEffect } from 'react';
import { Globe, Activity } from 'lucide-react';
import { api } from '../services/api';
import { StatusDot, Card, LoadingSpinner, EmptyState } from '../components/ui';

function RiskBar({ score }) {
  const color =
    score >= 60 ? 'bg-red-500' :
    score >= 30 ? 'bg-yellow-500' :
    'bg-green-500';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${Math.min(score, 100)}%` }} />
      </div>
      <span className={`text-xs font-bold tabular-nums w-8 text-right ${
        score >= 60 ? 'text-red-400' : score >= 30 ? 'text-yellow-400' : 'text-green-400'
      }`}>{score.toFixed(0)}</span>
    </div>
  );
}

function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function Endpoints() {
  const [endpoints, setEndpoints] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.getEndpoints()
      .then(data => { setEndpoints(data.items); setError(null); })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  // Summary stats
  const critical = endpoints.filter(e => e.security_status === 'CRITICAL').length;
  const atRisk   = endpoints.filter(e => e.security_status === 'AT_RISK').length;
  const healthy  = endpoints.filter(e => e.security_status === 'HEALTHY').length;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-white">Endpoints</h1>
        <p className="text-slate-400 text-sm mt-0.5">API surface coverage and per-endpoint security posture</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Critical', value: critical, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
          { label: 'At Risk', value: atRisk, color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
          { label: 'Healthy', value: healthy, color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20' },
        ].map(({ label, value, color, bg }) => (
          <div key={label} className={`p-4 rounded-xl border ${bg} flex items-center gap-3`}>
            <Globe size={18} className={color} />
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wide">{label}</p>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Table */}
      <Card className="overflow-hidden">
        {loading ? <LoadingSpinner /> : error ? (
          <div className="p-6 text-red-400 text-sm">{error}</div>
        ) : endpoints.length === 0 ? <EmptyState message="No endpoints recorded yet" /> : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900/60 border-b border-slate-800">
                <tr>
                  {['Endpoint', 'Methods', 'Requests', 'Threats', 'Avg Risk', 'Status', 'Last Seen'].map(h => (
                    <th key={h} className="table-header">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {endpoints.map(ep => (
                  <tr key={ep.id} className="table-row">
                    <td className="table-cell font-mono text-sm text-cyan-400">{ep.path}</td>
                    <td className="table-cell">
                      <div className="flex gap-1">
                        {ep.methods.map(m => (
                          <span key={m} className="text-xs font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                            {m}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="table-cell">
                      <div className="flex items-center gap-1.5">
                        <Activity size={12} className="text-slate-500" />
                        <span className="text-sm text-slate-300 tabular-nums">{ep.total_requests.toLocaleString()}</span>
                      </div>
                    </td>
                    <td className="table-cell">
                      <span className={`text-sm font-semibold tabular-nums ${ep.threat_count > 0 ? 'text-orange-400' : 'text-slate-500'}`}>
                        {ep.threat_count}
                      </span>
                    </td>
                    <td className="table-cell w-40">
                      <RiskBar score={ep.avg_risk_score} />
                    </td>
                    <td className="table-cell"><StatusDot status={ep.security_status} /></td>
                    <td className="table-cell text-xs text-slate-500">{timeAgo(ep.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
