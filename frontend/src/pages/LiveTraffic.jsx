import { useState, useEffect, useCallback } from 'react';
import { RefreshCw } from 'lucide-react';
import { api } from '../services/api';
import { SeverityBadge, ActionBadge, RiskScore, MethodBadge, Card, LoadingSpinner, EmptyState } from '../components/ui';

const SEVERITY_OPTS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const METHOD_OPTS   = ['ALL', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
const ACTION_OPTS   = ['ALL', 'BLOCK', 'CHALLENGE', 'MONITOR', 'ALLOW'];

function formatTime(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function LiveTraffic() {
  const [requests, setRequests] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Filters
  const [severity, setSeverity] = useState('ALL');
  const [method, setMethod] = useState('ALL');
  const [action, setAction] = useState('ALL');
  const [threatsOnly, setThreatsOnly] = useState(false);

  const load = useCallback(async () => {
    try {
      const params = {
        limit: 150,
        ...(severity !== 'ALL' && { severity }),
        ...(method !== 'ALL' && { method }),
        ...(action !== 'ALL' && { action }),
        ...(threatsOnly && { has_threat: true }),
      };
      const data = await api.getRequests(params);
      setRequests(data.items);
      setTotal(data.total);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [severity, method, action, threatsOnly]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, load]);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Live Traffic</h1>
          <p className="text-slate-400 text-sm mt-0.5">{total.toLocaleString()} total requests</p>
        </div>
        <button
          onClick={() => setAutoRefresh(v => !v)}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all
            ${autoRefresh
              ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
              : 'bg-slate-800 text-slate-400 border-slate-700'}`}
        >
          <RefreshCw size={12} className={autoRefresh ? 'animate-spin' : ''} style={autoRefresh ? { animationDuration: '3s' } : {}} />
          {autoRefresh ? 'Live' : 'Paused'}
        </button>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="flex flex-wrap gap-4">
          <div>
            <p className="text-xs text-slate-500 mb-1.5 uppercase tracking-wide">Severity</p>
            <div className="flex gap-1">
              {SEVERITY_OPTS.map(s => (
                <button key={s} onClick={() => setSeverity(s)}
                  className={`filter-btn ${severity === s ? 'filter-btn-active' : 'filter-btn-inactive'}`}>
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1.5 uppercase tracking-wide">Method</p>
            <div className="flex gap-1">
              {METHOD_OPTS.map(m => (
                <button key={m} onClick={() => setMethod(m)}
                  className={`filter-btn ${method === m ? 'filter-btn-active' : 'filter-btn-inactive'}`}>
                  {m}
                </button>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1.5 uppercase tracking-wide">Action</p>
            <div className="flex gap-1">
              {ACTION_OPTS.map(a => (
                <button key={a} onClick={() => setAction(a)}
                  className={`filter-btn ${action === a ? 'filter-btn-active' : 'filter-btn-inactive'}`}>
                  {a}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-end">
            <button onClick={() => setThreatsOnly(v => !v)}
              className={`filter-btn ${threatsOnly ? 'filter-btn-active' : 'filter-btn-inactive'}`}>
              Threats Only
            </button>
          </div>
        </div>
      </Card>

      {/* Table */}
      <Card className="overflow-hidden">
        {loading ? <LoadingSpinner /> : error ? (
          <div className="p-6 text-red-400 text-sm">{error}</div>
        ) : requests.length === 0 ? <EmptyState message="No requests match the current filters" /> : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900/60 border-b border-slate-800">
                <tr>
                  {['Time', 'Method', 'Endpoint', 'Client / IP', 'Status', 'Risk', 'Action'].map(h => (
                    <th key={h} className="table-header">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {requests.map(req => (
                  <tr key={req.id} className="table-row">
                    <td className="table-cell font-mono text-xs text-slate-400">{formatTime(req.timestamp)}</td>
                    <td className="table-cell"><MethodBadge method={req.method} /></td>
                    <td className="table-cell font-mono text-xs text-slate-300 max-w-[200px] truncate">{req.endpoint}</td>
                    <td className="table-cell">
                      <div className="text-xs">
                        <p className="text-slate-300 font-mono">{req.source_ip}</p>
                        {req.client_id && <p className="text-slate-500">{req.client_id}</p>}
                      </div>
                    </td>
                    <td className="table-cell">
                      <span className={`font-mono text-sm font-semibold ${
                        req.status_code < 300 ? 'text-green-400' :
                        req.status_code < 400 ? 'text-yellow-400' :
                        'text-red-400'
                      }`}>{req.status_code}</span>
                    </td>
                    <td className="table-cell">
                      {req.risk_score != null ? (
                        <div>
                          <RiskScore score={req.risk_score} />
                          {req.severity && <div className="mt-1"><SeverityBadge severity={req.severity} /></div>}
                        </div>
                      ) : <span className="text-slate-600 text-xs">—</span>}
                    </td>
                    <td className="table-cell">
                      {req.action ? <ActionBadge action={req.action} /> : <span className="text-slate-600 text-xs">—</span>}
                    </td>
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
