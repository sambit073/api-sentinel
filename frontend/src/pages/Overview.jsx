import { useState, useEffect } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import {
  Shield, Activity, AlertTriangle, XCircle, Zap, TrendingUp,
} from 'lucide-react';
import { api } from '../services/api';
import { SeverityBadge, ActionBadge, RiskScore, StatCard, Card, LoadingSpinner, StatusDot } from '../components/ui';

const COLORS = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
  BOLA:            '#8b5cf6',
  SQL_INJECTION:   '#ef4444',
  RATE_ABUSE:      '#f97316',
  BROKEN_AUTH:     '#eab308',
  SENSITIVE_DATA:  '#06b6d4',
};

const PIE_COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4', '#8b5cf6'];

function formatThreatType(t) {
  return t.replace(/_/g, ' ');
}

function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function SecurityScoreExplanation({ summary }) {
  const { total_requests, threats_detected, requests_blocked, critical_threats, api_security_score, protection_status } = summary;

  const threatRatioPct = total_requests > 0 ? ((threats_detected / total_requests) * 100).toFixed(1) : 0;
  const ratioPenalty = Math.round((threats_detected / Math.max(total_requests, 1)) * 60);
  const criticalPenalty = Math.round(critical_threats * 0.5);

  return (
    <Card className="p-4 bg-slate-900/80 border border-slate-800">
      <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-2">
        <div className="flex items-center gap-2">
          <Shield size={16} className={api_security_score >= 70 ? 'text-green-400' : api_security_score >= 40 ? 'text-yellow-400' : 'text-red-400'} />
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Why this score? — Security Score Factors</h3>
        </div>
        <span className={`text-xs px-2 py-0.5 rounded font-mono font-bold ${
          api_security_score >= 70 ? 'bg-green-500/10 text-green-400 border border-green-500/20' :
          api_security_score >= 40 ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' :
          'bg-red-500/10 text-red-400 border border-red-500/20'
        }`}>
          {api_security_score} / 100 ({protection_status})
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
        <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
          <p className="text-slate-500 font-medium mb-0.5">Baseline Health Score</p>
          <p className="text-sm font-bold text-emerald-400">100 / 100</p>
          <p className="text-[11px] text-slate-500 mt-1">Starting baseline prior to anomaly penalties</p>
        </div>

        <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
          <p className="text-slate-500 font-medium mb-0.5">Threat Density Impact</p>
          <p className="text-sm font-bold text-orange-400">-{ratioPenalty} pts</p>
          <p className="text-[11px] text-slate-500 mt-1">{threats_detected} threats out of {total_requests} requests ({threatRatioPct}%)</p>
        </div>

        <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
          <p className="text-slate-500 font-medium mb-0.5">Critical Threat Penalty</p>
          <p className="text-sm font-bold text-red-400">-{criticalPenalty} pts</p>
          <p className="text-[11px] text-slate-500 mt-1">{critical_threats} critical severity events recorded</p>
        </div>

        <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
          <p className="text-slate-500 font-medium mb-0.5">Automated Protection</p>
          <p className="text-sm font-bold text-cyan-400">{requests_blocked} Blocked</p>
          <p className="text-[11px] text-slate-500 mt-1">Active response controls prevent exposure escalation</p>
        </div>
      </div>
    </Card>
  );
}

export default function Overview() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = async () => {
    try {
      const data = await api.getDashboardSummary();
      setSummary(data);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <LoadingSpinner />;
  if (error) return (
    <div className="p-6 text-red-400 bg-red-500/10 rounded-xl border border-red-500/20">
      Failed to load dashboard: {error}
    </div>
  );

  const { total_requests, threats_detected, requests_blocked,
    critical_threats, api_security_score, protection_status,
    traffic_over_time, severity_distribution, threat_type_distribution,
    recent_events } = summary;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Overview</h1>
          <p className="text-slate-400 text-sm mt-0.5">Real-time API threat detection and monitoring</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 rounded-lg border border-slate-700">
          <StatusDot status={protection_status} />
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard icon={Activity} label="Total Requests" value={total_requests.toLocaleString()} color="text-cyan-400" />
        <StatCard icon={AlertTriangle} label="Threats Detected" value={threats_detected} color="text-orange-400" />
        <StatCard icon={XCircle} label="Requests Blocked" value={requests_blocked} color="text-red-400" />
        <StatCard icon={Zap} label="Critical Threats" value={critical_threats} color="text-red-500" />
        <StatCard
          icon={Shield}
          label="Security Score"
          value={`${api_security_score}`}
          sub="/100"
          color={api_security_score >= 70 ? 'text-green-400' : api_security_score >= 40 ? 'text-yellow-400' : 'text-red-400'}
        />
        <StatCard icon={TrendingUp} label="Protection" value={protection_status} color="text-cyan-400" />
      </div>

      {/* Security Score Factor Explanation */}
      <SecurityScoreExplanation summary={summary} />

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Traffic over time */}
        <Card className="lg:col-span-2 p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">
            Request Traffic (24h)
          </h2>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={traffic_over_time} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorReq" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorThr" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} />
              <YAxis tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }}
                labelStyle={{ color: '#94a3b8' }}
              />
              <Area type="monotone" dataKey="requests" stroke="#06b6d4" fill="url(#colorReq)" strokeWidth={2} name="Requests" />
              <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#colorThr)" strokeWidth={2} name="Threats" />
              <Legend formatter={(v) => <span style={{ color: '#94a3b8', fontSize: 12 }}>{v}</span>} />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        {/* Severity distribution */}
        <Card className="p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">
            Severity Distribution
          </h2>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={severity_distribution}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={3}
                dataKey="value"
              >
                {severity_distribution.map((entry) => (
                  <Cell key={entry.name} fill={COLORS[entry.name] || '#64748b'} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }}
                formatter={(v, n) => [v, n]}
              />
              <Legend
                formatter={(v) => <span style={{ color: '#94a3b8', fontSize: 11 }}>{v}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Threat types + Recent events */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat type bar chart */}
        <Card className="p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">
            Threat Types
          </h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={threat_type_distribution} layout="vertical" margin={{ left: 10, right: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} tickLine={false} width={100}
                tickFormatter={formatThreatType} />
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }}
                formatter={(v) => [v, 'Events']}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {threat_type_distribution.map((entry, i) => (
                  <Cell key={entry.name} fill={COLORS[entry.name] || PIE_COLORS[i % PIE_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Recent events feed */}
        <Card className="p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">
            Recent Security Events
          </h2>
          <div className="space-y-2 overflow-y-auto max-h-[220px] pr-1">
            {recent_events.length === 0 && (
              <p className="text-slate-500 text-sm py-4 text-center">No events yet</p>
            )}
            {recent_events.map((evt) => (
              <div
                key={evt.id}
                className="flex items-center gap-3 p-2.5 rounded-lg bg-slate-900/50 border border-slate-700/30 hover:border-slate-600/50 transition-colors"
              >
                <SeverityBadge severity={evt.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-slate-200 truncate">
                    {formatThreatType(evt.threat_type)}
                  </p>
                  <p className="text-xs text-slate-500 truncate font-mono">{evt.endpoint}</p>
                </div>
                <div className="text-right flex-shrink-0">
                  <RiskScore score={evt.risk_score} />
                  <p className="text-xs text-slate-600 mt-0.5">{timeAgo(evt.timestamp)}</p>
                </div>
                <ActionBadge action={evt.action} />
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
