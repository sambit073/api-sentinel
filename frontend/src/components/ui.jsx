// Severity badge component
export const SEVERITY_CONFIG = {
  CRITICAL: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/40', dot: 'bg-red-500' },
  HIGH:     { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/40', dot: 'bg-orange-500' },
  MEDIUM:   { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/40', dot: 'bg-yellow-500' },
  LOW:      { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/40', dot: 'bg-green-500' },
};

export const ACTION_CONFIG = {
  BLOCK:     { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
  CHALLENGE: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30' },
  MONITOR:   { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  ALLOW:     { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30' },
};

export function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.LOW;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {severity}
    </span>
  );
}

export function ActionBadge({ action }) {
  const cfg = ACTION_CONFIG[action] || ACTION_CONFIG.ALLOW;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      {action}
    </span>
  );
}

export function RiskScore({ score }) {
  const color =
    score >= 80 ? 'text-red-400' :
    score >= 60 ? 'text-orange-400' :
    score >= 30 ? 'text-yellow-400' :
    'text-green-400';
  return (
    <span className={`font-bold tabular-nums ${color}`}>
      {score != null ? score.toFixed(0) : '—'}
      <span className="text-slate-500 font-normal text-xs">/100</span>
    </span>
  );
}

export function StatusDot({ status }) {
  const colors = {
    HEALTHY: 'bg-green-400',
    AT_RISK: 'bg-yellow-400',
    CRITICAL: 'bg-red-400',
    PROTECTED: 'bg-green-400',
  };
  const labels = {
    HEALTHY: 'text-green-400',
    AT_RISK: 'text-yellow-400',
    CRITICAL: 'text-red-400',
    PROTECTED: 'text-green-400',
  };
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold ${labels[status] || 'text-slate-400'}`}>
      <span className={`w-2 h-2 rounded-full animate-pulse ${colors[status] || 'bg-slate-400'}`} />
      {status}
    </span>
  );
}

export function Card({ children, className = '' }) {
  return (
    <div className={`bg-slate-800/60 border border-slate-700/50 rounded-xl backdrop-blur-sm ${className}`}>
      {children}
    </div>
  );
}

export function StatCard({ icon: Icon, label, value, sub, color = 'text-cyan-400' }) {
  return (
    <Card className="p-5 flex items-start gap-4">
      <div className={`p-2.5 rounded-lg bg-slate-700/50 ${color}`}>
        <Icon size={20} />
      </div>
      <div className="min-w-0">
        <p className="text-slate-400 text-xs font-medium uppercase tracking-wide">{label}</p>
        <p className={`text-2xl font-bold mt-0.5 ${color}`}>{value}</p>
        {sub && <p className="text-slate-500 text-xs mt-0.5">{sub}</p>}
      </div>
    </Card>
  );
}

export function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center p-12">
      <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

export function EmptyState({ message = 'No data available' }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-slate-500">
      <svg className="w-12 h-12 mb-3 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
          d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
      <p className="text-sm">{message}</p>
    </div>
  );
}

export function MethodBadge({ method }) {
  const colors = {
    GET:    'text-green-400 bg-green-500/10 border-green-500/20',
    POST:   'text-blue-400 bg-blue-500/10 border-blue-500/20',
    PUT:    'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    PATCH:  'text-orange-400 bg-orange-500/10 border-orange-500/20',
    DELETE: 'text-red-400 bg-red-500/10 border-red-500/20',
  };
  return (
    <span className={`font-mono text-xs font-bold px-1.5 py-0.5 rounded border ${colors[method] || 'text-slate-400'}`}>
      {method}
    </span>
  );
}
