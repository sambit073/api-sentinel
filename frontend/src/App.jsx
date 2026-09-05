import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { Shield, Activity, AlertTriangle, Globe, Zap } from 'lucide-react';

import Overview from './pages/Overview';
import LiveTraffic from './pages/LiveTraffic';
import Threats from './pages/Threats';
import Endpoints from './pages/Endpoints';
import Simulator from './pages/Simulator';

const NAV_ITEMS = [
  { to: '/',          label: 'Overview',        Icon: Shield },
  { to: '/traffic',   label: 'Live Traffic',     Icon: Activity },
  { to: '/threats',   label: 'Threats',          Icon: AlertTriangle },
  { to: '/endpoints', label: 'Endpoints',        Icon: Globe },
  { to: '/simulator', label: 'Attack Simulator', Icon: Zap },
];

function Sidebar() {
  return (
    <aside className="w-60 flex-shrink-0 flex flex-col bg-slate-900/80 border-r border-slate-800/60 backdrop-blur-sm">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-slate-800/60">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
            <Shield size={16} className="text-cyan-400" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-white tracking-wide">API Sentinel</h1>
            <p className="text-xs text-slate-500">Security Platform</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV_ITEMS.map(({ to, label, Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `nav-link${isActive ? ' active' : ''}`
            }
          >
            <Icon size={16} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-slate-800/60">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-xs text-slate-500">Detection Engine Active</span>
        </div>
      </div>
    </aside>
  );
}

function Layout() {
  const location = useLocation();
  const current = NAV_ITEMS.find(n => n.to === location.pathname)?.label || 'API Sentinel';

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        {/* Top bar */}
        <header className="sticky top-0 z-10 bg-slate-950/80 backdrop-blur-sm border-b border-slate-800/60 px-6 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <span className="text-slate-400 font-medium">{current}</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <span>Live Monitoring</span>
            </div>
          </div>
        </header>

        <div className="p-6">
          <Routes>
            <Route path="/"          element={<Overview />} />
            <Route path="/traffic"   element={<LiveTraffic />} />
            <Route path="/threats"   element={<Threats />} />
            <Route path="/endpoints" element={<Endpoints />} />
            <Route path="/simulator" element={<Simulator />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Layout />
    </BrowserRouter>
  );
}
