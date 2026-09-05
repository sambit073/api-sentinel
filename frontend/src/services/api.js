import API_BASE from '../config/api';

async function apiFetch(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  health: () => apiFetch('/health'),

  getDashboardSummary: () => apiFetch('/dashboard/summary'),

  getRequests: (params = {}) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v != null && q.append(k, v));
    return apiFetch(`/requests?${q}`);
  },

  getThreats: (params = {}) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v != null && q.append(k, v));
    return apiFetch(`/threats?${q}`);
  },

  getThreat: (id) => apiFetch(`/threats/${id}`),

  getEndpoints: () => apiFetch('/endpoints'),

  simulate: (scenario) =>
    apiFetch('/simulate', {
      method: 'POST',
      body: JSON.stringify({ scenario }),
    }),

  analyze: (payload) =>
    apiFetch('/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};
