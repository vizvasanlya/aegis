const API_BASE = '/api';

async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchScans(params = {}) {
  const qs = new URLSearchParams();
  if (params.search) qs.set('search', params.search);
  if (params.status) qs.set('status', params.status);
  if (params.sort) qs.set('sort', params.sort);
  const query = qs.toString();
  return apiFetch(`/scans${query ? `?${query}` : ''}`);
}

export async function fetchStats() {
  return apiFetch('/stats');
}

export async function fetchScan(scanId) {
  return apiFetch(`/scans/${encodeURIComponent(scanId)}`);
}

export async function fetchVulnerabilities(scanId, severity) {
  const qs = severity ? `?severity=${encodeURIComponent(severity)}` : '';
  return apiFetch(`/scans/${encodeURIComponent(scanId)}/vulnerabilities${qs}`);
}

export async function fetchVulnerabilityDetail(scanId, vulnId) {
  return apiFetch(`/scans/${encodeURIComponent(scanId)}/vulnerabilities/${encodeURIComponent(vulnId)}`);
}

export function getExportUrl(scanId, format = 'json') {
  return `${API_BASE}/scans/${encodeURIComponent(scanId)}/export?format=${format}`;
}

export function getSseUrl(scanId) {
  return `${API_BASE}/scans/${encodeURIComponent(scanId)}/stream`;
}

export async function uploadMobileApp(file, scanMode = 'standard', instruction = '') {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('scan_mode', scanMode);
  if (instruction) formData.append('instruction', instruction);
  const res = await fetch(`${API_BASE}/mobile/scan`, { method: 'POST', body: formData });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export function formatDate(dateStr) {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr.replace('Z', '+00:00').replace(' ', 'T'));
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch { return dateStr; }
}

export function formatCost(cost) {
  if (cost == null || cost === 0) return '—';
  if (cost < 0.01) return '<$0.01';
  return `$${Number(cost).toFixed(4)}`;
}

export function formatNumber(n) {
  if (n == null) return '—';
  return Number(n).toLocaleString();
}
