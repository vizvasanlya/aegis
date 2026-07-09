const API_BASE = '/api'

// ─── Date Formatting ────────────────────────────────────────────────────────

export function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '-'
  const d = new Date(dateStr)
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })
}

export function formatDateTime(dateStr: string | null | undefined): string {
  if (!dateStr) return '-'
  const d = new Date(dateStr)
  const date = d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })
  const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  return `${date} ${time}`
}

export async function fetchApi<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  })
  
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`)
  }
  
  return res.json()
}

export const api = {
  // Scans
  listScans: () => fetchApi<any[]>('/scans'),
  getScan: (id: string) => fetchApi<any>(`/scans/${id}`),
  createScan: (data: any) => fetchApi<any>('/scans', { method: 'POST', body: JSON.stringify(data) }),
  deleteScan: (id: string) => fetchApi<any>(`/scans/${id}`, { method: 'DELETE' }),

  // API Scanning
  createApiScan: (data: any) => fetchApi<any>('/api-scan', { method: 'POST', body: JSON.stringify(data) }),

  // Internal Network Testing
  createInternalScan: (data: any) => fetchApi<any>('/internal-scan', { method: 'POST', body: JSON.stringify(data) }),

  // Mobile Scanning
  createMobileScan: (data: any) => fetchApi<any>('/mobile-scan', { method: 'POST', body: JSON.stringify(data) }),
  uploadMobileApp: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    const res = await fetch(`${API_BASE}/mobile-scan/upload`, { method: 'POST', body: formData })
    if (!res.ok) throw new Error(`Upload failed: ${res.status}`)
    return res.json()
  },

  // Mobile Apps Management
  listMobileApps: () => fetchApi<any[]>('/mobile-apps'),
  createMobileApp: (data: any) => fetchApi<any>('/mobile-apps', { method: 'POST', body: JSON.stringify(data) }),
  getMobileApp: (id: number) => fetchApi<any>(`/mobile-apps/${id}`),
  updateMobileApp: (id: number, data: any) => fetchApi<any>(`/mobile-apps/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteMobileApp: (id: number) => fetchApi<any>(`/mobile-apps/${id}`, { method: 'DELETE' }),
  listMobileAppScans: (id: number) => fetchApi<any[]>(`/mobile-apps/${id}/scans`),

  // Vulnerabilities
  listVulnerabilities: () => fetchApi<any[]>('/vulnerabilities'),
  getScanVulnerabilities: (scanId: string) => fetchApi<any[]>(`/scans/${scanId}/vulnerabilities`),

  // Credentials
  listCredentials: () => fetchApi<any[]>('/credentials'),
  createCredential: (data: any) => fetchApi<any>('/credentials', { method: 'POST', body: JSON.stringify(data) }),
  getCredential: (id: number) => fetchApi<any>(`/credentials/${id}`),
  updateCredential: (id: number, data: any) => fetchApi<any>(`/credentials/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteCredential: (id: number) => fetchApi<any>(`/credentials/${id}`, { method: 'DELETE' }),
  getCredentialForScan: (id: number) => fetchApi<any>(`/credentials/${id}/for-scan`),

  // Repos
  listRepos: () => fetchApi<any[]>('/repos'),
  addRepo: (data: any) => fetchApi<any>('/repos', { method: 'POST', body: JSON.stringify(data) }),
  deleteRepo: (id: number) => fetchApi<any>(`/repos/${id}`, { method: 'DELETE' }),
  scanRepo: (id: number) => fetchApi<any>(`/repos/${id}/scan`, { method: 'POST' }),

  // Git
  scanGitRepo: (data: any) => fetchApi<any>('/git/scan', { method: 'POST', body: JSON.stringify(data) }),

  // API Endpoints
  listApiEndpoints: () => fetchApi<any[]>('/api-endpoints'),
  createApiEndpoint: (data: any) => fetchApi<any>('/api-endpoints', { method: 'POST', body: JSON.stringify(data) }),
  getApiEndpoint: (id: number) => fetchApi<any>(`/api-endpoints/${id}`),
  updateApiEndpoint: (id: number, data: any) => fetchApi<any>(`/api-endpoints/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteApiEndpoint: (id: number) => fetchApi<any>(`/api-endpoints/${id}`, { method: 'DELETE' }),
  testApiEndpoint: (id: number, data: any) => fetchApi<any>(`/api-endpoints/${id}/test`, { method: 'POST', body: JSON.stringify(data) }),
  listApiHistory: (endpointId?: number) => fetchApi<any[]>(`/api-history${endpointId ? `?endpoint_id=${endpointId}` : ''}`),
  clearApiHistory: () => fetchApi<any>('/api-history', { method: 'DELETE' }),
  parseOpenApiSchema: (url: string) => fetchApi<any>('/openapi/parse', { method: 'POST', body: JSON.stringify({ url }) }),

  // Auth / OAuth
  getAuthStatus: (provider: string) => fetchApi<any>(`/auth/${provider}/status`),
  disconnectAuth: (provider: string) => fetchApi<any>(`/auth/${provider}`, { method: 'DELETE' }),
  listProviderRepos: (provider: string) => fetchApi<any[]>(`/auth/${provider}/repos`),

  // Settings
  getSettings: () => fetchApi<any>('/settings'),
  updateSettings: (data: any) => fetchApi<any>('/settings', { method: 'PUT', body: JSON.stringify(data) }),

  // Skills
  listSkills: () => fetchApi<any>('/skills'),

  // Logs
  getLogs: (scanId: string, lines?: number) => fetchApi<any>(`/scans/${scanId}/logs?lines=${lines || 100}`),

  // Report
  getReportUrl: (scanId: string) => `${API_BASE}/scans/${scanId}/report`,
  getSarifUrl: (scanId: string) => `${API_BASE}/scans/${scanId}/sarif`,

  // Stats
  getStats: () => fetchApi<any>('/stats'),

  // Dashboard
  getDashboard: () => fetchApi<any>('/stats'),
}
