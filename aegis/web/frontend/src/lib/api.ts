const API_BASE = '/api'

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
  
  // Stats
  getStats: () => fetchApi<any>('/stats'),
}
