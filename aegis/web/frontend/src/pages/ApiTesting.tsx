import { useState, useEffect, useRef } from 'react'
import {
  Code,
  Plus,
  Trash2,
  Play,
  Loader2,
  Check,
  AlertCircle,
  Search,
  Clock,
  ChevronRight,
  ChevronDown,
  Edit3,
  Save,
  X,
  FileCode2,
  Globe,
  Lock,
  Key,
  Copy,
  RefreshCw,
  History,
  BookOpen,
  Send,
  ArrowRight,
  Zap,
  Shield,
  Eye,
  EyeOff,
} from 'lucide-react'
import { api, formatDate, formatDateTime } from '../lib/api'

// ─── Types ──────────────────────────────────────────────────────────────────

interface ApiEndpoint {
  id: number
  name: string
  base_url: string
  api_type: string
  auth_type: string | null
  auth_config: Record<string, string> | null
  openapi_url: string | null
  headers: Record<string, string> | null
  notes: string | null
  created_at: string
  last_tested: string | null
  total_requests: number
}

interface HistoryEntry {
  id: number
  endpoint_id: number
  endpoint_name: string
  method: string
  path: string
  url: string
  status_code: number
  elapsed_ms: number
  size_bytes: number
  timestamp: string
  request_headers: Record<string, string>
  request_body: string | null
  response_headers: Record<string, string>
  response_body: string
}

interface ParsedSchema {
  title: string
  version: string
  description: string
  total_endpoints: number
  endpoints: {
    method: string
    path: string
    summary: string
    operationId: string
    tags: string[]
    parameters: any[]
    requestBody: any
  }[]
}

type Tab = 'request' | 'history' | 'schema'

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
const METHOD_COLORS: Record<string, string> = {
  GET: 'bg-green-900/50 text-green-400',
  POST: 'bg-blue-900/50 text-blue-400',
  PUT: 'bg-orange-900/50 text-orange-400',
  DELETE: 'bg-red-900/50 text-red-400',
  PATCH: 'bg-yellow-900/50 text-yellow-400',
  HEAD: 'bg-gray-800 text-gray-400',
  OPTIONS: 'bg-gray-800 text-gray-400',
}

const AUTH_TYPES = [
  { value: 'none', label: 'No Auth', icon: Shield },
  { value: 'api_key', label: 'API Key', icon: Key },
  { value: 'bearer', label: 'Bearer Token', icon: Lock },
  { value: 'basic', label: 'Basic Auth', icon: Lock },
]

// ─── Main Component ─────────────────────────────────────────────────────────

export default function ApiTesting() {
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([])
  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpoint | null>(null)
  const [activeTab, setActiveTab] = useState<Tab>('request')
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [showSchemaModal, setShowSchemaModal] = useState(false)

  // Request state
  const [method, setMethod] = useState('GET')
  const [path, setPath] = useState('/')
  const [headers, setHeaders] = useState('')
  const [body, setBody] = useState('')
  const [sending, setSending] = useState(false)
  const [response, setResponse] = useState<any>(null)

  // History
  const [history, setHistory] = useState<HistoryEntry[]>([])

  useEffect(() => {
    loadEndpoints()
  }, [])

  const loadEndpoints = async () => {
    setLoading(true)
    try {
      const data = await api.listApiEndpoints()
      setEndpoints(data)
    } finally {
      setLoading(false)
    }
  }

  const selectEndpoint = async (ep: ApiEndpoint) => {
    setSelectedEndpoint(ep)
    setPath('/')
    setHeaders(ep.headers ? JSON.stringify(ep.headers, null, 2) : '')
    setBody('')
    setResponse(null)
    setActiveTab('request')
    // Load history for this endpoint
    try {
      const hist = await api.listApiHistory(ep.id)
      setHistory(hist.reverse())
    } catch {
      setHistory([])
    }
  }

  const handleSend = async () => {
    if (!selectedEndpoint) return
    setSending(true)
    setResponse(null)
    try {
      let parsedHeaders: Record<string, string> = {}
      if (headers.trim()) {
        try {
          parsedHeaders = JSON.parse(headers)
        } catch {
          setResponse({ error: 'Invalid headers JSON' })
          setSending(false)
          return
        }
      }

      const result = await api.testApiEndpoint(selectedEndpoint.id, {
        endpoint_id: selectedEndpoint.id,
        method,
        path: path.startsWith('/') ? path : `/${path}`,
        headers: parsedHeaders,
        body: body || undefined,
        content_type: 'application/json',
      })

      setResponse(result)
      // Refresh history
      const hist = await api.listApiHistory(selectedEndpoint.id)
      setHistory(hist.reverse())
    } catch (err: any) {
      setResponse({ error: err.message || 'Request failed' })
    } finally {
      setSending(false)
    }
  }

  const handleScanEndpoint = async () => {
    if (!selectedEndpoint) return
    try {
      const result = await api.createApiScan({
        endpoint: selectedEndpoint.base_url,
        method,
        api_type: selectedEndpoint.api_type,
        scan_mode: 'standard',
        instruction: `Test ${selectedEndpoint.name} API for security vulnerabilities`,
      })
      window.location.href = `/pentest/${result.scan_id}`
    } catch (err: any) {
      alert('Failed to start scan: ' + err.message)
    }
  }

  return (
    <div className="flex h-full">
      {/* Left Sidebar - Endpoints */}
      <div className="w-72 flex-shrink-0 border-r border-gray-800 bg-gray-900/50 flex flex-col">
        <div className="border-b border-gray-800 p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-white">API Endpoints</h2>
            <button
              onClick={() => setShowAddModal(true)}
              className="rounded-lg bg-cyan-600 p-1.5 text-white hover:bg-cyan-700 transition-colors"
            >
              <Plus className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-gray-400" />
            </div>
          ) : endpoints.length === 0 ? (
            <div className="p-4 text-center">
              <Code className="mx-auto h-8 w-8 text-gray-600" />
              <p className="mt-2 text-xs text-gray-500">No endpoints saved</p>
              <button
                onClick={() => setShowAddModal(true)}
                className="mt-2 text-xs text-cyan-400 hover:text-cyan-300"
              >
                Add your first endpoint
              </button>
            </div>
          ) : (
            <div className="p-2">
              {endpoints.map((ep) => (
                <button
                  key={ep.id}
                  onClick={() => selectEndpoint(ep)}
                  className={`w-full rounded-lg p-3 text-left transition-colors ${
                    selectedEndpoint?.id === ep.id
                      ? 'bg-cyan-900/30 border border-cyan-800'
                      : 'hover:bg-gray-800 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${METHOD_COLORS[ep.api_type === 'graphql' ? 'POST' : 'GET']}`}>
                      {ep.api_type.toUpperCase()}
                    </span>
                    <span className="text-sm font-medium text-white truncate">{ep.name}</span>
                  </div>
                  <p className="mt-1 text-xs text-gray-500 truncate">{ep.base_url}</p>
                  {ep.last_tested && (
                    <p className="mt-0.5 text-[10px] text-gray-600">
                      Last tested: {formatDate(ep.last_tested)}
                    </p>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {selectedEndpoint ? (
          <>
            {/* Endpoint Header */}
            <div className="border-b border-gray-800 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-lg font-semibold text-white">{selectedEndpoint.name}</h1>
                  <p className="text-sm text-gray-400 font-mono">{selectedEndpoint.base_url}</p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleScanEndpoint}
                    className="flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700 transition-colors"
                  >
                    <Zap className="h-4 w-4" />
                    Security Scan
                  </button>
                  <button
                    onClick={() => { setSelectedEndpoint(null); setResponse(null) }}
                    className="rounded-lg p-2 text-gray-400 hover:bg-gray-800 hover:text-white"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-gray-800 px-4">
              <div className="flex gap-1">
                {[
                  { key: 'request', label: 'Request Builder', icon: Send },
                  { key: 'history', label: `History (${history.length})`, icon: History },
                  { key: 'schema', label: 'Schema', icon: BookOpen },
                ].map((tab) => {
                  const Icon = tab.icon
                  return (
                    <button
                      key={tab.key}
                      onClick={() => setActiveTab(tab.key as Tab)}
                      className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
                        activeTab === tab.key
                          ? 'border-cyan-500 text-cyan-400'
                          : 'border-transparent text-gray-400 hover:text-white'
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                      {tab.label}
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-hidden">
              {activeTab === 'request' && (
                <RequestBuilder
                  method={method}
                  setMethod={setMethod}
                  path={path}
                  setPath={setPath}
                  headers={headers}
                  setHeaders={setHeaders}
                  body={body}
                  setBody={setBody}
                  sending={sending}
                  response={response}
                  onSend={handleSend}
                  apiType={selectedEndpoint.api_type}
                />
              )}
              {activeTab === 'history' && (
                <HistoryPanel
                  history={history}
                  onSelect={(entry) => {
                    setMethod(entry.method)
                    setPath(entry.path)
                    setHeaders(JSON.stringify(entry.request_headers, null, 2))
                    setBody(entry.request_body || '')
                    setActiveTab('request')
                  }}
                />
              )}
              {activeTab === 'schema' && (
                <SchemaPanel endpoint={selectedEndpoint} />
              )}
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <Code className="mx-auto h-16 w-16 text-gray-700" />
              <h2 className="mt-4 text-lg font-medium text-gray-400">No endpoint selected</h2>
              <p className="mt-1 text-sm text-gray-500">Select an endpoint from the sidebar or add a new one</p>
              <button
                onClick={() => setShowAddModal(true)}
                className="mt-4 rounded-lg bg-cyan-600 px-5 py-2.5 font-medium text-white hover:bg-cyan-700"
              >
                Add Endpoint
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Add Endpoint Modal */}
      {showAddModal && (
        <AddEndpointModal
          onClose={() => setShowAddModal(false)}
          onAdd={async (data) => {
            const ep = await api.createApiEndpoint(data)
            setEndpoints([...endpoints, ep])
            setShowAddModal(false)
            selectEndpoint(ep)
          }}
        />
      )}
    </div>
  )
}

// ─── Request Builder ────────────────────────────────────────────────────────

function RequestBuilder({
  method,
  setMethod,
  path,
  setPath,
  headers,
  setHeaders,
  body,
  setBody,
  sending,
  response,
  onSend,
  apiType,
}: {
  method: string
  setMethod: (m: string) => void
  path: string
  setPath: (p: string) => void
  headers: string
  setHeaders: (h: string) => void
  body: string
  setBody: (b: string) => void
  sending: boolean
  response: any
  onSend: () => void
  apiType: string
}) {
  return (
    <div className="flex flex-col h-full overflow-auto p-4">
      {/* URL Bar */}
      <div className="flex gap-2 mb-4">
        <select
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          className="rounded-xl border border-gray-700 bg-gray-800 px-3 py-3 text-sm font-bold text-white focus:border-cyan-500 focus:outline-none"
        >
          {METHODS.map((m) => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
        <input
          type="text"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="/api/v1/users"
          className="flex-1 rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 font-mono text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
        />
        <button
          onClick={onSend}
          disabled={sending}
          className="flex items-center gap-2 rounded-xl bg-cyan-600 px-6 py-3 font-medium text-white hover:bg-cyan-700 disabled:opacity-50 transition-colors"
        >
          {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
          {sending ? 'Sending...' : 'Send'}
        </button>
      </div>

      {/* Request Config */}
      <div className="grid grid-cols-2 gap-4 mb-4">
        {/* Headers */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Headers (JSON)</label>
          <textarea
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
            placeholder='{"Content-Type": "application/json"}'
            rows={4}
            className="w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 font-mono text-xs text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none resize-none"
          />
        </div>

        {/* Body */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Body</label>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder={apiType === 'graphql' ? '{ "query": "query { users { id name } }" }' : '{"key": "value"}'}
            rows={4}
            className="w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 font-mono text-xs text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none resize-none"
          />
        </div>
      </div>

      {/* Response */}
      {response && (
        <div className="flex-1 rounded-xl border border-gray-800 bg-gray-900/50 overflow-hidden">
          <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
            <div className="flex items-center gap-3">
              <span className="text-sm font-medium text-white">Response</span>
              {response.status_code !== undefined && (
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-bold ${
                  response.status_code >= 200 && response.status_code < 300
                    ? 'bg-green-900/50 text-green-400'
                    : response.status_code >= 400
                    ? 'bg-red-900/50 text-red-400'
                    : 'bg-yellow-900/50 text-yellow-400'
                }`}>
                  {response.status_code} {response.status_text}
                </span>
              )}
              {response.elapsed_ms !== undefined && (
                <span className="text-xs text-gray-500">{response.elapsed_ms}ms</span>
              )}
              {response.size_bytes !== undefined && (
                <span className="text-xs text-gray-500">
                  {response.size_bytes > 1024
                    ? `${(response.size_bytes / 1024).toFixed(1)} KB`
                    : `${response.size_bytes} B`}
                </span>
              )}
            </div>
            <button
              onClick={() => navigator.clipboard.writeText(response.body || response.error || '')}
              className="rounded p-1.5 text-gray-400 hover:bg-gray-800 hover:text-white"
            >
              <Copy className="h-4 w-4" />
            </button>
          </div>
          <div className="p-4 max-h-[400px] overflow-auto">
            {response.error ? (
              <p className="text-sm text-red-400">{response.error}</p>
            ) : (
              <pre className="font-mono text-xs text-gray-300 whitespace-pre-wrap">
                {response.body}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── History Panel ──────────────────────────────────────────────────────────

function HistoryPanel({
  history,
  onSelect,
}: {
  history: HistoryEntry[]
  onSelect: (entry: HistoryEntry) => void
}) {
  const [search, setSearch] = useState('')

  const filtered = history.filter(
    (h) =>
      h.path.toLowerCase().includes(search.toLowerCase()) ||
      h.method.toLowerCase().includes(search.toLowerCase()) ||
      String(h.status_code).includes(search)
  )

  return (
    <div className="h-full flex flex-col p-4">
      <div className="mb-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search history..."
            className="w-full rounded-xl border border-gray-800 bg-gray-900/50 py-2.5 pl-10 pr-4 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-gray-500">
            <History className="h-10 w-10 mb-3 text-gray-600" />
            <p className="text-sm">No request history</p>
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((entry) => (
              <button
                key={entry.id}
                onClick={() => onSelect(entry)}
                className="w-full rounded-xl border border-gray-800 bg-gray-900/50 p-3 text-left hover:border-gray-700 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${METHOD_COLORS[entry.method]}`}>
                      {entry.method}
                    </span>
                    <span className="text-sm text-gray-300 font-mono truncate max-w-[300px]">
                      {entry.path}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`text-xs font-medium ${
                      entry.status_code >= 200 && entry.status_code < 300
                        ? 'text-green-400'
                        : entry.status_code >= 400
                        ? 'text-red-400'
                        : 'text-yellow-400'
                    }`}>
                      {entry.status_code}
                    </span>
                    <span className="text-xs text-gray-500">{entry.elapsed_ms}ms</span>
                  </div>
                </div>
                <p className="mt-1 text-[10px] text-gray-600">
                  {formatDateTime(entry.timestamp)}
                </p>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Schema Panel ───────────────────────────────────────────────────────────

function SchemaPanel({ endpoint }: { endpoint: ApiEndpoint }) {
  const [openApiUrl, setOpenApiUrl] = useState(endpoint.openapi_url || '')
  const [schema, setSchema] = useState<ParsedSchema | null>(null)
  const [parsing, setParsing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expandedPath, setExpandedPath] = useState<string | null>(null)

  const handleParse = async () => {
    if (!openApiUrl.trim()) return
    setParsing(true)
    setError(null)
    try {
      const result = await api.parseOpenApiSchema(openApiUrl)
      setSchema(result)
    } catch (err: any) {
      setError(err.message || 'Failed to parse schema')
    } finally {
      setParsing(false)
    }
  }

  return (
    <div className="h-full flex flex-col p-4">
      <div className="mb-4 rounded-xl border border-gray-800 bg-gray-900/50 p-4">
        <h3 className="text-sm font-medium text-white mb-2">OpenAPI / Swagger Schema</h3>
        <p className="text-xs text-gray-400 mb-3">
          Import an OpenAPI schema to discover all available endpoints and their parameters
        </p>
        <div className="flex gap-2">
          <input
            type="text"
            value={openApiUrl}
            onChange={(e) => setOpenApiUrl(e.target.value)}
            placeholder="https://api.example.com/swagger.json"
            className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
          />
          <button
            onClick={handleParse}
            disabled={parsing || !openApiUrl.trim()}
            className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-700 disabled:opacity-50"
          >
            {parsing ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileCode2 className="h-4 w-4" />}
            {parsing ? 'Parsing...' : 'Parse'}
          </button>
        </div>
        {error && (
          <p className="mt-2 text-xs text-red-400">{error}</p>
        )}
      </div>

      {schema && (
        <div className="flex-1 overflow-y-auto">
          <div className="mb-4 rounded-xl border border-gray-800 bg-gray-900/50 p-4">
            <h3 className="font-semibold text-white">{schema.title}</h3>
            {schema.version && <p className="text-xs text-gray-400">v{schema.version}</p>}
            {schema.description && <p className="mt-1 text-sm text-gray-400">{schema.description}</p>}
            <p className="mt-2 text-xs text-cyan-400">{schema.total_endpoints} endpoints discovered</p>
          </div>

          <div className="space-y-2">
            {schema.endpoints.map((ep, idx) => {
              const key = `${ep.method}-${ep.path}`
              const isExpanded = expandedPath === key
              return (
                <div key={idx} className="rounded-xl border border-gray-800 bg-gray-900/50">
                  <button
                    onClick={() => setExpandedPath(isExpanded ? null : key)}
                    className="flex w-full items-center gap-3 p-3 text-left"
                  >
                    <span className={`rounded px-2 py-0.5 text-[10px] font-bold ${METHOD_COLORS[ep.method]}`}>
                      {ep.method.toUpperCase()}
                    </span>
                    <span className="text-sm font-mono text-gray-300">{ep.path}</span>
                    {ep.summary && (
                      <span className="text-xs text-gray-500 truncate">{ep.summary}</span>
                    )}
                    <ChevronRight className={`h-4 w-4 text-gray-500 ml-auto transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                  </button>
                  {isExpanded && (
                    <div className="border-t border-gray-800 p-3 space-y-2">
                      {ep.operationId && (
                        <p className="text-xs text-gray-400">
                          <span className="text-gray-500">Operation ID:</span>{' '}
                          <span className="font-mono text-cyan-400">{ep.operationId}</span>
                        </p>
                      )}
                      {ep.tags.length > 0 && (
                        <div className="flex gap-1">
                          {ep.tags.map((tag) => (
                            <span key={tag} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                      {ep.parameters.length > 0 && (
                        <div>
                          <p className="text-xs text-gray-500 mb-1">Parameters:</p>
                          {ep.parameters.map((p, pi) => (
                            <p key={pi} className="text-xs text-gray-400 font-mono">
                              {p.name} ({p.in}){p.required ? ' *' : ''}
                            </p>
                          ))}
                        </div>
                      )}
                      {ep.requestBody && (
                        <p className="text-xs text-gray-400">
                          <span className="text-gray-500">Request Body:</span> defined
                        </p>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Add Endpoint Modal ─────────────────────────────────────────────────────

function AddEndpointModal({
  onClose,
  onAdd,
}: {
  onClose: () => void
  onAdd: (data: any) => Promise<void>
}) {
  const [form, setForm] = useState({
    name: '',
    base_url: '',
    api_type: 'rest',
    auth_type: 'none',
    openapi_url: '',
    notes: '',
  })
  const [authConfig, setAuthConfig] = useState<Record<string, string>>({})
  const [headers, setHeaders] = useState('')
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    if (!form.name || !form.base_url) return
    setSaving(true)
    try {
      let parsedHeaders: Record<string, string> = {}
      if (headers.trim()) {
        try {
          parsedHeaders = JSON.parse(headers)
        } catch {
          alert('Invalid headers JSON')
          setSaving(false)
          return
        }
      }

      await onAdd({
        name: form.name,
        base_url: form.base_url,
        api_type: form.api_type,
        auth_type: form.auth_type === 'none' ? null : form.auth_type,
        auth_config: form.auth_type !== 'none' ? authConfig : null,
        openapi_url: form.openapi_url || null,
        headers: Object.keys(parsedHeaders).length > 0 ? parsedHeaders : null,
        notes: form.notes || null,
      })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-2xl border border-gray-800 bg-gray-900 p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-white">Add API Endpoint</h2>
          <button onClick={onClose} className="rounded-lg p-1 text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="My API"
              className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              autoFocus
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300">Base URL</label>
            <input
              type="text"
              value={form.base_url}
              onChange={(e) => setForm({ ...form, base_url: e.target.value })}
              placeholder="https://api.example.com/v1"
              className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 font-mono text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">API Type</label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { value: 'rest', label: 'REST' },
                { value: 'graphql', label: 'GraphQL' },
                { value: 'grpc', label: 'gRPC' },
                { value: 'websocket', label: 'WebSocket' },
              ].map((t) => (
                <button
                  key={t.value}
                  type="button"
                  onClick={() => setForm({ ...form, api_type: t.value })}
                  className={`rounded-lg border p-2.5 text-sm font-medium transition-colors ${
                    form.api_type === t.value
                      ? 'border-cyan-500 bg-cyan-900/30 text-cyan-400'
                      : 'border-gray-700 bg-gray-800 text-gray-400 hover:border-gray-600'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Authentication</label>
            <div className="grid grid-cols-2 gap-2">
              {AUTH_TYPES.map((a) => {
                const Icon = a.icon
                return (
                  <button
                    key={a.value}
                    type="button"
                    onClick={() => setForm({ ...form, auth_type: a.value })}
                    className={`flex items-center gap-2 rounded-lg border p-2.5 text-sm font-medium transition-colors ${
                      form.auth_type === a.value
                        ? 'border-cyan-500 bg-cyan-900/30 text-cyan-400'
                        : 'border-gray-700 bg-gray-800 text-gray-400 hover:border-gray-600'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    {a.label}
                  </button>
                )
              })}
            </div>

            {form.auth_type === 'api_key' && (
              <div className="mt-3 space-y-2">
                <input
                  type="text"
                  value={authConfig.key_name || ''}
                  onChange={(e) => setAuthConfig({ ...authConfig, key_name: e.target.value })}
                  placeholder="Header name (e.g., X-API-Key)"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                />
                <input
                  type="password"
                  value={authConfig.key || ''}
                  onChange={(e) => setAuthConfig({ ...authConfig, key: e.target.value })}
                  placeholder="API Key value"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                />
                <select
                  value={authConfig.key_in || 'header'}
                  onChange={(e) => setAuthConfig({ ...authConfig, key_in: e.target.value })}
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none"
                >
                  <option value="header">Send in Header</option>
                  <option value="query">Send in Query Parameter</option>
                </select>
              </div>
            )}

            {form.auth_type === 'bearer' && (
              <div className="mt-3">
                <input
                  type="password"
                  value={authConfig.token || ''}
                  onChange={(e) => setAuthConfig({ ...authConfig, token: e.target.value })}
                  placeholder="Bearer token"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            )}

            {form.auth_type === 'basic' && (
              <div className="mt-3 space-y-2">
                <input
                  type="text"
                  value={authConfig.username || ''}
                  onChange={(e) => setAuthConfig({ ...authConfig, username: e.target.value })}
                  placeholder="Username"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                />
                <input
                  type="password"
                  value={authConfig.password || ''}
                  onChange={(e) => setAuthConfig({ ...authConfig, password: e.target.value })}
                  placeholder="Password"
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300">OpenAPI Spec URL (Optional)</label>
            <input
              type="text"
              value={form.openapi_url}
              onChange={(e) => setForm({ ...form, openapi_url: e.target.value })}
              placeholder="https://api.example.com/swagger.json"
              className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300">Default Headers (JSON, Optional)</label>
            <textarea
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              placeholder='{"X-Custom-Header": "value"}'
              rows={2}
              className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 font-mono text-xs text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none resize-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300">Notes (Optional)</label>
            <textarea
              value={form.notes}
              onChange={(e) => setForm({ ...form, notes: e.target.value })}
              placeholder="Notes about this API..."
              rows={2}
              className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none resize-none"
            />
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="rounded-lg px-4 py-2 text-sm text-gray-400 hover:text-white"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !form.name || !form.base_url}
            className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-cyan-700 disabled:opacity-50"
          >
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
            {saving ? 'Adding...' : 'Add Endpoint'}
          </button>
        </div>
      </div>
    </div>
  )
}
