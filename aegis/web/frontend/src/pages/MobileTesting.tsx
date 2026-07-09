import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Smartphone,
  Upload,
  Plus,
  Trash2,
  Play,
  Loader2,
  Check,
  AlertCircle,
  Search,
  Clock,
  ChevronRight,
  Globe,
  FileCode2,
  Shield,
  Eye,
  Download,
  MoreVertical,
  X,
  Scan,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Package,
  Lock,
  Key,
  Fingerprint,
  Server,
  Code,
  Bug,
  BarChart3,
  RefreshCw,
} from 'lucide-react'
import { api, formatDate, formatDateTime } from '../lib/api'

// Custom icons for platforms (lucide-react doesn't ship Android/Apple)
function Android({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M5 16V9a7 7 0 0 1 14 0v7" />
      <path d="M4 14h16" />
      <path d="M7 4l1.5 2" />
      <path d="M17 4l-1.5 2" />
      <rect x="8" y="16" width="2" height="4" rx="1" />
      <rect x="14" y="16" width="2" height="4" rx="1" />
    </svg>
  )
}

function Apple({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 20.94c1.5 0 2.75 1.06 4 1.06 3 0 6-8 6-12.22A4.91 4.91 0 0 0 17 5c-2.22 0-4 1.44-5 2-1-.56-2.78-2-5-2a4.9 4.9 0 0 0-5 4.78C2 14 5 22 8 22c1.25 0 2.5-1.06 4-1.06Z" />
      <path d="M10 2c1 .5 2 2 2 5" />
    </svg>
  )
}

// ─── Types ──────────────────────────────────────────────────────────────────

interface MobileApp {
  id: number
  name: string
  platform: string
  filename: string
  file_path: string
  file_size: number
  source: string
  app_url: string | null
  notes: string
  created_at: string
  last_scanned: string | null
  total_scans: number
  vulnerabilities_found: number
}

interface ScanResult {
  id: string
  status: string
  started_at: string
  scan_mode: string
}

type View = 'library' | 'detail' | 'upload'

// ─── Main Component ─────────────────────────────────────────────────────────

export default function MobileTesting() {
  const navigate = useNavigate()
  const [view, setView] = useState<View>('library')
  const [apps, setApps] = useState<MobileApp[]>([])
  const [selectedApp, setSelectedApp] = useState<MobileApp | null>(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filterPlatform, setFilterPlatform] = useState<string>('all')

  useEffect(() => {
    loadApps()
  }, [])

  const loadApps = async () => {
    setLoading(true)
    try {
      const data = await api.listMobileApps()
      setApps(data.sort((a: any, b: any) =>
        new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
      ))
    } finally {
      setLoading(false)
    }
  }

  const selectApp = async (app: MobileApp) => {
    setSelectedApp(app)
    setView('detail')
  }

  const handleDelete = async (id: number) => {
    if (confirm('Delete this app and its file?')) {
      await api.deleteMobileApp(id)
      setApps(apps.filter(a => a.id !== id))
      if (selectedApp?.id === id) {
        setSelectedApp(null)
        setView('library')
      }
    }
  }

  const filtered = apps.filter(a => {
    const matchesSearch = a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.filename.toLowerCase().includes(search.toLowerCase())
    const matchesPlatform = filterPlatform === 'all' || a.platform === filterPlatform
    return matchesSearch && matchesPlatform
  })

  const platformCounts = {
    all: apps.length,
    android: apps.filter(a => a.platform === 'android').length,
    ios: apps.filter(a => a.platform === 'ios').length,
  }

  return (
    <div className="flex h-full">
      {/* Left Sidebar - App Library */}
      <div className="w-80 flex-shrink-0 border-r border-gray-800 bg-gray-900/50 flex flex-col">
        <div className="border-b border-gray-800 p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-white">App Library</h2>
            <button
              onClick={() => setView('upload')}
              className="flex items-center gap-1.5 rounded-lg bg-orange-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-orange-700 transition-colors"
            >
              <Upload className="h-3.5 w-3.5" />
              Upload
            </button>
          </div>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search apps..."
              className="w-full rounded-lg border border-gray-800 bg-gray-900 py-2 pl-9 pr-3 text-sm text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none"
            />
          </div>

          {/* Platform Filter */}
          <div className="mt-3 flex gap-1">
            {(['all', 'android', 'ios'] as const).map((p) => (
              <button
                key={p}
                onClick={() => setFilterPlatform(p)}
                className={`flex-1 rounded-lg px-2 py-1.5 text-xs font-medium transition-colors ${
                  filterPlatform === p
                    ? 'bg-orange-900/50 text-orange-400'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {p === 'all' ? `All (${platformCounts.all})` :
                 p === 'android' ? `Android (${platformCounts.android})` :
                 `iOS (${platformCounts.ios})`}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-gray-400" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="p-4 text-center">
              <Smartphone className="mx-auto h-8 w-8 text-gray-600" />
              <p className="mt-2 text-xs text-gray-500">
                {search ? 'No apps match search' : 'No apps uploaded'}
              </p>
              {!search && (
                <button
                  onClick={() => setView('upload')}
                  className="mt-2 text-xs text-orange-400 hover:text-orange-300"
                >
                  Upload your first app
                </button>
              )}
            </div>
          ) : (
            <div className="p-2">
              {filtered.map((app) => (
                <button
                  key={app.id}
                  onClick={() => selectApp(app)}
                  className={`w-full rounded-lg p-3 text-left transition-colors ${
                    selectedApp?.id === app.id
                      ? 'bg-orange-900/30 border border-orange-800'
                      : 'hover:bg-gray-800 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${
                      app.platform === 'android' ? 'bg-green-900/30' : 'bg-gray-800'
                    }`}>
                      {app.platform === 'android' ? (
                        <Android className="h-5 w-5 text-green-400" />
                      ) : (
                        <Apple className="h-5 w-5 text-gray-300" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-white truncate">{app.name}</p>
                      <p className="text-xs text-gray-500 truncate">{app.filename}</p>
                    </div>
                  </div>
                  <div className="mt-2 flex items-center justify-between">
                    <span className="text-[10px] text-gray-600">
                      {app.total_scans} scan{app.total_scans !== 1 ? 's' : ''}
                    </span>
                    <span className="text-[10px] text-gray-600">
                      {formatFileSize(app.file_size)}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-y-auto">
        {view === 'upload' ? (
          <UploadView
            onUpload={async (app) => {
              await loadApps()
              setView('library')
              // Auto-select the new app
              const updated = await api.listMobileApps()
              const newest = updated.sort((a: any, b: any) =>
                new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
              )[0]
              if (newest) selectApp(newest)
            }}
            onCancel={() => setView('library')}
          />
        ) : view === 'detail' && selectedApp ? (
          <DetailView
            app={selectedApp}
            onBack={() => { setView('library'); setSelectedApp(null) }}
            onRefresh={loadApps}
            onScan={(scanId) => navigate(`/pentest/${scanId}`)}
          />
        ) : (
          <LibraryView
            apps={apps}
            onSelect={selectApp}
            onUpload={() => setView('upload')}
          />
        )}
      </div>
    </div>
  )
}

// ─── Library View (Default) ─────────────────────────────────────────────────

function LibraryView({
  apps,
  onSelect,
  onUpload,
}: {
  apps: MobileApp[]
  onSelect: (app: MobileApp) => void
  onUpload: () => void
}) {
  const stats = {
    total: apps.length,
    android: apps.filter(a => a.platform === 'android').length,
    ios: apps.filter(a => a.platform === 'ios').length,
    scanned: apps.filter(a => a.total_scans > 0).length,
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Mobile App Testing</h1>
        <p className="mt-2 text-gray-400">Upload and analyze Android and iOS applications</p>
      </div>

      {/* Stats */}
      <div className="mb-8 grid grid-cols-4 gap-4">
        <StatCard icon={Package} label="Total Apps" value={stats.total} color="orange" />
        <StatCard icon={Android} label="Android" value={stats.android} color="green" />
        <StatCard icon={Apple} label="iOS" value={stats.ios} color="gray" />
        <StatCard icon={Scan} label="Scanned" value={stats.scanned} color="cyan" />
      </div>

      {/* Quick Upload */}
      <div className="mb-8 rounded-2xl border-2 border-dashed border-gray-700 bg-gray-900/50 p-8 text-center hover:border-orange-600 transition-colors cursor-pointer" onClick={onUpload}>
        <Upload className="mx-auto h-12 w-12 text-gray-600" />
        <h3 className="mt-4 text-lg font-medium text-gray-300">Upload an App</h3>
        <p className="mt-1 text-sm text-gray-500">Drag & drop an APK or IPA file, or click to browse</p>
        <p className="mt-2 text-xs text-gray-600">Supports .apk, .aab, and .ipa files</p>
      </div>

      {/* Recent Apps */}
      {apps.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-4">Recent Apps</h2>
          <div className="grid grid-cols-3 gap-4">
            {apps.slice(0, 6).map((app) => (
              <button
                key={app.id}
                onClick={() => onSelect(app)}
                className="rounded-xl border border-gray-800 bg-gray-900/50 p-4 text-left hover:border-gray-700 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${
                    app.platform === 'android' ? 'bg-green-900/30' : 'bg-gray-800'
                  }`}>
                    {app.platform === 'android' ? (
                      <Android className="h-5 w-5 text-green-400" />
                    ) : (
                      <Apple className="h-5 w-5 text-gray-300" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-white truncate">{app.name}</p>
                    <p className="text-xs text-gray-500">{app.platform}</p>
                  </div>
                </div>
                <div className="mt-3 flex items-center justify-between text-xs text-gray-500">
                  <span>{app.total_scans} scan{app.total_scans !== 1 ? 's' : ''}</span>
                  <span>{formatFileSize(app.file_size)}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Upload View ────────────────────────────────────────────────────────────

function UploadView({
  onUpload,
  onCancel,
}: {
  onUpload: (app: any) => void
  onCancel: () => void
}) {
  const navigate = useNavigate()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [platform, setPlatform] = useState<'android' | 'ios'>('android')
  const [appName, setAppName] = useState('')
  const [source, setSource] = useState<'upload' | 'url'>('upload')
  const [appUrl, setAppUrl] = useState('')
  const [notes, setNotes] = useState('')
  const [uploading, setUploading] = useState(false)
  const [scanMode, setScanMode] = useState('standard')
  const [instruction, setInstruction] = useState('')

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) {
      setFile(f)
      if (!appName) {
        setAppName(f.name.replace(/\.(apk|aab|ipa)$/i, ''))
      }
      // Auto-detect platform from extension
      const ext = f.name.split('.').pop()?.toLowerCase()
      if (ext === 'ipa') setPlatform('ios')
      else if (ext === 'apk' || ext === 'aab') setPlatform('android')
    }
  }

  const handleUpload = async () => {
    if (source === 'upload' && !file) return
    if (source === 'url' && !appUrl) return
    if (!appName) return

    setUploading(true)
    try {
      let filePath = ''
      let fileSize = 0
      let filename = ''

      if (source === 'upload' && file) {
        const result = await api.uploadMobileApp(file)
        filePath = result.path
        fileSize = result.size
        filename = result.filename
      } else {
        filename = appUrl.split('/').pop() || 'app'
        filePath = appUrl
      }

      // Register the app
      const app = await api.createMobileApp({
        name: appName,
        platform,
        filename,
        file_path: filePath,
        file_size: fileSize,
        source,
        app_url: source === 'url' ? appUrl : null,
        notes,
      })

      onUpload(app)
    } catch (err: any) {
      alert('Failed: ' + err.message)
    } finally {
      setUploading(false)
    }
  }

  const handleUploadAndScan = async () => {
    if (source === 'upload' && !file) return
    if (source === 'url' && !appUrl) return
    if (!appName) return

    setUploading(true)
    try {
      let filePath = ''
      let fileSize = 0
      let filename = ''

      if (source === 'upload' && file) {
        const result = await api.uploadMobileApp(file)
        filePath = result.path
        fileSize = result.size
        filename = result.filename
      } else {
        filename = appUrl.split('/').pop() || 'app'
        filePath = appUrl
      }

      // Register the app
      const app = await api.createMobileApp({
        name: appName,
        platform,
        filename,
        file_path: filePath,
        file_size: fileSize,
        source,
        app_url: source === 'url' ? appUrl : null,
        notes,
      })

      // Start scan
      const scanResult = await api.createMobileScan({
        app_name: appName,
        platform,
        source,
        app_url: source === 'url' ? appUrl : filePath,
        scan_mode: scanMode,
        instruction: instruction || undefined,
        app_id: app.id,
      })

      navigate(`/pentest/${scanResult.scan_id}`)
    } catch (err: any) {
      alert('Failed: ' + err.message)
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="p-8">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Upload Mobile App</h1>
          <p className="mt-1 text-gray-400">Add an Android or iOS app to your library</p>
        </div>
        <button onClick={onCancel} className="rounded-lg p-2 text-gray-400 hover:text-white">
          <X className="h-5 w-5" />
        </button>
      </div>

      <div className="max-w-2xl space-y-6">
        {/* Platform */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-3">Platform</label>
          <div className="grid grid-cols-2 gap-3">
            {[
              { value: 'android', label: 'Android', icon: Android, color: 'green', desc: 'APK / AAB files' },
              { value: 'ios', label: 'iOS', icon: Apple, color: 'gray', desc: 'IPA files' },
            ].map((p) => {
              const Icon = p.icon
              return (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => setPlatform(p.value as any)}
                  className={`rounded-xl border p-4 text-left transition-colors ${
                    platform === p.value
                      ? `border-${p.color}-500 bg-${p.color}-900/30`
                      : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                  }`}
                >
                  <Icon className={`h-6 w-6 mb-2 ${platform === p.value ? `text-${p.color}-400` : 'text-gray-400'}`} />
                  <p className="font-medium text-white">{p.label}</p>
                  <p className="text-xs text-gray-400">{p.desc}</p>
                </button>
              )
            })}
          </div>
        </div>

        {/* Source */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-3">Source</label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setSource('upload')}
              className={`rounded-xl border p-4 text-left transition-colors ${
                source === 'upload'
                  ? 'border-orange-500 bg-orange-900/30'
                  : 'border-gray-700 bg-gray-800 hover:border-gray-600'
              }`}
            >
              <Upload className="h-5 w-5 text-gray-400 mb-2" />
              <p className="font-medium text-white">Upload File</p>
              <p className="text-xs text-gray-400">Local APK or IPA</p>
            </button>
            <button
              type="button"
              onClick={() => setSource('url')}
              className={`rounded-xl border p-4 text-left transition-colors ${
                source === 'url'
                  ? 'border-orange-500 bg-orange-900/30'
                  : 'border-gray-700 bg-gray-800 hover:border-gray-600'
              }`}
            >
              <Globe className="h-5 w-5 text-gray-400 mb-2" />
              <p className="font-medium text-white">Download URL</p>
              <p className="text-xs text-gray-400">Direct link to APK/IPA</p>
            </button>
          </div>
        </div>

        {/* Upload / URL */}
        {source === 'upload' ? (
          <div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".apk,.ipa,.aab"
              onChange={handleFileSelect}
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className={`w-full rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
                file
                  ? 'border-green-500 bg-green-900/10'
                  : 'border-gray-700 hover:border-gray-600'
              }`}
            >
              {file ? (
                <div className="flex items-center justify-center gap-3">
                  <Package className="h-8 w-8 text-green-400" />
                  <div className="text-left">
                    <p className="font-medium text-white">{file.name}</p>
                    <p className="text-sm text-gray-400">{formatFileSize(file.size)} — Ready</p>
                  </div>
                  <button
                    onClick={(e) => { e.stopPropagation(); setFile(null) }}
                    className="rounded-lg p-1 text-gray-400 hover:text-red-400"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              ) : (
                <>
                  <Upload className="mx-auto h-10 w-10 text-gray-500" />
                  <p className="mt-2 text-sm text-gray-400">Click to upload or drag and drop</p>
                  <p className="mt-1 text-xs text-gray-500">.apk, .aab, or .ipa files</p>
                </>
              )}
            </button>
          </div>
        ) : (
          <div>
            <label className="block text-sm font-medium text-gray-300">Download URL</label>
            <input
              type="text"
              value={appUrl}
              onChange={(e) => setAppUrl(e.target.value)}
              placeholder="https://example.com/app.apk"
              className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none"
            />
          </div>
        )}

        {/* App Name */}
        <div>
          <label className="block text-sm font-medium text-gray-300">App Name</label>
          <input
            type="text"
            value={appName}
            onChange={(e) => setAppName(e.target.value)}
            placeholder="My Application"
            className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none"
          />
        </div>

        {/* Scan Options (optional) */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
          <p className="text-sm font-medium text-gray-300 mb-3">Auto-Scan After Upload (Optional)</p>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Scan Mode</label>
              <select
                value={scanMode}
                onChange={(e) => setScanMode(e.target.value)}
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-orange-500 focus:outline-none"
              >
                <option value="quick">Quick (~15 min)</option>
                <option value="standard">Standard (~30 min)</option>
                <option value="deep">Deep (~60 min)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Custom Instructions</label>
              <textarea
                value={instruction}
                onChange={(e) => setInstruction(e.target.value)}
                placeholder="Focus on insecure storage, check for hardcoded secrets..."
                rows={2}
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none resize-none"
              />
            </div>
          </div>
        </div>

        {/* Notes */}
        <div>
          <label className="block text-sm font-medium text-gray-300">Notes (Optional)</label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Notes about this app..."
            rows={2}
            className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none resize-none"
          />
        </div>

        {/* Actions */}
        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="rounded-xl px-5 py-3 text-sm font-medium text-gray-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleUpload}
            disabled={uploading || !appName || (source === 'upload' && !file) || (source === 'url' && !appUrl)}
            className="flex items-center gap-2 rounded-xl bg-orange-600 px-5 py-3 text-sm font-medium text-white hover:bg-orange-700 disabled:opacity-50 transition-colors"
          >
            {uploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
            {uploading ? 'Uploading...' : 'Upload Only'}
          </button>
          <button
            onClick={handleUploadAndScan}
            disabled={uploading || !appName || (source === 'upload' && !file) || (source === 'url' && !appUrl)}
            className="flex items-center gap-2 rounded-xl bg-cyan-600 px-5 py-3 text-sm font-medium text-white hover:bg-cyan-700 disabled:opacity-50 transition-colors"
          >
            {uploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            {uploading ? 'Starting...' : 'Upload & Scan'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Detail View ────────────────────────────────────────────────────────────

function DetailView({
  app,
  onBack,
  onRefresh,
  onScan,
}: {
  app: MobileApp
  onBack: () => void
  onRefresh: () => void
  onScan: (scanId: string) => void
}) {
  const [scans, setScans] = useState<ScanResult[]>([])
  const [loadingScans, setLoadingScans] = useState(true)
  const [showScanModal, setShowScanModal] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [scanMode, setScanMode] = useState('standard')
  const [instruction, setInstruction] = useState('')

  useEffect(() => {
    loadScans()
    // Refresh app data to get updated total_scans
    api.getMobileApp(app.id).then((data) => {
      Object.assign(app, data)
    }).catch(() => {})
  }, [app.id])

  const loadScans = async () => {
    setLoadingScans(true)
    try {
      const data = await api.listMobileAppScans(app.id)
      setScans(data)
    } finally {
      setLoadingScans(false)
    }
  }

  const handleScan = async () => {
    setScanning(true)
    try {
      const result = await api.createMobileScan({
        app_name: app.name,
        platform: app.platform,
        source: app.source,
        app_url: app.app_url || app.file_path,
        scan_mode: scanMode,
        instruction: instruction || undefined,
        app_id: app.id,
      })
      setShowScanModal(false)
      onScan(result.scan_id)
    } catch (err: any) {
      alert('Failed to start scan: ' + err.message)
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-6 flex items-center gap-4">
        <button onClick={onBack} className="rounded-lg p-2 hover:bg-gray-800 transition-colors">
          <ChevronRight className="h-5 w-5 text-gray-400 rotate-180" />
        </button>
        <div className={`flex h-14 w-14 items-center justify-center rounded-xl ${
          app.platform === 'android' ? 'bg-green-900/30' : 'bg-gray-800'
        }`}>
          {app.platform === 'android' ? (
            <Android className="h-7 w-7 text-green-400" />
          ) : (
            <Apple className="h-7 w-7 text-gray-300" />
          )}
        </div>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-white">{app.name}</h1>
          <p className="text-sm text-gray-400">{app.filename} — {formatFileSize(app.file_size)}</p>
        </div>
        <button
          onClick={() => setShowScanModal(true)}
          className="flex items-center gap-2 rounded-xl bg-cyan-600 px-5 py-2.5 font-medium text-white hover:bg-cyan-700 transition-colors"
        >
          <Play className="h-4 w-4" />
          Start Scan
        </button>
      </div>

      {/* Stats */}
      <div className="mb-6 grid grid-cols-4 gap-4">
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
          <p className="text-xs text-gray-500">Platform</p>
          <p className="mt-1 text-lg font-bold text-white capitalize">{app.platform}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
          <p className="text-xs text-gray-500">Total Scans</p>
          <p className="mt-1 text-lg font-bold text-white">{app.total_scans}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
          <p className="text-xs text-gray-500">Vulnerabilities</p>
          <p className="mt-1 text-lg font-bold text-orange-400">{app.vulnerabilities_found}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
          <p className="text-xs text-gray-500">Last Scanned</p>
          <p className="mt-1 text-sm font-medium text-white">
            {formatDate(app.last_scanned)}
          </p>
        </div>
      </div>

      {/* Analysis Capabilities */}
      <div className="mb-6 rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Analysis Capabilities</h2>
        <div className="grid grid-cols-3 gap-4">
          {[
            { icon: FileCode2, label: 'Static Analysis', desc: 'Decompile and analyze source code', color: 'cyan' },
            { icon: Lock, label: 'Permission Audit', desc: 'Review requested permissions', color: 'purple' },
            { icon: Key, label: 'Secret Detection', desc: 'Find hardcoded keys and tokens', color: 'orange' },
            { icon: Server, label: 'Network Analysis', desc: 'Inspect API calls and traffic', color: 'green' },
            { icon: Bug, label: 'Vulnerability Scan', desc: 'OWASP Mobile Top 10 testing', color: 'red' },
            { icon: Fingerprint, label: 'Component Analysis', desc: 'Activities, Services, Receivers', color: 'blue' },
          ].map((cap) => {
            const Icon = cap.icon
            return (
              <div key={cap.label} className="rounded-xl border border-gray-800 bg-gray-800/50 p-4">
                <Icon className={`h-5 w-5 text-${cap.color}-400 mb-2`} />
                <p className="text-sm font-medium text-white">{cap.label}</p>
                <p className="text-xs text-gray-500 mt-0.5">{cap.desc}</p>
              </div>
            )
          })}
        </div>
      </div>

      {/* Scan History */}
      <div className="rounded-2xl border border-gray-800 bg-gray-900/50">
        <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
          <h2 className="text-lg font-semibold text-white">Scan History</h2>
          <button
            onClick={loadScans}
            className="rounded p-1.5 text-gray-400 hover:bg-gray-800 hover:text-white"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
        {loadingScans ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 animate-spin text-gray-400" />
          </div>
        ) : scans.length === 0 ? (
          <div className="py-12 text-center text-gray-500">
            <Scan className="mx-auto h-10 w-10 text-gray-600 mb-3" />
            <p className="text-sm">No scans yet</p>
            <button
              onClick={() => setShowScanModal(true)}
              className="mt-2 text-sm text-cyan-400 hover:text-cyan-300"
            >
              Start first scan
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {scans.map((scan) => (
              <button
                key={scan.id}
                onClick={() => onScan(scan.id)}
                className="flex w-full items-center justify-between px-6 py-4 text-left hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center gap-3">
                  {scan.status === 'completed' ? (
                    <CheckCircle className="h-5 w-5 text-green-400" />
                  ) : scan.status === 'running' ? (
                    <Loader2 className="h-5 w-5 text-blue-400 animate-spin" />
                  ) : scan.status === 'failed' ? (
                    <XCircle className="h-5 w-5 text-red-400" />
                  ) : (
                    <Clock className="h-5 w-5 text-gray-400" />
                  )}
                  <div>
                    <p className="text-sm font-medium text-white">{scan.id}</p>
                    <p className="text-xs text-gray-500">
                      {formatDateTime(scan.started_at)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-400 capitalize">{scan.scan_mode}</span>
                  <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                    scan.status === 'completed' ? 'bg-green-900/50 text-green-400' :
                    scan.status === 'running' ? 'bg-blue-900/50 text-blue-400' :
                    scan.status === 'failed' ? 'bg-red-900/50 text-red-400' :
                    'bg-gray-800 text-gray-400'
                  }`}>
                    {scan.status}
                  </span>
                  <ChevronRight className="h-4 w-4 text-gray-500" />
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Scan Modal */}
      {showScanModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-gray-800 bg-gray-900 p-6 shadow-2xl">
            <h2 className="text-lg font-semibold text-white">Start Mobile Scan</h2>
            <p className="mt-1 text-sm text-gray-400">Configure the security scan for {app.name}</p>

            <div className="mt-5 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300">Scan Mode</label>
                <div className="mt-2 grid grid-cols-3 gap-2">
                  {[
                    { value: 'quick', label: 'Quick', desc: '~15 min' },
                    { value: 'standard', label: 'Standard', desc: '~30 min' },
                    { value: 'deep', label: 'Deep', desc: '~60 min' },
                  ].map((mode) => (
                    <button
                      key={mode.value}
                      type="button"
                      onClick={() => setScanMode(mode.value)}
                      className={`rounded-lg border p-3 text-left transition-colors ${
                        scanMode === mode.value
                          ? 'border-cyan-500 bg-cyan-900/30'
                          : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                      }`}
                    >
                      <p className="text-sm font-medium text-white">{mode.label}</p>
                      <p className="text-xs text-gray-400">{mode.desc}</p>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300">Custom Instructions (Optional)</label>
                <textarea
                  value={instruction}
                  onChange={(e) => setInstruction(e.target.value)}
                  placeholder="Focus on insecure storage, check for hardcoded secrets..."
                  rows={3}
                  className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none resize-none"
                />
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => setShowScanModal(false)}
                className="rounded-lg px-4 py-2 text-sm text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleScan}
                disabled={scanning}
                className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-cyan-700 disabled:opacity-50"
              >
                {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                {scanning ? 'Starting...' : 'Start Scan'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Stat Card ──────────────────────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: any
  label: string
  value: number
  color: string
}) {
  const colorClasses: Record<string, string> = {
    orange: 'bg-orange-500/10 text-orange-400',
    green: 'bg-green-500/10 text-green-400',
    gray: 'bg-gray-500/10 text-gray-400',
    cyan: 'bg-cyan-500/10 text-cyan-400',
  }

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500">{label}</p>
        <div className={`rounded-lg p-1.5 ${colorClasses[color]}`}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
      <p className="mt-2 text-2xl font-bold text-white">{value}</p>
    </div>
  )
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}
