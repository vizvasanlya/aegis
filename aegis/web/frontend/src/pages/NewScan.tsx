import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Globe,
  Code,
  GitBranch,
  Smartphone,
  Network,
  Play,
  Loader2,
  ArrowLeft,
  ArrowRight,
  Check,
  Upload,
  FileCode2,
  Zap,
  Shield,
  Clock,
  AlertCircle,
  X,
} from 'lucide-react'
import { api } from '../lib/api'

// ─── Types ──────────────────────────────────────────────────────────────────

type ScanType = 'webapp' | 'api' | 'git' | 'mobile' | 'internal'
type Step = 'type' | 'target' | 'options' | 'review'

interface ScanConfig {
  type: ScanType | null
  // Web App
  targetUrl: string
  // API
  apiEndpoint: string
  apiMethod: string
  apiType: 'rest' | 'graphql' | 'grpc' | 'websocket'
  openApiUrl: string
  apiHeaders: string
  // Git
  repoUrl: string
  repoBranch: string
  // Mobile
  appName: string
  platform: 'android' | 'ios'
  mobileSource: 'upload' | 'url'
  appUrl: string
  uploadedFile: File | null
  uploadedFilePath: string | null
  // Internal
  internalTarget: string
  internalScope: 'network' | 'ad' | 'full'
  // Common
  scanMode: string
  instruction: string
  credentialId: number | null
}

const scanTypes = [
  {
    id: 'webapp' as ScanType,
    label: 'Web Application',
    description: 'Scan websites and web apps for OWASP Top 10 vulnerabilities',
    icon: Globe,
    color: 'cyan',
    tags: ['URL', 'Authentication', 'OWASP'],
  },
  {
    id: 'api' as ScanType,
    label: 'API Endpoint',
    description: 'Test REST, GraphQL, gRPC, and WebSocket APIs',
    icon: Code,
    color: 'purple',
    tags: ['REST', 'GraphQL', 'gRPC', 'WebSocket'],
  },
  {
    id: 'git' as ScanType,
    label: 'Git Repository',
    description: 'Source code analysis for GitHub and GitLab repos',
    icon: GitBranch,
    color: 'green',
    tags: ['SAST', 'Secrets', 'Dependencies'],
  },
  {
    id: 'mobile' as ScanType,
    label: 'Mobile App',
    description: 'Analyze Android APK and iOS IPA files',
    icon: Smartphone,
    color: 'orange',
    tags: ['Android', 'iOS', 'Static', 'Dynamic'],
  },
  {
    id: 'internal' as ScanType,
    label: 'Internal Network',
    description: 'Test internal network, AD, and lateral movement',
    icon: Network,
    color: 'red',
    tags: ['AD', 'Pentest', 'Lateral Movement'],
  },
]

const apiMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
const apiTypes = [
  { value: 'rest', label: 'REST API', description: 'Standard RESTful endpoints' },
  { value: 'graphql', label: 'GraphQL', description: 'GraphQL schema and queries' },
  { value: 'grpc', label: 'gRPC', description: 'gRPC protocol buffers' },
  { value: 'websocket', label: 'WebSocket', description: 'Real-time WebSocket connections' },
]

// ─── Main Component ─────────────────────────────────────────────────────────

export default function NewScan() {
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>('type')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [credentials, setCredentials] = useState<any[]>([])

  const [config, setConfig] = useState<ScanConfig>({
    type: null,
    targetUrl: '',
    apiEndpoint: '',
    apiMethod: 'GET',
    apiType: 'rest',
    openApiUrl: '',
    apiHeaders: '',
    repoUrl: '',
    repoBranch: 'main',
    appName: '',
    platform: 'android',
    mobileSource: 'url',
    appUrl: '',
    uploadedFile: null,
    uploadedFilePath: null,
    internalTarget: '',
    internalScope: 'full',
    scanMode: 'standard',
    instruction: '',
    credentialId: null,
  })

  useEffect(() => {
    api.listCredentials().then(setCredentials).catch(() => {})
  }, [])

  const updateConfig = (partial: Partial<ScanConfig>) => {
    setConfig(prev => ({ ...prev, ...partial }))
    setError(null)
  }

  // ─── Validation ─────────────────────────────────────────────────────────

  const canProceed = (): boolean => {
    switch (step) {
      case 'type':
        return config.type !== null
      case 'target':
        switch (config.type) {
          case 'webapp':
            return config.targetUrl.trim().length > 0
          case 'api':
            return config.apiEndpoint.trim().length > 0
          case 'git':
            return config.repoUrl.trim().length > 0
          case 'mobile':
            if (config.mobileSource === 'upload') {
              return config.uploadedFilePath !== null
            }
            return config.appUrl.trim().length > 0 || config.appName.trim().length > 0
          case 'internal':
            return config.internalTarget.trim().length > 0
          default:
            return false
        }
      case 'options':
        return true
      case 'review':
        return true
      default:
        return false
    }
  }

  // ─── Launch Scan ────────────────────────────────────────────────────────

  const handleLaunch = async () => {
    setLoading(true)
    setError(null)
    try {
      let result: any

      switch (config.type) {
        case 'webapp':
          let instruction = config.instruction
          if (config.credentialId) {
            const credData = await api.getCredentialForScan(config.credentialId)
            instruction = credData.instruction + (instruction ? '\n' + instruction : '')
          }
          result = await api.createScan({
            target: config.targetUrl,
            scan_mode: config.scanMode,
            instruction: instruction || undefined,
            credential_id: config.credentialId || undefined,
          })
          navigate(`/pentest/${result.scan_id}`)
          break

        case 'api':
          result = await api.createApiScan({
            endpoint: config.apiEndpoint,
            method: config.apiMethod,
            api_type: config.apiType,
            scan_mode: config.scanMode,
            instruction: config.instruction || undefined,
            credential_id: config.credentialId || undefined,
            openapi_url: config.openApiUrl || undefined,
            headers: config.apiHeaders ? JSON.parse(config.apiHeaders) : undefined,
          })
          navigate(`/pentest/${result.scan_id}`)
          break

        case 'git':
          result = await api.scanGitRepo({
            repo_url: config.repoUrl,
            branch: config.repoBranch,
            scan_mode: config.scanMode,
            instruction: config.instruction || undefined,
          })
          navigate(`/pentest/${result.scan_id}`)
          break

        case 'mobile':
          result = await api.createMobileScan({
            app_name: config.appName || config.uploadedFile?.name || 'unknown',
            platform: config.platform,
            source: config.mobileSource,
            app_url: config.mobileSource === 'url' ? config.appUrl : config.uploadedFilePath,
            scan_mode: config.scanMode,
            instruction: config.instruction || undefined,
          })
          navigate(`/pentest/${result.scan_id}`)
          break

        case 'internal':
          let internalInstruction = config.instruction
          if (config.credentialId) {
            const credData = await api.getCredentialForScan(config.credentialId)
            internalInstruction = credData.instruction + (internalInstruction ? '\n' + internalInstruction : '')
          }
          result = await api.createInternalScan({
            target: config.internalTarget,
            scan_mode: config.scanMode,
            instruction: internalInstruction || undefined,
            credential_id: config.credentialId || undefined,
            scope: config.internalScope,
          })
          navigate(`/pentest/${result.scan_id}`)
          break
      }
    } catch (err: any) {
      setError(err.message || 'Failed to start scan')
    } finally {
      setLoading(false)
    }
  }

  // ─── Step Navigation ────────────────────────────────────────────────────

  const nextStep = () => {
    if (step === 'type') setStep('target')
    else if (step === 'target') setStep('options')
    else if (step === 'options') setStep('review')
  }

  const prevStep = () => {
    if (step === 'review') setStep('options')
    else if (step === 'options') setStep('target')
    else if (step === 'target') setStep('type')
  }

  const steps: { key: Step; label: string }[] = [
    { key: 'type', label: 'Test Type' },
    { key: 'target', label: 'Target' },
    { key: 'options', label: 'Options' },
    { key: 'review', label: 'Review' },
  ]

  const currentStepIdx = steps.findIndex(s => s.key === step)

  // ─── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="mx-auto max-w-4xl p-8">
      {/* Progress Bar */}
      <div className="mb-10">
        <div className="flex items-center justify-between">
          {steps.map((s, idx) => (
            <div key={s.key} className="flex items-center">
              <div className="flex items-center gap-3">
                <div
                  className={`flex h-9 w-9 items-center justify-center rounded-full text-sm font-bold transition-colors ${
                    idx < currentStepIdx
                      ? 'bg-cyan-600 text-white'
                      : idx === currentStepIdx
                      ? 'bg-cyan-900/50 text-cyan-400 ring-2 ring-cyan-500'
                      : 'bg-gray-800 text-gray-500'
                  }`}
                >
                  {idx < currentStepIdx ? <Check className="h-4 w-4" /> : idx + 1}
                </div>
                <span
                  className={`text-sm font-medium ${
                    idx <= currentStepIdx ? 'text-white' : 'text-gray-500'
                  }`}
                >
                  {s.label}
                </span>
              </div>
              {idx < steps.length - 1 && (
                <div
                  className={`mx-4 h-0.5 w-12 ${
                    idx < currentStepIdx ? 'bg-cyan-600' : 'bg-gray-800'
                  }`}
                />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-6 flex items-center gap-3 rounded-xl border border-red-800 bg-red-900/20 px-4 py-3">
          <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Step Content */}
      <div className="min-h-[400px]">
        {step === 'type' && (
          <StepType config={config} updateConfig={updateConfig} />
        )}
        {step === 'target' && (
          <StepTarget config={config} updateConfig={updateConfig} />
        )}
        {step === 'options' && (
          <StepOptions config={config} updateConfig={updateConfig} credentials={credentials} />
        )}
        {step === 'review' && (
          <StepReview config={config} />
        )}
      </div>

      {/* Navigation */}
      <div className="mt-8 flex items-center justify-between">
        <button
          onClick={step === 'type' ? () => navigate(-1) : prevStep}
          className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-medium text-gray-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          {step === 'type' ? 'Cancel' : 'Back'}
        </button>

        {step === 'review' ? (
          <button
            onClick={handleLaunch}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl bg-cyan-600 px-6 py-3 font-medium text-white hover:bg-cyan-700 disabled:opacity-50 transition-colors"
          >
            {loading ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Play className="h-5 w-5" />
            )}
            {loading ? 'Starting...' : 'Launch Scan'}
          </button>
        ) : (
          <button
            onClick={nextStep}
            disabled={!canProceed()}
            className="flex items-center gap-2 rounded-xl bg-cyan-600 px-6 py-3 font-medium text-white hover:bg-cyan-700 disabled:opacity-50 transition-colors"
          >
            Next
            <ArrowRight className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  )
}

// ─── Step 1: Choose Test Type ──────────────────────────────────────────────

function StepType({
  config,
  updateConfig,
}: {
  config: ScanConfig
  updateConfig: (p: Partial<ScanConfig>) => void
}) {
  const colorMap: Record<string, string> = {
    cyan: 'border-cyan-500 bg-cyan-900/20 ring-1 ring-cyan-500/50',
    purple: 'border-purple-500 bg-purple-900/20 ring-1 ring-purple-500/50',
    green: 'border-green-500 bg-green-900/20 ring-1 ring-green-500/50',
    orange: 'border-orange-500 bg-orange-900/20 ring-1 ring-orange-500/50',
  }
  const iconColorMap: Record<string, string> = {
    cyan: 'text-cyan-400',
    purple: 'text-purple-400',
    green: 'text-green-400',
    orange: 'text-orange-400',
  }
  const tagColorMap: Record<string, string> = {
    cyan: 'bg-cyan-900/50 text-cyan-400',
    purple: 'bg-purple-900/50 text-purple-400',
    green: 'bg-green-900/50 text-green-400',
    orange: 'bg-orange-900/50 text-orange-400',
  }

  return (
    <div>
      <div className="mb-8 text-center">
        <h1 className="text-3xl font-bold text-white">What do you want to test?</h1>
        <p className="mt-2 text-gray-400">Choose a test type to get started</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {scanTypes.map((type) => {
          const Icon = type.icon
          const selected = config.type === type.id
          return (
            <button
              key={type.id}
              onClick={() => updateConfig({ type: type.id })}
              className={`rounded-2xl border-2 p-6 text-left transition-all hover:scale-[1.02] ${
                selected
                  ? colorMap[type.color]
                  : 'border-gray-800 bg-gray-900/50 hover:border-gray-700'
              }`}
            >
              <div className={`mb-4 inline-flex rounded-xl p-3 ${
                selected ? 'bg-white/10' : 'bg-gray-800'
              }`}>
                <Icon className={`h-6 w-6 ${selected ? iconColorMap[type.color] : 'text-gray-400'}`} />
              </div>
              <h3 className="text-lg font-semibold text-white">{type.label}</h3>
              <p className="mt-1 text-sm text-gray-400">{type.description}</p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {type.tags.map((tag) => (
                  <span
                    key={tag}
                    className={`rounded-md px-2 py-0.5 text-xs font-medium ${
                      selected ? tagColorMap[type.color] : 'bg-gray-800 text-gray-500'
                    }`}
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

// ─── Step 2: Configure Target ──────────────────────────────────────────────

function StepTarget({
  config,
  updateConfig,
}: {
  config: ScanConfig
  updateConfig: (p: Partial<ScanConfig>) => void
}) {
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      const result = await api.uploadMobileApp(file)
      updateConfig({ uploadedFile: file, uploadedFilePath: result.path })
    } catch (err) {
      alert('Failed to upload file')
    }
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">
          {config.type === 'webapp' && 'Web Application Target'}
          {config.type === 'api' && 'API Endpoint'}
          {config.type === 'git' && 'Repository URL'}
          {config.type === 'mobile' && 'Mobile App'}
        </h1>
        <p className="mt-2 text-gray-400">
          {config.type === 'webapp' && 'Enter the URL of the web application to test'}
          {config.type === 'api' && 'Enter the API endpoint URL and configure the API type'}
          {config.type === 'git' && 'Enter the GitHub or GitLab repository URL'}
          {config.type === 'mobile' && 'Upload an APK/IPA file or provide a download URL'}
        </p>
      </div>

      <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
        {/* Web App */}
        {config.type === 'webapp' && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300">Target URL</label>
              <input
                type="text"
                value={config.targetUrl}
                onChange={(e) => updateConfig({ targetUrl: e.target.value })}
                placeholder="https://example.com"
                className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                autoFocus
              />
              <p className="mt-1.5 text-xs text-gray-500">
                Supports URLs, IP addresses, and localhost
              </p>
            </div>
          </div>
        )}

        {/* API */}
        {config.type === 'api' && (
          <div className="space-y-5">
            {/* API Type */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-3">API Type</label>
              <div className="grid grid-cols-2 gap-3">
                {apiTypes.map((t) => (
                  <button
                    key={t.value}
                    type="button"
                    onClick={() => updateConfig({ apiType: t.value as any })}
                    className={`rounded-xl border p-4 text-left transition-colors ${
                      config.apiType === t.value
                        ? 'border-purple-500 bg-purple-900/30'
                        : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                    }`}
                  >
                    <p className="font-medium text-white">{t.label}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{t.description}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Method + Endpoint */}
            <div className="flex gap-3">
              <div className="w-32">
                <label className="block text-sm font-medium text-gray-300">Method</label>
                <select
                  value={config.apiMethod}
                  onChange={(e) => updateConfig({ apiMethod: e.target.value })}
                  className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-3 py-3 text-white focus:border-purple-500 focus:outline-none"
                >
                  {apiMethods.map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
              <div className="flex-1">
                <label className="block text-sm font-medium text-gray-300">Endpoint URL</label>
                <input
                  type="text"
                  value={config.apiEndpoint}
                  onChange={(e) => updateConfig({ apiEndpoint: e.target.value })}
                  placeholder="https://api.example.com/v1/users"
                  className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-purple-500 focus:outline-none"
                  autoFocus
                />
              </div>
            </div>

            {/* OpenAPI URL */}
            {(config.apiType === 'rest' || config.apiType === 'graphql') && (
              <div>
                <label className="block text-sm font-medium text-gray-300">
                  OpenAPI / Swagger URL (Optional)
                </label>
                <input
                  type="text"
                  value={config.openApiUrl}
                  onChange={(e) => updateConfig({ openApiUrl: e.target.value })}
                  placeholder="https://api.example.com/swagger.json"
                  className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-purple-500 focus:outline-none"
                />
                <p className="mt-1.5 text-xs text-gray-500">
                  Provide an OpenAPI spec for more thorough endpoint discovery
                </p>
              </div>
            )}

            {/* Custom Headers */}
            <div>
              <label className="block text-sm font-medium text-gray-300">
                Custom Headers (Optional, JSON)
              </label>
              <textarea
                value={config.apiHeaders}
                onChange={(e) => updateConfig({ apiHeaders: e.target.value })}
                placeholder='{"Authorization": "Bearer token...", "X-API-Key": "..."}'
                rows={3}
                className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 font-mono text-sm text-white placeholder-gray-500 focus:border-purple-500 focus:outline-none resize-none"
              />
            </div>
          </div>
        )}

        {/* Git */}
        {config.type === 'git' && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300">Repository URL</label>
              <input
                type="text"
                value={config.repoUrl}
                onChange={(e) => updateConfig({ repoUrl: e.target.value })}
                placeholder="https://github.com/owner/repo"
                className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-green-500 focus:outline-none"
                autoFocus
              />
              <p className="mt-1.5 text-xs text-gray-500">
                Supports GitHub and GitLab public/private repositories
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300">Branch</label>
              <input
                type="text"
                value={config.repoBranch}
                onChange={(e) => updateConfig({ repoBranch: e.target.value })}
                placeholder="main"
                className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-green-500 focus:outline-none"
              />
            </div>
          </div>
        )}

        {/* Mobile */}
        {config.type === 'mobile' && (
          <div className="space-y-5">
            {/* Platform */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-3">Platform</label>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { value: 'android', label: 'Android', desc: 'APK / AAB files' },
                  { value: 'ios', label: 'iOS', desc: 'IPA files' },
                ].map((p) => (
                  <button
                    key={p.value}
                    type="button"
                    onClick={() => updateConfig({ platform: p.value as any })}
                    className={`rounded-xl border p-4 text-left transition-colors ${
                      config.platform === p.value
                        ? 'border-orange-500 bg-orange-900/30'
                        : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                    }`}
                  >
                    <p className="font-medium text-white">{p.label}</p>
                    <p className="text-xs text-gray-400">{p.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Source */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-3">Source</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => updateConfig({ mobileSource: 'upload' })}
                  className={`rounded-xl border p-4 text-left transition-colors ${
                    config.mobileSource === 'upload'
                      ? 'border-orange-500 bg-orange-900/30'
                      : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                  }`}
                >
                  <Upload className="h-5 w-5 text-gray-400 mb-2" />
                  <p className="font-medium text-white">Upload File</p>
                  <p className="text-xs text-gray-400">Upload APK or IPA</p>
                </button>
                <button
                  type="button"
                  onClick={() => updateConfig({ mobileSource: 'url' })}
                  className={`rounded-xl border p-4 text-left transition-colors ${
                    config.mobileSource === 'url'
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

            {config.mobileSource === 'upload' ? (
              <div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".apk,.ipa,.aab"
                  onChange={handleFileUpload}
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className={`w-full rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
                    config.uploadedFile
                      ? 'border-green-500 bg-green-900/10'
                      : 'border-gray-700 hover:border-gray-600'
                  }`}
                >
                  {config.uploadedFile ? (
                    <div className="flex items-center justify-center gap-3">
                      <FileCode2 className="h-8 w-8 text-green-400" />
                      <div className="text-left">
                        <p className="font-medium text-white">{config.uploadedFile.name}</p>
                        <p className="text-sm text-gray-400">
                          {(config.uploadedFile.size / 1024 / 1024).toFixed(1)} MB — Ready
                        </p>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          updateConfig({ uploadedFile: null, uploadedFilePath: null })
                        }}
                        className="rounded-lg p-1 text-gray-400 hover:text-red-400"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                  ) : (
                    <>
                      <Upload className="mx-auto h-10 w-10 text-gray-500" />
                      <p className="mt-2 text-sm text-gray-400">
                        Click to upload or drag and drop
                      </p>
                      <p className="mt-1 text-xs text-gray-500">
                        .apk, .aab, or .ipa files up to 200MB
                      </p>
                    </>
                  )}
                </button>
              </div>
            ) : (
              <div>
                <label className="block text-sm font-medium text-gray-300">Download URL</label>
                <input
                  type="text"
                  value={config.appUrl}
                  onChange={(e) => updateConfig({ appUrl: e.target.value })}
                  placeholder="https://example.com/app.apk"
                  className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none"
                  autoFocus
                />
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-300">App Name</label>
              <input
                type="text"
                value={config.appName}
                onChange={(e) => updateConfig({ appName: e.target.value })}
                placeholder="My Application"
                className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none"
              />
            </div>
          </div>
        )}

        {/* Internal Network */}
        {config.type === 'internal' && (
          <div className="space-y-5">
            {/* Target */}
            <div>
              <label className="block text-sm font-medium text-gray-300">Network Target</label>
              <input
                type="text"
                value={config.internalTarget}
                onChange={(e) => updateConfig({ internalTarget: e.target.value })}
                placeholder="192.168.1.0/24 or 10.0.0.1"
                className="mt-2 w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 font-mono text-sm text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
                autoFocus
              />
              <p className="mt-1.5 text-xs text-gray-500">
                IP address, CIDR range, or hostname inside the target network
              </p>
            </div>

            {/* Scope */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-3">Testing Scope</label>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { value: 'network', label: 'Network', desc: 'Host discovery, ports, services' },
                  { value: 'ad', label: 'Active Directory', desc: 'AD enumeration, Kerberos' },
                  { value: 'full', label: 'Full Pentest', desc: 'Network + AD + lateral movement' },
                ].map((scope) => (
                  <button
                    key={scope.value}
                    type="button"
                    onClick={() => updateConfig({ internalScope: scope.value as any })}
                    className={`rounded-xl border p-4 text-left transition-colors ${
                      config.internalScope === scope.value
                        ? 'border-red-500 bg-red-900/30'
                        : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                    }`}
                  >
                    <p className="font-medium text-white">{scope.label}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{scope.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-red-900/50 bg-red-900/10 p-4">
              <p className="text-sm text-red-400 font-medium">Requires network access</p>
              <p className="mt-1 text-xs text-gray-400">
                Aegis must run from inside the target network (VPN, jump server, or office workstation).
                Docker mode uses <code className="text-red-300">--network=host</code> for direct access.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Step 3: Options ───────────────────────────────────────────────────────

function StepOptions({
  config,
  updateConfig,
  credentials,
}: {
  config: ScanConfig
  updateConfig: (p: Partial<ScanConfig>) => void
  credentials: any[]
}) {
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Scan Options</h1>
        <p className="mt-2 text-gray-400">Configure how the scan should run</p>
      </div>

      <div className="space-y-6">
        {/* Scan Mode */}
        <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
          <div className="flex items-center gap-3 mb-4">
            <Zap className="h-5 w-5 text-cyan-400" />
            <div>
              <h2 className="font-semibold text-white">Scan Mode</h2>
              <p className="text-sm text-gray-400">Controls depth and duration of the scan</p>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            {[
              { value: 'quick', label: 'Quick', desc: '~15 min', icon: Clock },
              { value: 'standard', label: 'Standard', desc: '~30 min', icon: Shield },
              { value: 'deep', label: 'Deep', desc: '~60 min', icon: AlertCircle },
            ].map((mode) => {
              const Icon = mode.icon
              return (
                <button
                  key={mode.value}
                  type="button"
                  onClick={() => updateConfig({ scanMode: mode.value })}
                  className={`rounded-xl border p-4 text-left transition-colors ${
                    config.scanMode === mode.value
                      ? 'border-cyan-500 bg-cyan-900/30'
                      : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                  }`}
                >
                  <Icon className={`h-5 w-5 mb-2 ${
                    config.scanMode === mode.value ? 'text-cyan-400' : 'text-gray-400'
                  }`} />
                  <p className="font-medium text-white">{mode.label}</p>
                  <p className="text-xs text-gray-400">{mode.desc}</p>
                </button>
              )
            })}
          </div>
        </div>

        {/* Credentials */}
        <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="h-5 w-5 text-cyan-400" />
            <div>
              <h2 className="font-semibold text-white">Authentication</h2>
              <p className="text-sm text-gray-400">Provide credentials for authenticated testing</p>
            </div>
          </div>
          <select
            value={config.credentialId || ''}
            onChange={(e) => updateConfig({ credentialId: e.target.value ? Number(e.target.value) : null })}
            className="w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white focus:border-cyan-500 focus:outline-none"
          >
            <option value="">No credentials (unauthenticated testing)</option>
            {credentials.map((cred: any) => (
              <option key={cred.id} value={cred.id}>
                {cred.name} — {cred.site_url}
              </option>
            ))}
          </select>
          {credentials.length === 0 && (
            <p className="mt-2 text-xs text-gray-500">
              No credentials stored yet. Add them in the Credentials page for authenticated testing.
            </p>
          )}
        </div>

        {/* Custom Instructions */}
        <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
          <div className="flex items-center gap-3 mb-4">
            <FileCode2 className="h-5 w-5 text-cyan-400" />
            <div>
              <h2 className="font-semibold text-white">Custom Instructions</h2>
              <p className="text-sm text-gray-400">Guide the AI on what to focus on</p>
            </div>
          </div>
          <textarea
            value={config.instruction}
            onChange={(e) => updateConfig({ instruction: e.target.value })}
            placeholder={
              config.type === 'webapp'
                ? 'Focus on authentication bypass, test admin panels...'
                : config.type === 'api'
                ? 'Test all CRUD endpoints for IDOR, check rate limiting...'
                : config.type === 'git'
                ? 'Focus on hardcoded secrets, check dependency vulnerabilities...'
                : config.type === 'internal'
                ? 'Enumerate all hosts, test for credential reuse, check SMB signing...'
                : 'Analyze permissions, check for insecure storage...'
            }
            rows={4}
            className="w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none resize-none"
          />
        </div>
      </div>
    </div>
  )
}

// ─── Step 4: Review & Launch ───────────────────────────────────────────────

function StepReview({ config }: { config: ScanConfig }) {
  const typeLabels: Record<ScanType, string> = {
    webapp: 'Web Application',
    api: 'API Endpoint',
    git: 'Git Repository',
    mobile: 'Mobile App',
    internal: 'Internal Network',
  }

  const getTarget = () => {
    switch (config.type) {
      case 'webapp':
        return config.targetUrl
      case 'api':
        return `${config.apiMethod} ${config.apiEndpoint}`
      case 'git':
        return config.repoUrl
      case 'mobile':
        return config.mobileSource === 'upload'
          ? config.uploadedFile?.name || 'Uploaded file'
          : config.appUrl
      case 'internal':
        return config.internalTarget
      default:
        return ''
    }
  }

  const details: { label: string; value: string }[] = [
    { label: 'Test Type', value: config.type ? typeLabels[config.type] : '' },
    { label: 'Target', value: getTarget() },
    { label: 'Scan Mode', value: config.scanMode.charAt(0).toUpperCase() + config.scanMode.slice(1) },
  ]

  if (config.type === 'api') {
    details.push({ label: 'API Type', value: config.apiType.toUpperCase() })
    if (config.openApiUrl) details.push({ label: 'OpenAPI Spec', value: config.openApiUrl })
  }
  if (config.type === 'git') {
    details.push({ label: 'Branch', value: config.repoBranch })
  }
  if (config.type === 'mobile') {
    details.push({ label: 'Platform', value: config.platform === 'android' ? 'Android' : 'iOS' })
    details.push({ label: 'Source', value: config.mobileSource === 'upload' ? 'File Upload' : 'URL' })
  }
  if (config.type === 'internal') {
    details.push({ label: 'Scope', value: config.internalScope === 'full' ? 'Full Pentest' : config.internalScope === 'ad' ? 'Active Directory' : 'Network Discovery' })
  }
  if (config.credentialId) {
    details.push({ label: 'Authentication', value: 'Using stored credentials' })
  }
  if (config.instruction) {
    details.push({ label: 'Instructions', value: config.instruction })
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Review & Launch</h1>
        <p className="mt-2 text-gray-400">Confirm your scan configuration before starting</p>
      </div>

      <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
        <div className="space-y-4">
          {details.map((d) => (
            <div key={d.label} className="flex items-start justify-between gap-4 py-3 border-b border-gray-800 last:border-0">
              <span className="text-sm text-gray-400 flex-shrink-0">{d.label}</span>
              <span className="text-sm text-white text-right font-medium break-all">{d.value}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-6 rounded-xl border border-cyan-900/50 bg-cyan-900/10 p-4">
        <div className="flex items-start gap-3">
          <Zap className="h-5 w-5 text-cyan-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-sm font-medium text-cyan-400">Scan will begin immediately</p>
            <p className="mt-1 text-xs text-gray-400">
              The AI agent will start analyzing your target. You can monitor progress in the Pentest Detail page.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
