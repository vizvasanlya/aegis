import { useEffect, useState } from 'react'
import {
  Save,
  Loader2,
  Check,
  Key,
  Shield,
  ExternalLink,
  Eye,
  EyeOff,
  ChevronDown,
  Gauge,
  Activity,
} from 'lucide-react'
import { api } from '../lib/api'

const providers = [
  {
    id: 'opencode',
    name: 'OpenCode Zen',
    description: 'Curated models with best performance',
    models: [
      { id: 'mimo-v2.5-free', name: 'MiMo V2.5 Free', pricing: 'Free' },
      { id: 'deepseek-v4-flash-free', name: 'DeepSeek V4 Flash Free', pricing: 'Free' },
      { id: 'north-mini-code-free', name: 'North Mini Code Free', pricing: 'Free' },
      { id: 'nemotron-3-ultra-free', name: 'Nemotron 3 Ultra Free', pricing: 'Free' },
      { id: 'big-pickle', name: 'Big Pickle', pricing: 'Free' },
      { id: 'gpt-5.5', name: 'GPT 5.5', pricing: '$5/$30 per 1M tokens' },
      { id: 'gpt-5.4', name: 'GPT 5.4', pricing: '$2.50/$15 per 1M tokens' },
      { id: 'gpt-5.4-mini', name: 'GPT 5.4 Mini', pricing: '$0.75/$4.50 per 1M tokens' },
      { id: 'gpt-5.4-nano', name: 'GPT 5.4 Nano', pricing: '$0.20/$1.25 per 1M tokens' },
      { id: 'gpt-5', name: 'GPT 5', pricing: '$1.07/$8.50 per 1M tokens' },
      { id: 'gpt-5-nano', name: 'GPT 5 Nano', pricing: '$0.05/$0.40 per 1M tokens' },
      { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6', pricing: '$3/$15 per 1M tokens' },
      { id: 'claude-sonnet-4-5', name: 'Claude Sonnet 4.5', pricing: '$3/$15 per 1M tokens' },
      { id: 'claude-opus-4-6', name: 'Claude Opus 4.6', pricing: '$5/$25 per 1M tokens' },
      { id: 'claude-haiku-4-5', name: 'Claude Haiku 4.5', pricing: '$1/$5 per 1M tokens' },
      { id: 'gemini-3.5-flash', name: 'Gemini 3.5 Flash', pricing: '$1.50/$9 per 1M tokens' },
      { id: 'gemini-3.1-pro', name: 'Gemini 3.1 Pro', pricing: '$2/$12 per 1M tokens' },
      { id: 'gemini-3-flash', name: 'Gemini 3 Flash', pricing: '$0.50/$3 per 1M tokens' },
      { id: 'deepseek-v4-pro', name: 'DeepSeek V4 Pro', pricing: '$1.74/$3.48 per 1M tokens' },
      { id: 'deepseek-v4-flash', name: 'DeepSeek V4 Flash', pricing: '$0.14/$0.28 per 1M tokens' },
      { id: 'qwen3.7-max', name: 'Qwen3.7 Max', pricing: '$2.50/$7.50 per 1M tokens' },
      { id: 'qwen3.7-plus', name: 'Qwen3.7 Plus', pricing: '$0.40/$1.60 per 1M tokens' },
    ],
  },
  {
    id: 'openai',
    name: 'OpenAI',
    description: 'Direct OpenAI API access',
    models: [
      { id: 'gpt-4o', name: 'GPT-4o', pricing: '$2.50/$10 per 1M tokens' },
      { id: 'gpt-4o-mini', name: 'GPT-4o Mini', pricing: '$0.15/$0.60 per 1M tokens' },
      { id: 'gpt-4-turbo', name: 'GPT-4 Turbo', pricing: '$10/$30 per 1M tokens' },
    ],
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    description: 'Direct Anthropic API access',
    models: [
      { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6', pricing: '$3/$15 per 1M tokens' },
      { id: 'claude-opus-4', name: 'Claude Opus 4', pricing: '$15/$75 per 1M tokens' },
      { id: 'claude-haiku-3.5', name: 'Claude Haiku 3.5', pricing: '$0.80/$4 per 1M tokens' },
    ],
  },
  {
    id: 'google',
    name: 'Google',
    description: 'Direct Google API access',
    models: [
      { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', pricing: '$1.25/$10 per 1M tokens' },
      { id: 'gemini-2.0-flash', name: 'Gemini 2.0 Flash', pricing: '$0.10/$0.40 per 1M tokens' },
    ],
  },
]

const selectClass = "w-full appearance-none rounded-xl border border-gray-700 bg-gray-800/50 px-4 py-3 pr-10 text-white focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 transition-colors"

function DropdownIcon() {
  return <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
}

function FieldLabel({ children, hint }: { children: React.ReactNode; hint?: string }) {
  return (
    <div className="mb-2">
      <label className="block text-sm font-medium text-gray-300">{children}</label>
      {hint && <p className="mt-0.5 text-xs text-gray-500">{hint}</p>}
    </div>
  )
}

export default function Settings() {
  const [settings, setSettings] = useState({
    provider: 'opencode',
    model: 'mimo-v2.5-free',
    apiKey: '',
    apiBase: '',
    scanMode: 'deep',
    reasoningEffort: 'high',
    timeout: 300,
    telemetry: true,
  })
  const [apiKeyConfigured, setApiKeyConfigured] = useState(false)
  const [showApiKey, setShowApiKey] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [testingModel, setTestingModel] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)

  useEffect(() => {
    api.getSettings().then(data => {
      const model = data.model || ''
      const provider = providers.find(p =>
        p.models.some(m => `opencode/${m.id}` === model || m.id === model)
      )
      setSettings({
        provider: provider?.id || 'opencode',
        model: model.replace('opencode/', ''),
        apiKey: '',
        apiBase: data.api_base || '',
        scanMode: data.scan_mode || 'deep',
        reasoningEffort: data.reasoning_effort || 'high',
        timeout: data.timeout || 300,
        telemetry: data.telemetry ?? true,
      })
      setApiKeyConfigured(data.api_key_configured ?? false)
    })
  }, [])

  const currentProvider = providers.find(p => p.id === settings.provider)

  const handleSave = async () => {
    setSaving(true)
    try {
      const fullModel = settings.provider === 'opencode'
        ? `opencode/${settings.model}`
        : settings.model

      await api.updateSettings({
        model: fullModel,
        api_key: settings.apiKey || undefined,
        api_base: settings.apiBase || undefined,
        scan_mode: settings.scanMode,
        reasoning_effort: settings.reasoningEffort,
        timeout: settings.timeout,
        telemetry: settings.telemetry,
      })
      if (settings.apiKey) {
        setApiKeyConfigured(true)
        setShowApiKey(false)
      }
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } finally {
      setSaving(false)
    }
  }

  const handleTestModel = async () => {
    setTestingModel(true)
    setTestResult(null)
    try {
      const fullModel = settings.provider === 'opencode'
        ? `opencode/${settings.model}`
        : settings.model
      await api.updateSettings({ model: fullModel })
      setTestResult({ success: true, message: `Model ${fullModel} configured successfully` })
    } catch (err) {
      setTestResult({ success: false, message: 'Failed to configure model' })
    } finally {
      setTestingModel(false)
    }
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Settings</h1>
        <p className="mt-1 text-gray-400">Configure Aegis behavior and integrations</p>
      </div>

      <div className="max-w-3xl space-y-6">
        {/* ── LLM Provider ────────────────────────────────────────────── */}
        <Section icon={Key} title="LLM Provider" description="Select and configure the AI model for scanning">
          <div className="space-y-5">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <FieldLabel>Provider</FieldLabel>
                <div className="relative">
                  <select
                    value={settings.provider}
                    onChange={(e) => {
                      const p = providers.find(p => p.id === e.target.value)
                      setSettings({ ...settings, provider: e.target.value, model: p?.models[0]?.id || '' })
                    }}
                    className={selectClass}
                  >
                    {providers.map(p => (
                      <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                  </select>
                  <DropdownIcon />
                </div>
              </div>
              <div>
                <FieldLabel>Model</FieldLabel>
                <div className="relative">
                  <select
                    value={settings.model}
                    onChange={(e) => setSettings({ ...settings, model: e.target.value })}
                    className={selectClass}
                  >
                    {currentProvider?.models.map(m => (
                      <option key={m.id} value={m.id}>{m.name}</option>
                    ))}
                  </select>
                  <DropdownIcon />
                </div>
              </div>
            </div>

            {/* Model pricing info */}
            {currentProvider && (
              <div className="rounded-xl border border-gray-800 bg-gray-800/30 px-4 py-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-500">{currentProvider.models.length} models available</span>
                  <span className={`font-medium ${
                    currentProvider.models.find(m => m.id === settings.model)?.pricing === 'Free'
                      ? 'text-green-400' : 'text-gray-400'
                  }`}>
                    {currentProvider.models.find(m => m.id === settings.model)?.pricing}
                  </span>
                </div>
              </div>
            )}

            {/* API Key */}
            <div>
              <FieldLabel hint={settings.provider === 'opencode' ? undefined : 'Required for direct provider access'}>
                API Key
                {settings.provider === 'opencode' && (
                  <a href="https://opencode.ai/auth" target="_blank" rel="noopener noreferrer"
                     className="ml-2 text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1">
                    Get key <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </FieldLabel>
              {apiKeyConfigured && !showApiKey ? (
                <div className="flex items-center gap-3">
                  <div className="flex-1 flex items-center rounded-xl border border-gray-700 bg-gray-800/50 px-4 py-3">
                    <Key className="h-4 w-4 text-green-400 mr-3 flex-shrink-0" />
                    <span className="flex-1 text-gray-400 tracking-widest text-sm select-none">••••••••••••••••••••</span>
                    <span className="ml-2 text-xs text-green-400 font-medium bg-green-900/30 px-2 py-0.5 rounded-full">Active</span>
                  </div>
                  <button
                    onClick={() => setShowApiKey(true)}
                    className="rounded-xl border border-gray-700 px-4 py-3 text-gray-400 hover:bg-gray-800 hover:text-white transition-colors"
                    title="Edit API key"
                  >
                    <Eye className="h-4 w-4" />
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                  <div className="relative flex-1">
                    <input
                      type={showApiKey ? 'text' : 'password'}
                      value={settings.apiKey}
                      onChange={(e) => setSettings({ ...settings, apiKey: e.target.value })}
                      placeholder={apiKeyConfigured ? 'Enter new key to replace' : 'Paste your API key'}
                      className="w-full rounded-xl border border-gray-700 bg-gray-800/50 px-4 py-3 pr-12 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 transition-colors"
                    />
                    <button
                      type="button"
                      onClick={() => setShowApiKey(!showApiKey)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
                    >
                      {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  {apiKeyConfigured && (
                    <button
                      onClick={() => { setShowApiKey(false); setSettings({ ...settings, apiKey: '' }) }}
                      className="rounded-xl border border-gray-700 px-4 py-3 text-xs text-gray-400 hover:bg-gray-800 hover:text-white transition-colors"
                    >
                      Cancel
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* API Base URL */}
            <div>
              <FieldLabel hint="Override the default API endpoint for your provider">API Base URL</FieldLabel>
              <input
                type="text"
                value={settings.apiBase}
                onChange={(e) => setSettings({ ...settings, apiBase: e.target.value })}
                placeholder="https://opencode.ai/zen/v1"
                className="w-full rounded-xl border border-gray-700 bg-gray-800/50 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 transition-colors"
              />
            </div>

            {/* Test + Result */}
            <div className="flex items-center gap-3">
              <button
                onClick={handleTestModel}
                disabled={testingModel || !settings.model}
                className="flex items-center gap-2 rounded-xl border border-gray-700 px-4 py-2.5 text-sm font-medium text-gray-300 hover:bg-gray-800 hover:text-white disabled:opacity-50 transition-colors"
              >
                {testingModel ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}
                Test Model
              </button>
              {testResult && (
                <span className={`text-sm ${testResult.success ? 'text-green-400' : 'text-red-400'}`}>
                  {testResult.message}
                </span>
              )}
            </div>
          </div>
        </Section>

        {/* ── Scan Defaults ────────────────────────────────────────────── */}
        <Section icon={Gauge} title="Scan Defaults" description="Default behavior for new scans">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="Applied to new scans unless overridden">Scan Mode</FieldLabel>
              <div className="relative">
                <select
                  value={settings.scanMode}
                  onChange={(e) => setSettings({ ...settings, scanMode: e.target.value })}
                  className={selectClass}
                >
                  <option value="standard">Standard</option>
                  <option value="deep">Deep</option>
                  <option value="aggressive">Aggressive</option>
                </select>
                <DropdownIcon />
              </div>
            </div>
            <div>
              <FieldLabel hint="Higher = more thorough, slower, costs more tokens">Reasoning Effort</FieldLabel>
              <div className="relative">
                <select
                  value={settings.reasoningEffort}
                  onChange={(e) => setSettings({ ...settings, reasoningEffort: e.target.value })}
                  className={selectClass}
                >
                  <option value="none">None</option>
                  <option value="minimal">Minimal</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="xhigh">Extra High</option>
                </select>
                <DropdownIcon />
              </div>
            </div>
            <div>
              <FieldLabel hint="Max wait time for a single LLM response">Timeout (seconds)</FieldLabel>
              <input
                type="number"
                value={settings.timeout}
                onChange={(e) => setSettings({ ...settings, timeout: parseInt(e.target.value) || 300 })}
                min={30}
                max={600}
                className="w-full rounded-xl border border-gray-700 bg-gray-800/50 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 transition-colors"
              />
            </div>
          </div>
        </Section>

        {/* ── Telemetry ───────────────────────────────────────────────── */}
        <Section icon={Activity} title="Telemetry" description="Anonymous usage data helps improve Aegis">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-300">Send anonymous telemetry</p>
              <p className="text-xs text-gray-500 mt-0.5">No personal data — only scan counts and error rates</p>
            </div>
            <button
              onClick={() => setSettings({ ...settings, telemetry: !settings.telemetry })}
              className={`relative h-6 w-11 rounded-full transition-colors ${
                settings.telemetry ? 'bg-cyan-600' : 'bg-gray-700'
              }`}
            >
              <span className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
                settings.telemetry ? 'translate-x-5' : 'translate-x-0'
              }`} />
            </button>
          </div>
        </Section>

        {/* ── Save ──────────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between rounded-2xl border border-gray-800 bg-gray-900/50 p-4">
          <p className="text-sm text-gray-500">Changes are saved to disk and persist across restarts</p>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 rounded-xl bg-cyan-600 px-6 py-2.5 font-medium text-white hover:bg-cyan-700 disabled:opacity-50 transition-colors"
          >
            {saving ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : saved ? (
              <Check className="h-4 w-4" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            {saving ? 'Saving...' : saved ? 'Saved!' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  )
}

function Section({ icon: Icon, title, description, children }: any) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
      <div className="mb-5 flex items-center gap-3">
        <div className="rounded-xl bg-cyan-900/30 p-2.5">
          <Icon className="h-5 w-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="font-semibold text-white">{title}</h2>
          <p className="text-sm text-gray-400">{description}</p>
        </div>
      </div>
      {children}
    </div>
  )
}
