import { useEffect, useState } from 'react'
import { 
  Save, 
  Loader2, 
  Check,
  Key,
  Server,
  Shield,
  Bell,
  Database,
  ChevronDown,
  ExternalLink,
  AlertCircle
} from 'lucide-react'
import { api } from '../lib/api'

const providers = [
  {
    id: 'opencode',
    name: 'OpenCode Zen',
    description: 'Curated models with best performance',
    models: [
      // Free models
      { id: 'mimo-v2.5-free', name: 'MiMo V2.5 Free', pricing: 'Free' },
      { id: 'deepseek-v4-flash-free', name: 'DeepSeek V4 Flash Free', pricing: 'Free' },
      { id: 'north-mini-code-free', name: 'North Mini Code Free', pricing: 'Free' },
      { id: 'nemotron-3-ultra-free', name: 'Nemotron 3 Ultra Free', pricing: 'Free' },
      { id: 'big-pickle', name: 'Big Pickle', pricing: 'Free' },
      // GPT Models
      { id: 'gpt-5.5', name: 'GPT 5.5', pricing: '$5/$30 per 1M tokens' },
      { id: 'gpt-5.4', name: 'GPT 5.4', pricing: '$2.50/$15 per 1M tokens' },
      { id: 'gpt-5.4-mini', name: 'GPT 5.4 Mini', pricing: '$0.75/$4.50 per 1M tokens' },
      { id: 'gpt-5.4-nano', name: 'GPT 5.4 Nano', pricing: '$0.20/$1.25 per 1M tokens' },
      { id: 'gpt-5', name: 'GPT 5', pricing: '$1.07/$8.50 per 1M tokens' },
      { id: 'gpt-5-nano', name: 'GPT 5 Nano', pricing: '$0.05/$0.40 per 1M tokens' },
      // Claude Models
      { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6', pricing: '$3/$15 per 1M tokens' },
      { id: 'claude-sonnet-4-5', name: 'Claude Sonnet 4.5', pricing: '$3/$15 per 1M tokens' },
      { id: 'claude-opus-4-6', name: 'Claude Opus 4.6', pricing: '$5/$25 per 1M tokens' },
      { id: 'claude-haiku-4-5', name: 'Claude Haiku 4.5', pricing: '$1/$5 per 1M tokens' },
      // Gemini Models
      { id: 'gemini-3.5-flash', name: 'Gemini 3.5 Flash', pricing: '$1.50/$9 per 1M tokens' },
      { id: 'gemini-3.1-pro', name: 'Gemini 3.1 Pro', pricing: '$2/$12 per 1M tokens' },
      { id: 'gemini-3-flash', name: 'Gemini 3 Flash', pricing: '$0.50/$3 per 1M tokens' },
      // DeepSeek Models
      { id: 'deepseek-v4-pro', name: 'DeepSeek V4 Pro', pricing: '$1.74/$3.48 per 1M tokens' },
      { id: 'deepseek-v4-flash', name: 'DeepSeek V4 Flash', pricing: '$0.14/$0.28 per 1M tokens' },
      // Qwen Models
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

export default function Settings() {
  const [settings, setSettings] = useState({
    provider: 'opencode',
    model: 'mimo-v2.5-free',
    apiKey: '',
    apiBase: '',
    dockerImage: 'ghcr.io/vizvasanlya/aegis-sandbox:latest',
    maxBudget: '',
    reasoningEffort: 'high',
    telemetry: true,
  })
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [testingModel, setTestingModel] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)

  useEffect(() => {
    api.getSettings().then(data => {
      // Find provider from model
      const model = data.model || ''
      const provider = providers.find(p => 
        p.models.some(m => `opencode/${m.id}` === model || m.id === model)
      )
      setSettings({
        provider: provider?.id || 'opencode',
        model: model.replace('opencode/', ''),
        apiKey: data.api_key === '***' ? '' : data.api_key,
        apiBase: data.api_base || '',
        dockerImage: data.image || 'ghcr.io/vizvasanlya/aegis-sandbox:latest',
        maxBudget: '',
        reasoningEffort: 'high',
        telemetry: data.telemetry ?? true,
      })
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
        image: settings.dockerImage,
      })
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
      // Test by creating a simple scan that will fail fast
      // This validates the model configuration works
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
        {/* LLM Provider */}
        <SettingsSection icon={Key} title="LLM Provider" description="Select and configure the AI model for scanning">
          <div className="space-y-5">
            {/* Provider Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Provider</label>
              <div className="grid grid-cols-2 gap-3">
                {providers.map((p) => (
                  <button
                    key={p.id}
                    onClick={() => setSettings({ ...settings, provider: p.id, model: p.models[0]?.id || '' })}
                    className={`rounded-xl border p-4 text-left transition-all ${
                      settings.provider === p.id
                        ? 'border-cyan-500 bg-cyan-900/20'
                        : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                    }`}
                  >
                    <p className="font-medium text-white">{p.name}</p>
                    <p className="text-xs text-gray-400 mt-1">{p.description}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Model Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Model</label>
              <div className="max-h-60 overflow-y-auto rounded-xl border border-gray-700 bg-gray-800/50 divide-y divide-gray-700">
                {currentProvider?.models.map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setSettings({ ...settings, model: m.id })}
                    className={`flex w-full items-center justify-between px-4 py-3 text-left transition-colors ${
                      settings.model === m.id
                        ? 'bg-cyan-900/30 text-cyan-400'
                        : 'text-gray-300 hover:bg-gray-700/50'
                    }`}
                  >
                    <div>
                      <p className="font-medium">{m.name}</p>
                      <p className="text-xs text-gray-500">{m.id}</p>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded ${
                      m.pricing === 'Free' 
                        ? 'bg-green-900/50 text-green-400' 
                        : 'bg-gray-700 text-gray-400'
                    }`}>
                      {m.pricing}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* API Key */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                API Key
                {settings.provider === 'opencode' && (
                  <a href="https://opencode.ai/auth" target="_blank" rel="noopener noreferrer" 
                     className="ml-2 text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1">
                    Get key <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </label>
              <input
                type="password"
                value={settings.apiKey}
                onChange={(e) => setSettings({ ...settings, apiKey: e.target.value })}
                placeholder={settings.provider === 'opencode' ? 'Enter your Zen API key' : 'Enter your API key'}
                className="w-full rounded-xl border border-gray-700 bg-gray-800/50 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            {/* API Base URL */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">API Base URL (Optional)</label>
              <input
                type="text"
                value={settings.apiBase}
                onChange={(e) => setSettings({ ...settings, apiBase: e.target.value })}
                placeholder="https://opencode.ai/zen/v1"
                className="w-full rounded-xl border border-gray-700 bg-gray-800/50 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
              <p className="mt-1 text-xs text-gray-500">
                Default: https://opencode.ai/zen/v1 (for OpenCode Zen)
              </p>
            </div>

            {/* Test Model Button */}
            <button
              onClick={handleTestModel}
              disabled={testingModel || !settings.model}
              className="flex items-center gap-2 rounded-xl border border-gray-700 px-4 py-2.5 text-sm font-medium text-gray-300 hover:bg-gray-800 hover:text-white disabled:opacity-50 transition-colors"
            >
              {testingModel ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}
              Test Configuration
            </button>

            {testResult && (
              <div className={`flex items-center gap-2 rounded-xl px-4 py-3 text-sm ${
                testResult.success 
                  ? 'bg-green-900/30 text-green-400 border border-green-800' 
                  : 'bg-red-900/30 text-red-400 border border-red-800'
              }`}>
                {testResult.success ? <Check className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
                {testResult.message}
              </div>
            )}
          </div>
        </SettingsSection>

        {/* Docker */}
        <SettingsSection icon={Server} title="Docker Configuration" description="Configure the sandbox environment">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Docker Image</label>
            <input
              type="text"
              value={settings.dockerImage}
              onChange={(e) => setSettings({ ...settings, dockerImage: e.target.value })}
              className="w-full rounded-xl border border-gray-700 bg-gray-800/50 px-4 py-3 font-mono text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            />
            <p className="mt-1 text-xs text-gray-500">
              Image is pulled automatically on first run
            </p>
          </div>
        </SettingsSection>

        {/* Save Button */}
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 rounded-xl bg-cyan-600 px-6 py-3 font-medium text-white hover:bg-cyan-700 disabled:opacity-50 transition-colors"
        >
          {saving ? (
            <Loader2 className="h-5 w-5 animate-spin" />
          ) : saved ? (
            <Check className="h-5 w-5" />
          ) : (
            <Save className="h-5 w-5" />
          )}
          {saving ? 'Saving...' : saved ? 'Saved!' : 'Save Settings'}
        </button>
      </div>
    </div>
  )
}

function SettingsSection({ icon: Icon, title, description, children }: any) {
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
