import { useState } from 'react'
import { 
  Save, 
  Loader2, 
  Check,
  Key,
  Server,
  Shield,
  Bell,
  Database
} from 'lucide-react'

const providers = [
  { id: 'openai', name: 'OpenAI', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo'] },
  { id: 'anthropic', name: 'Anthropic', models: ['claude-sonnet-4-6', 'claude-opus-4'] },
  { id: 'google', name: 'Google', models: ['gemini-2.5-pro', 'gemini-2.0-flash'] },
  { id: 'deepseek', name: 'DeepSeek', models: ['deepseek-v4', 'deepseek-chat'] },
  { id: 'opencode', name: 'OpenCode', models: ['mimo-v2.5-free'] },
]

export default function Settings() {
  const [settings, setSettings] = useState({
    provider: 'openai',
    model: 'gpt-4o',
    apiKey: '',
    apiBase: '',
    dockerImage: 'ghcr.io/vizvasanlya/aegis-sandbox:latest',
    maxBudget: '',
    reasoningEffort: 'high',
    telemetry: true,
    notifications: true,
  })
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const handleSave = async () => {
    setSaving(true)
    // Simulate save
    await new Promise(r => setTimeout(r, 1000))
    setSaving(false)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const currentProvider = providers.find(p => p.id === settings.provider)

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Settings</h1>
        <p className="mt-1 text-gray-400">Configure Aegis behavior and integrations</p>
      </div>

      <div className="max-w-3xl space-y-6">
        {/* LLM Provider */}
        <SettingsSection icon={Key} title="LLM Provider" description="Configure the AI model used for scanning">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300">Provider</label>
              <select
                value={settings.provider}
                onChange={(e) => setSettings({ ...settings, provider: e.target.value, model: '' })}
                className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white focus:border-cyan-500 focus:outline-none"
              >
                {providers.map(p => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300">Model</label>
              <select
                value={settings.model}
                onChange={(e) => setSettings({ ...settings, model: e.target.value })}
                className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white focus:border-cyan-500 focus:outline-none"
              >
                {currentProvider?.models.map(m => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300">API Key</label>
              <input
                type="password"
                value={settings.apiKey}
                onChange={(e) => setSettings({ ...settings, apiKey: e.target.value })}
                placeholder="Enter your API key"
                className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300">API Base URL (Optional)</label>
              <input
                type="text"
                value={settings.apiBase}
                onChange={(e) => setSettings({ ...settings, apiBase: e.target.value })}
                placeholder="https://api.example.com/v1"
                className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300">Reasoning Effort</label>
              <select
                value={settings.reasoningEffort}
                onChange={(e) => setSettings({ ...settings, reasoningEffort: e.target.value })}
                className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white focus:border-cyan-500 focus:outline-none"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>
          </div>
        </SettingsSection>

        {/* Docker */}
        <SettingsSection icon={Server} title="Docker Configuration" description="Configure the sandbox environment">
          <div>
            <label className="block text-sm font-medium text-gray-300">Docker Image</label>
            <input
              type="text"
              value={settings.dockerImage}
              onChange={(e) => setSettings({ ...settings, dockerImage: e.target.value })}
              className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 font-mono text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </SettingsSection>

        {/* Budget */}
        <SettingsSection icon={Database} title="Budget" description="Set spending limits">
          <div>
            <label className="block text-sm font-medium text-gray-300">Max Budget (USD)</label>
            <input
              type="number"
              value={settings.maxBudget}
              onChange={(e) => setSettings({ ...settings, maxBudget: e.target.value })}
              placeholder="No limit"
              className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </SettingsSection>

        {/* Notifications */}
        <SettingsSection icon={Bell} title="Notifications" description="Configure alerts and notifications">
          <div className="space-y-3">
            <ToggleSetting
              label="Email notifications"
              description="Get notified when scans complete"
              enabled={settings.notifications}
              onChange={(v) => setSettings({ ...settings, notifications: v })}
            />
            <ToggleSetting
              label="Telemetry"
              description="Send anonymous usage data"
              enabled={settings.telemetry}
              onChange={(v) => setSettings({ ...settings, telemetry: v })}
            />
          </div>
        </SettingsSection>

        {/* Save Button */}
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-6 py-3 font-medium text-white hover:bg-cyan-700 disabled:opacity-50 transition-colors"
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
    <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-6">
      <div className="mb-4 flex items-center gap-3">
        <div className="rounded-lg bg-cyan-900/30 p-2">
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

function ToggleSetting({ label, description, enabled, onChange }: any) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-white">{label}</p>
        <p className="text-xs text-gray-400">{description}</p>
      </div>
      <button
        onClick={() => onChange(!enabled)}
        className={`relative h-6 w-11 rounded-full transition-colors ${
          enabled ? 'bg-cyan-600' : 'bg-gray-700'
        }`}
      >
        <div
          className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
            enabled ? 'translate-x-5' : 'translate-x-0.5'
          }`}
        />
      </button>
    </div>
  )
}
