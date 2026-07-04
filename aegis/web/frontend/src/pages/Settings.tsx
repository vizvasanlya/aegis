import { useEffect, useState } from 'react'
import { Save, Loader2, Check } from 'lucide-react'
import { api } from '../lib/api'

export default function Settings() {
  const [settings, setSettings] = useState({
    model: '',
    api_key: '',
    api_base: '',
    image: '',
  })
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    api.getSettings().then(setSettings)
  }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      await api.updateSettings(settings)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-8">
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="mt-1 text-gray-400">Configure Aegis behavior</p>
      </div>

      <div className="space-y-6">
        {/* LLM Model */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-6">
          <h2 className="text-lg font-semibold">LLM Configuration</h2>
          <p className="mt-1 text-sm text-gray-400">Configure the AI model used for scanning</p>
          
          <div className="mt-4 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300">Model</label>
              <select
                value={settings.model}
                onChange={(e) => setSettings({ ...settings, model: e.target.value })}
                className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white focus:border-cyan-500 focus:outline-none"
              >
                <option value="">Select a model</option>
                <option value="openai/gpt-4o">OpenAI GPT-4o</option>
                <option value="openai/gpt-4o-mini">OpenAI GPT-4o Mini</option>
                <option value="anthropic/claude-sonnet-4-6">Claude Sonnet 4.6</option>
                <option value="opencode/deepseek-v4">DeepSeek V4</option>
                <option value="opencode/mimo-v2.5-free">MiMo V2.5</option>
                <option value="vertex_ai/gemini-2.5-pro">Gemini 2.5 Pro</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300">API Key</label>
              <input
                type="password"
                value={settings.api_key}
                onChange={(e) => setSettings({ ...settings, api_key: e.target.value })}
                placeholder="Enter your API key"
                className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300">API Base URL (Optional)</label>
              <input
                type="text"
                value={settings.api_base}
                onChange={(e) => setSettings({ ...settings, api_base: e.target.value })}
                placeholder="https://api.example.com/v1"
                className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>
        </div>

        {/* Docker Image */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-6">
          <h2 className="text-lg font-semibold">Docker Image</h2>
          <p className="mt-1 text-sm text-gray-400">Configure the sandbox image</p>
          
          <div className="mt-4">
            <label className="block text-sm font-medium text-gray-300">Image</label>
            <input
              type="text"
              value={settings.image}
              onChange={(e) => setSettings({ ...settings, image: e.target.value })}
              placeholder="ghcr.io/vizvasanlya/aegis-sandbox:latest"
              className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 font-mono text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>

        {/* Save Button */}
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-6 py-3 font-medium text-white hover:bg-cyan-700 disabled:opacity-50"
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
