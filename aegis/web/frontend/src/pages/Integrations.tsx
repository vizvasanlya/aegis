import { useEffect, useState } from 'react'
import { 
  Github, 
  Gitlab, 
  Box,
  MessageSquare,
  Users,
  Check,
  ExternalLink,
  Loader2,
  Settings,
  AlertCircle
} from 'lucide-react'
import { api } from '../lib/api'

const codeProviders = [
  { id: 'github', name: 'GitHub', icon: Github, color: 'text-white', description: 'Connect GitHub repositories for source-aware pentesting' },
  { id: 'gitlab', name: 'GitLab', icon: Gitlab, color: 'text-orange-500', description: 'Connect GitLab repositories for source-aware pentesting' },
]

const communication = [
  { id: 'slack', name: 'Slack', icon: MessageSquare, color: 'text-purple-500', available: true, description: 'Get notified about test results in Slack' },
  { id: 'teams', name: 'Microsoft Teams', icon: Users, color: 'text-blue-600', available: false, description: 'Coming soon' },
]

export default function Integrations() {
  const [statuses, setStatuses] = useState<Record<string, boolean>>({})
  const [configuring, setConfiguring] = useState<string | null>(null)
  const [configForm, setConfigForm] = useState({ clientId: '', clientSecret: '' })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check connection status for all providers
    Promise.all(
      [...codeProviders, ...communication.filter(c => c.available)].map(p => 
        api.getAuthStatus(p.id).catch(() => ({ connected: false }))
      )
    ).then(results => {
      const newStatuses: Record<string, boolean> = {}
      results.forEach((r: any, i: number) => {
        const provider = [...codeProviders, ...communication.filter(c => c.available)][i]
        newStatuses[provider.id] = r.connected || false
      })
      setStatuses(newStatuses)
      setLoading(false)
    })
  }, [])

  const handleConnect = async (providerId: string) => {
    setConfiguring(providerId)
  }

  const handleSaveConfig = async () => {
    if (!configuring || !configForm.clientId) return
    
    try {
      // Save OAuth config
      await fetch(`/api/auth/${configuring}/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: configuring,
          client_id: configForm.clientId,
          client_secret: configForm.clientSecret,
          redirect_uri: `${window.location.origin}/api/auth/callback`,
        }),
      })
      
      // Get authorization URL
      const response = await fetch(`/api/auth/${configuring}/authorize`)
      const { auth_url } = await response.json()
      
      // Redirect to OAuth provider
      window.location.href = auth_url
    } catch (err) {
      console.error('Failed to initiate OAuth:', err)
    }
  }

  const handleDisconnect = async (providerId: string) => {
    try {
      await api.disconnectAuth(providerId)
      setStatuses({ ...statuses, [providerId]: false })
    } catch (err) {
      console.error('Failed to disconnect:', err)
    }
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Integrations</h1>
        <p className="mt-1 text-gray-400">Connect your tools and services for automated pentesting</p>
      </div>

      {/* Code Providers */}
      <section className="mb-10">
        <div className="mb-4">
          <h2 className="text-xl font-semibold text-white">Code Providers</h2>
          <p className="text-sm text-gray-400">Connect your repositories for source-aware pentesting</p>
        </div>
        <div className="space-y-3">
          {codeProviders.map((provider) => {
            const Icon = provider.icon
            const isConnected = statuses[provider.id]
            const isConfiguring = configuring === provider.id
            
            return (
              <div key={provider.id} className="rounded-xl border border-gray-800 bg-gray-900/50">
                <div className="flex items-center justify-between px-6 py-4">
                  <div className="flex items-center gap-4">
                    <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gray-800">
                      <Icon className={`h-6 w-6 ${provider.color}`} />
                    </div>
                    <div>
                      <p className="font-medium text-white">{provider.name}</p>
                      <p className="text-sm text-gray-400">{provider.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {isConnected ? (
                      <>
                        <span className="flex items-center gap-2 rounded-full bg-green-900/50 px-3 py-1.5 text-sm text-green-400">
                          <Check className="h-4 w-4" />
                          Connected
                        </span>
                        <button
                          onClick={() => handleDisconnect(provider.id)}
                          className="rounded-lg px-3 py-1.5 text-sm text-gray-400 hover:text-red-400"
                        >
                          Disconnect
                        </button>
                      </>
                    ) : (
                      <button
                        onClick={() => handleConnect(provider.id)}
                        className="rounded-lg bg-white px-4 py-2 text-sm font-medium text-gray-900 hover:bg-gray-100"
                      >
                        Connect
                      </button>
                    )}
                  </div>
                </div>
                
                {/* Configuration Form */}
                {isConfiguring && (
                  <div className="border-t border-gray-800 px-6 py-4">
                    <div className="rounded-lg bg-gray-800/50 p-4">
                      <div className="mb-3 flex items-center gap-2">
                        <Settings className="h-4 w-4 text-gray-400" />
                        <p className="text-sm font-medium text-white">OAuth Configuration</p>
                      </div>
                      <p className="mb-4 text-xs text-gray-400">
                        Create an OAuth App at {provider.name === 'GitHub' ? 'github.com/settings/developers' : 'gitlab.com/-/profile/applications'} and enter the credentials below.
                      </p>
                      <div className="space-y-3">
                        <input
                          type="text"
                          placeholder="Client ID"
                          value={configForm.clientId}
                          onChange={(e) => setConfigForm({ ...configForm, clientId: e.target.value })}
                          className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                        />
                        <input
                          type="password"
                          placeholder="Client Secret"
                          value={configForm.clientSecret}
                          onChange={(e) => setConfigForm({ ...configForm, clientSecret: e.target.value })}
                          className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                        />
                        <p className="text-xs text-gray-500">
                          Redirect URI: {window.location.origin}/api/auth/callback
                        </p>
                        <div className="flex gap-2">
                          <button
                            onClick={handleSaveConfig}
                            disabled={!configForm.clientId}
                            className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-700 disabled:opacity-50"
                          >
                            Save & Connect
                          </button>
                          <button
                            onClick={() => { setConfiguring(null); setConfigForm({ clientId: '', clientSecret: '' }) }}
                            className="rounded-lg px-4 py-2 text-sm text-gray-400 hover:text-white"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* Communication */}
      <section>
        <div className="mb-4">
          <h2 className="text-xl font-semibold text-white">Communication</h2>
          <p className="text-sm text-gray-400">Get notified about test results and findings</p>
        </div>
        <div className="space-y-3">
          {communication.map((item) => {
            const Icon = item.icon
            const isConnected = statuses[item.id]
            return (
              <div key={item.id} className="flex items-center justify-between rounded-xl border border-gray-800 bg-gray-900/50 px-6 py-4">
                <div className="flex items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gray-800">
                    <Icon className={`h-6 w-6 ${item.color}`} />
                  </div>
                  <div>
                    <p className="font-medium text-white">{item.name}</p>
                    <p className="text-sm text-gray-400">{item.description}</p>
                  </div>
                </div>
                {item.available ? (
                  isConnected ? (
                    <span className="flex items-center gap-2 rounded-full bg-green-900/50 px-3 py-1.5 text-sm text-green-400">
                      <Check className="h-4 w-4" /> Connected
                    </span>
                  ) : (
                    <button className="rounded-lg bg-white px-4 py-2 text-sm font-medium text-gray-900 hover:bg-gray-100">
                      Connect
                    </button>
                  )
                ) : (
                  <span className="text-sm text-gray-500">Coming soon</span>
                )}
              </div>
            )
          })}
        </div>
      </section>
    </div>
  )
}
