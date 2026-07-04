import { useState } from 'react'
import { 
  Github, 
  Gitlab, 
  Box,
  MessageSquare,
  Users,
  Check,
  ExternalLink,
  Plus
} from 'lucide-react'

const codeProviders = [
  { id: 'github', name: 'GitHub', icon: Github, connected: false, color: 'text-white' },
  { id: 'gitlab', name: 'GitLab', icon: Gitlab, connected: false, color: 'text-orange-500' },
  { id: 'bitbucket', name: 'Bitbucket', icon: Box, connected: false, color: 'text-blue-500' },
]

const communication = [
  { id: 'slack', name: 'Slack', icon: MessageSquare, connected: false, color: 'text-purple-500', available: true },
  { id: 'teams', name: 'Microsoft Teams', icon: Users, connected: false, color: 'text-blue-600', available: false },
]

export default function Integrations() {
  const [connections, setConnections] = useState<Record<string, boolean>>({})

  const handleConnect = (id: string) => {
    // In production, this would open OAuth flow
    setConnections({ ...connections, [id]: !connections[id] })
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Integrations</h1>
        <p className="mt-1 text-gray-400">Connect your tools and services</p>
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
            const isConnected = connections[provider.id]
            return (
              <div
                key={provider.id}
                className="flex items-center justify-between rounded-xl border border-gray-800 bg-gray-900/50 px-6 py-4"
              >
                <div className="flex items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gray-800">
                    <Icon className={`h-6 w-6 ${provider.color}`} />
                  </div>
                  <div>
                    <p className="font-medium text-white">{provider.name}</p>
                    <p className="text-sm text-gray-400">
                      {isConnected ? 'Connected' : 'Not connected'}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => handleConnect(provider.id)}
                  className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
                    isConnected
                      ? 'bg-green-900/50 text-green-400 hover:bg-green-900/70'
                      : 'bg-white text-gray-900 hover:bg-gray-100'
                  }`}
                >
                  {isConnected ? (
                    <span className="flex items-center gap-2">
                      <Check className="h-4 w-4" /> Connected
                    </span>
                  ) : (
                    'Connect'
                  )}
                </button>
              </div>
            )
          })}
        </div>
      </section>

      {/* Communication */}
      <section>
        <div className="mb-4">
          <h2 className="text-xl font-semibold text-white">Communication</h2>
          <p className="text-sm text-gray-400">Get notified about test results and findings in your team channels</p>
        </div>
        <div className="space-y-3">
          {communication.map((item) => {
            const Icon = item.icon
            const isConnected = connections[item.id]
            return (
              <div
                key={item.id}
                className="flex items-center justify-between rounded-xl border border-gray-800 bg-gray-900/50 px-6 py-4"
              >
                <div className="flex items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gray-800">
                    <Icon className={`h-6 w-6 ${item.color}`} />
                  </div>
                  <div>
                    <p className="font-medium text-white">{item.name}</p>
                    <p className="text-sm text-gray-400">
                      {item.available ? (isConnected ? 'Connected' : 'Not connected') : 'Coming soon'}
                    </p>
                  </div>
                </div>
                {item.available ? (
                  <button
                    onClick={() => handleConnect(item.id)}
                    className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
                      isConnected
                        ? 'bg-green-900/50 text-green-400 hover:bg-green-900/70'
                        : 'bg-white text-gray-900 hover:bg-gray-100'
                    }`}
                  >
                    {isConnected ? (
                      <span className="flex items-center gap-2">
                        <Check className="h-4 w-4" /> Connected
                      </span>
                    ) : (
                      'Connect'
                    )}
                  </button>
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
