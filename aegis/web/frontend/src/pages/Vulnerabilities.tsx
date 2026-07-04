import { useEffect, useState } from 'react'
import { Shield, AlertTriangle, XCircle, Filter } from 'lucide-react'
import { api } from '../lib/api'

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState<any[]>([])
  const [filter, setFilter] = useState<string>('all')

  useEffect(() => {
    api.listVulnerabilities().then(setVulns)
  }, [])

  const filtered = filter === 'all' 
    ? vulns 
    : vulns.filter(v => v.severity === filter)

  const stats = {
    critical: vulns.filter(v => v.severity === 'critical').length,
    high: vulns.filter(v => v.severity === 'high').length,
    medium: vulns.filter(v => v.severity === 'medium').length,
    low: vulns.filter(v => v.severity === 'low').length,
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Vulnerabilities</h1>
        <div className="flex gap-2">
          {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                filter === f
                  ? 'bg-cyan-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {f === 'all' ? `All (${vulns.length})` : `${f} (${stats[f as keyof typeof stats]})`}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-3">
        {filtered.map((vuln) => (
          <VulnRow key={`${vuln.scan_id}-${vuln.id}`} vuln={vuln} />
        ))}
        {filtered.length === 0 && (
          <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-12 text-center text-gray-500">
            No vulnerabilities found
          </div>
        )}
      </div>
    </div>
  )
}

function VulnRow({ vuln }: { vuln: any }) {
  const [expanded, setExpanded] = useState(false)

  const severityConfig: Record<string, { bg: string; text: string; icon: any }> = {
    critical: { bg: 'bg-red-900/30', text: 'text-red-400', icon: XCircle },
    high: { bg: 'bg-orange-900/30', text: 'text-orange-400', icon: AlertTriangle },
    medium: { bg: 'bg-yellow-900/30', text: 'text-yellow-400', icon: Shield },
    low: { bg: 'bg-blue-900/30', text: 'text-blue-400', icon: Shield },
  }

  const config = severityConfig[vuln.severity] || severityConfig.low
  const Icon = config.icon

  return (
    <div className={`rounded-xl border border-gray-800 ${config.bg}`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-4 p-4 text-left"
      >
        <Icon className={`h-5 w-5 ${config.text}`} />
        <div className="flex-1">
          <p className="font-medium">{vuln.title}</p>
          <p className="text-sm text-gray-400">{vuln.scan_id}</p>
        </div>
        <span className="rounded bg-gray-800 px-2 py-1 text-xs font-medium">
          {vuln.severity}
        </span>
        {vuln.cvss && (
          <span className="text-sm text-gray-400">{vuln.cvss}</span>
        )}
      </button>

      {expanded && (
        <div className="border-t border-gray-800 p-4">
          <p className="text-sm text-gray-300">{vuln.description}</p>
          {vuln.endpoint && (
            <p className="mt-2 text-sm text-gray-400">Endpoint: {vuln.endpoint}</p>
          )}
        </div>
      )}
    </div>
  )
}
