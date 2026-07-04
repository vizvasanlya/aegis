import { useEffect, useState } from 'react'
import { 
  Shield, 
  Search,
  Loader2
} from 'lucide-react'
import { api } from '../lib/api'
import VulnerabilityModal from '../components/VulnerabilityModal'

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [selectedVuln, setSelectedVuln] = useState<any>(null)

  useEffect(() => {
    api.listVulnerabilities().then(data => {
      setVulns(data)
      setLoading(false)
    })
  }, [])

  const filtered = vulns
    .filter((v: any) => filter === 'all' || v.severity === filter)
    .filter((v: any) => 
      v.title?.toLowerCase().includes(search.toLowerCase()) ||
      v.description?.toLowerCase().includes(search.toLowerCase())
    )

  const counts = {
    all: vulns.length,
    critical: vulns.filter((v: any) => v.severity === 'critical').length,
    high: vulns.filter((v: any) => v.severity === 'high').length,
    medium: vulns.filter((v: any) => v.severity === 'medium').length,
    low: vulns.filter((v: any) => v.severity === 'low').length,
  }

  return (
    <div className="p-8">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-white">Vulnerabilities</h1>
        <p className="mt-1 text-gray-400">All findings across all pentests</p>
      </div>

      {/* Filters */}
      <div className="mb-6 flex flex-wrap items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search vulnerabilities..."
            className="w-full rounded-xl border border-gray-800 bg-gray-900/50 py-2.5 pl-12 pr-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
        <div className="flex gap-2">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                filter === f
                  ? 'bg-cyan-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-white'
              }`}
            >
              {f === 'all' ? `All (${counts.all})` : `${f} (${counts[f]})`}
            </button>
          ))}
        </div>
      </div>

      {/* Vulnerability List */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="rounded-2xl border border-gray-800 bg-gray-900/50 py-20 text-center">
          <Shield className="mx-auto h-16 w-16 text-gray-700" />
          <h3 className="mt-4 text-lg font-medium text-gray-400">
            {search || filter !== 'all' ? 'No matching vulnerabilities' : 'No vulnerabilities found'}
          </h3>
          <p className="mt-2 text-sm text-gray-500">Run a pentest to discover security issues</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((vuln: any, idx: number) => (
            <VulnRow 
              key={`${vuln.scan_id}-${vuln.id || idx}`} 
              vuln={vuln} 
              onClick={() => setSelectedVuln(vuln)} 
            />
          ))}
        </div>
      )}

      {/* Modal */}
      {selectedVuln && (
        <VulnerabilityModal vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />
      )}
    </div>
  )
}

function VulnRow({ vuln, onClick }: { vuln: any; onClick: () => void }) {
  const severityConfig: Record<string, { bg: string; dot: string }> = {
    critical: { bg: 'bg-red-950/50', dot: 'bg-red-500' },
    high: { bg: 'bg-orange-950/50', dot: 'bg-orange-500' },
    medium: { bg: 'bg-yellow-950/50', dot: 'bg-yellow-500' },
    low: { bg: 'bg-blue-950/50', dot: 'bg-blue-500' },
  }

  const config = severityConfig[vuln.severity] || severityConfig.low

  return (
    <button
      onClick={onClick}
      className={`w-full rounded-xl border border-gray-800 ${config.bg} p-4 text-left transition-all hover:border-gray-700`}
    >
      <div className="flex items-center gap-4">
        <div className={`h-2.5 w-2.5 rounded-full flex-shrink-0 ${config.dot}`} />
        <div className="flex-1 min-w-0">
          <p className="font-medium text-white truncate">{vuln.title}</p>
          <p className="text-sm text-gray-400 truncate mt-0.5">{vuln.scan_id}</p>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          {vuln.cvss && <span className="text-sm text-gray-400">{vuln.cvss}</span>}
          <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${
            vuln.severity === 'critical' ? 'bg-red-900/50 text-red-400' :
            vuln.severity === 'high' ? 'bg-orange-900/50 text-orange-400' :
            vuln.severity === 'medium' ? 'bg-yellow-900/50 text-yellow-400' :
            'bg-blue-900/50 text-blue-400'
          }`}>
            {vuln.severity}
          </span>
        </div>
      </div>
    </button>
  )
}
