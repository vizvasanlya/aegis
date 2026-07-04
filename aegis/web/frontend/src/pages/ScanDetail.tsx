import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { 
  ArrowLeft, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  ExternalLink,
  Copy
} from 'lucide-react'
import { api } from '../lib/api'

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<any>(null)
  const [vulns, setVulns] = useState<any[]>([])
  const [logs, setLogs] = useState('')
  const [activeTab, setActiveTab] = useState<'vulns' | 'logs' | 'details'>('vulns')

  useEffect(() => {
    if (id) {
      api.getScan(id).then(setScan)
      api.getScanVulnerabilities(id).then(setVulns)
      api.getLogs(id, 500).then(data => setLogs(data.logs))
    }
  }, [id])

  if (!scan) {
    return <div className="text-center text-gray-400">Loading...</div>
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link to="/scans" className="rounded-lg p-2 hover:bg-gray-800">
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold">{scan.target}</h1>
          <p className="text-gray-400">{scan.id}</p>
        </div>
        <span className={`ml-auto rounded-full px-3 py-1 text-sm font-medium ${
          scan.status === 'completed' ? 'bg-green-900/50 text-green-400' :
          scan.status === 'running' ? 'bg-blue-900/50 text-blue-400' :
          'bg-gray-800 text-gray-400'
        }`}>
          {scan.status}
        </span>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {[
          { key: 'vulns', label: `Vulnerabilities (${vulns.length})` },
          { key: 'logs', label: 'Logs' },
          { key: 'details', label: 'Details' },
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as any)}
            className={`border-b-2 px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.key
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'vulns' && (
        <div className="space-y-4">
          {vulns.map((vuln) => (
            <VulnerabilityCard key={vuln.id} vuln={vuln} />
          ))}
          {vulns.length === 0 && (
            <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-12 text-center text-gray-500">
              No vulnerabilities found
            </div>
          )}
        </div>
      )}

      {activeTab === 'logs' && (
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-6">
          <pre className="overflow-auto font-mono text-sm text-gray-300">{logs || 'No logs available'}</pre>
        </div>
      )}

      {activeTab === 'details' && (
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-6">
          <dl className="grid grid-cols-2 gap-4">
            <div>
              <dt className="text-sm text-gray-400">Scan ID</dt>
              <dd className="font-mono">{scan.id}</dd>
            </div>
            <div>
              <dt className="text-sm text-gray-400">Target</dt>
              <dd>{scan.target}</dd>
            </div>
            <div>
              <dt className="text-sm text-gray-400">Mode</dt>
              <dd>{scan.scan_mode}</dd>
            </div>
            <div>
              <dt className="text-sm text-gray-400">Status</dt>
              <dd>{scan.status}</dd>
            </div>
          </dl>
        </div>
      )}
    </div>
  )
}

function VulnerabilityCard({ vuln }: { vuln: any }) {
  const [expanded, setExpanded] = useState(false)

  const severityColors: Record<string, string> = {
    critical: 'bg-red-900/50 text-red-400 border-red-800',
    high: 'bg-orange-900/50 text-orange-400 border-orange-800',
    medium: 'bg-yellow-900/50 text-yellow-400 border-yellow-800',
    low: 'bg-blue-900/50 text-blue-400 border-blue-800',
  }

  return (
    <div className={`rounded-xl border ${severityColors[vuln.severity] || 'border-gray-800'} bg-gray-900/50`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between p-4 text-left"
      >
        <div className="flex items-center gap-3">
          <span className="text-lg font-semibold">{vuln.title}</span>
          <span className="rounded px-2 py-0.5 text-xs font-medium bg-gray-800">
            {vuln.severity}
          </span>
          {vuln.cvss && (
            <span className="text-sm text-gray-400">CVSS {vuln.cvss}</span>
          )}
        </div>
        <span className="text-gray-400">{expanded ? '−' : '+'}</span>
      </button>
      
      {expanded && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          <div>
            <h4 className="text-sm font-medium text-gray-400">Description</h4>
            <p className="mt-1">{vuln.description}</p>
          </div>
          {vuln.poc_script_code && (
            <div>
              <h4 className="text-sm font-medium text-gray-400">Proof of Concept</h4>
              <pre className="mt-1 overflow-auto rounded bg-gray-800 p-3 font-mono text-sm">
                {vuln.poc_script_code}
              </pre>
            </div>
          )}
          {vuln.remediation_steps && (
            <div>
              <h4 className="text-sm font-medium text-gray-400">Remediation</h4>
              <p className="mt-1">{vuln.remediation_steps}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
