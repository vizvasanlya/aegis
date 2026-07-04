import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { 
  Shield, 
  AlertTriangle, 
  XCircle,
  Scan,
  ArrowRight,
  Loader2
} from 'lucide-react'
import { api } from '../lib/api'

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null)
  const [recentScans, setRecentScans] = useState<any[]>([])
  const [recentVulns, setRecentVulns] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      api.getStats(),
      api.listScans(),
      api.listVulnerabilities(),
    ]).then(([statsData, scansData, vulnsData]) => {
      setStats(statsData)
      setRecentScans(scansData.slice(0, 5))
      setRecentVulns(vulnsData.slice(0, 5))
      setLoading(false)
    })
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
      </div>
    )
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Dashboard</h1>
        <p className="mt-1 text-gray-400">Security assessment overview</p>
      </div>

      {/* Stats Cards */}
      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Pentests"
          value={stats?.total_scans || 0}
          icon={Scan}
          color="cyan"
        />
        <StatCard
          title="Critical"
          value={stats?.severity_breakdown?.critical || 0}
          icon={XCircle}
          color="red"
        />
        <StatCard
          title="High"
          value={stats?.severity_breakdown?.high || 0}
          icon={AlertTriangle}
          color="orange"
        />
        <StatCard
          title="Total Findings"
          value={stats?.total_vulnerabilities || 0}
          icon={Shield}
          color="green"
        />
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recent Pentests */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/50">
          <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
            <h2 className="text-lg font-semibold text-white">Recent Pentests</h2>
            <Link to="/pentests" className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
              View all <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          <div className="divide-y divide-gray-800">
            {recentScans.map((scan: any) => (
              <Link
                key={scan.id}
                to={`/pentest/${scan.id}`}
                className="flex items-center justify-between px-6 py-4 hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-800 flex-shrink-0">
                    <Scan className="h-5 w-5 text-gray-400" />
                  </div>
                  <div className="min-w-0">
                    <p className="font-medium text-white truncate">{scan.target}</p>
                    <p className="text-xs text-gray-500">{scan.id}</p>
                  </div>
                </div>
                <StatusBadge status={scan.status} />
              </Link>
            ))}
            {recentScans.length === 0 && (
              <div className="px-6 py-12 text-center text-gray-500">
                No pentests yet
              </div>
            )}
          </div>
        </div>

        {/* Recent Findings */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/50">
          <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
            <h2 className="text-lg font-semibold text-white">Recent Findings</h2>
            <Link to="/vulnerabilities" className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
              View all <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          <div className="divide-y divide-gray-800">
            {recentVulns.map((vuln: any, idx: number) => (
              <div key={idx} className="px-6 py-4">
                <div className="flex items-center gap-3">
                  <SeverityDot severity={vuln.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-white truncate">{vuln.title}</p>
                    <p className="text-xs text-gray-500 truncate">{vuln.scan_id}</p>
                  </div>
                  {vuln.cvss && (
                    <span className="text-xs text-gray-400 flex-shrink-0">CVSS {vuln.cvss}</span>
                  )}
                </div>
              </div>
            ))}
            {recentVulns.length === 0 && (
              <div className="px-6 py-12 text-center text-gray-500">
                No findings yet
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, color }: any) {
  const colorClasses: Record<string, string> = {
    cyan: 'bg-cyan-500/10 text-cyan-400',
    red: 'bg-red-500/10 text-red-400',
    orange: 'bg-orange-500/10 text-orange-400',
    green: 'bg-green-500/10 text-green-400',
  }

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-5">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-gray-400">{title}</p>
        <div className={`rounded-lg p-2 ${colorClasses[color]}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <p className="mt-3 text-3xl font-bold text-white">{value}</p>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: 'bg-green-900/50 text-green-400',
    running: 'bg-blue-900/50 text-blue-400',
    failed: 'bg-red-900/50 text-red-400',
  }

  return (
    <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${styles[status] || 'bg-gray-800 text-gray-400'}`}>
      {status}
    </span>
  )
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
  }
  return <div className={`h-2.5 w-2.5 rounded-full ${colors[severity] || 'bg-gray-500'}`} />
}
