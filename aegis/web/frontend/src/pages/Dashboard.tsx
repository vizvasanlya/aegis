import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  TrendingUp,
  Scan,
  Plus,
  ArrowRight
} from 'lucide-react'
import { api } from '../lib/api'

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null)
  const [recentScans, setRecentScans] = useState<any[]>([])
  const [recentVulns, setRecentVulns] = useState<any[]>([])

  useEffect(() => {
    api.getStats().then(setStats)
    api.listScans().then(scans => setRecentScans(scans.slice(0, 5)))
    api.listVulnerabilities().then(vulns => setRecentVulns(vulns.slice(0, 5)))
  }, [])

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Dashboard</h1>
          <p className="mt-1 text-gray-400">Security assessment overview</p>
        </div>
        <Link
          to="/new-scan"
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 font-medium text-white hover:bg-cyan-700 transition-colors"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Scans"
          value={stats?.total_scans || 0}
          icon={Scan}
          color="cyan"
          trend="+2 this week"
        />
        <StatCard
          title="Critical Findings"
          value={stats?.severity_breakdown?.critical || 0}
          icon={XCircle}
          color="red"
          trend="Needs attention"
        />
        <StatCard
          title="High Findings"
          value={stats?.severity_breakdown?.high || 0}
          icon={AlertTriangle}
          color="orange"
          trend="Review recommended"
        />
        <StatCard
          title="Total Vulnerabilities"
          value={stats?.total_vulnerabilities || 0}
          icon={Shield}
          color="green"
          trend="Across all scans"
        />
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recent Scans */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/50">
          <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
            <h2 className="text-lg font-semibold text-white">Recent Scans</h2>
            <Link to="/scans" className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
              View all <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          <div className="divide-y divide-gray-800">
            {recentScans.map((scan) => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                className="flex items-center justify-between px-6 py-4 hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-800">
                    <Scan className="h-5 w-5 text-gray-400" />
                  </div>
                  <div>
                    <p className="font-medium text-white">{scan.target}</p>
                    <p className="text-xs text-gray-500">{scan.id}</p>
                  </div>
                </div>
                <StatusBadge status={scan.status} />
              </Link>
            ))}
            {recentScans.length === 0 && (
              <div className="px-6 py-12 text-center text-gray-500">
                No scans yet
              </div>
            )}
          </div>
        </div>

        {/* Recent Vulnerabilities */}
        <div className="rounded-xl border border-gray-800 bg-gray-900/50">
          <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
            <h2 className="text-lg font-semibold text-white">Recent Findings</h2>
            <Link to="/vulnerabilities" className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
              View all <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          <div className="divide-y divide-gray-800">
            {recentVulns.map((vuln, idx) => (
              <div key={idx} className="px-6 py-4">
                <div className="flex items-center gap-3">
                  <SeverityDot severity={vuln.severity} />
                  <div className="flex-1">
                    <p className="font-medium text-white">{vuln.title}</p>
                    <p className="text-xs text-gray-500">{vuln.scan_id}</p>
                  </div>
                  <span className="text-xs text-gray-400">CVSS {vuln.cvss}</span>
                </div>
              </div>
            ))}
            {recentVulns.length === 0 && (
              <div className="px-6 py-12 text-center text-gray-500">
                No vulnerabilities found
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, color, trend }: any) {
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
      <p className="mt-1 text-xs text-gray-500">{trend}</p>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: 'bg-green-500/10 text-green-400',
    running: 'bg-blue-500/10 text-blue-400',
    failed: 'bg-red-500/10 text-red-400',
    pending: 'bg-yellow-500/10 text-yellow-400',
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

  return (
    <div className={`h-2.5 w-2.5 rounded-full ${colors[severity] || 'bg-gray-500'}`} />
  )
}
