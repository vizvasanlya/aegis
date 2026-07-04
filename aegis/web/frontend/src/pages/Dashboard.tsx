import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  TrendingUp,
  Scan,
  Plus
} from 'lucide-react'
import { api } from '../lib/api'

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null)
  const [recentScans, setRecentScans] = useState<any[]>([])

  useEffect(() => {
    api.getStats().then(setStats)
    api.listScans().then(scans => setRecentScans(scans.slice(0, 5)))
  }, [])

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="mt-1 text-gray-400">Security assessment overview</p>
        </div>
        <Link
          to="/new-scan"
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 font-medium text-white hover:bg-cyan-700"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Scans"
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
          title="Medium"
          value={stats?.severity_breakdown?.medium || 0}
          icon={Shield}
          color="yellow"
        />
      </div>

      {/* Recent Scans */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/50">
        <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
          <h2 className="text-lg font-semibold">Recent Scans</h2>
          <Link to="/scans" className="text-sm text-cyan-400 hover:text-cyan-300">
            View all →
          </Link>
        </div>
        <div className="divide-y divide-gray-800">
          {recentScans.map((scan) => (
            <Link
              key={scan.id}
              to={`/scans/${scan.id}`}
              className="flex items-center justify-between px-6 py-4 hover:bg-gray-800/50"
            >
              <div className="flex items-center gap-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-800">
                  <Scan className="h-5 w-5 text-gray-400" />
                </div>
                <div>
                  <p className="font-medium">{scan.target}</p>
                  <p className="text-sm text-gray-400">{scan.id}</p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <span className={`rounded-full px-2 py-1 text-xs font-medium ${
                  scan.status === 'completed' ? 'bg-green-900/50 text-green-400' :
                  scan.status === 'running' ? 'bg-blue-900/50 text-blue-400' :
                  'bg-gray-800 text-gray-400'
                }`}>
                  {scan.status}
                </span>
              </div>
            </Link>
          ))}
          {recentScans.length === 0 && (
            <div className="px-6 py-12 text-center text-gray-500">
              No scans yet. Start your first scan!
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, color }: any) {
  const colorClasses = {
    cyan: 'bg-cyan-900/50 text-cyan-400',
    red: 'bg-red-900/50 text-red-400',
    orange: 'bg-orange-900/50 text-orange-400',
    yellow: 'bg-yellow-900/50 text-yellow-400',
  }

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">{title}</p>
        <div className={`rounded-lg p-2 ${colorClasses[color]}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <p className="mt-4 text-3xl font-bold">{value}</p>
    </div>
  )
}
