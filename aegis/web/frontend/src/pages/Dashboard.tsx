import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  XCircle,
  Scan,
  ArrowRight,
  Loader2,
  Globe,
  Code,
  GitBranch,
  Smartphone,
  Play,
  Clock,
  CheckCircle,
  TrendingUp,
  Activity,
  Zap,
  Plus,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'
import { api } from '../lib/api'

// ─── Color Constants ────────────────────────────────────────────────────────

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
}

const TYPE_COLORS = {
  webapp: '#06b6d4',
  api: '#a855f7',
  git: '#22c55e',
  mobile: '#f97316',
  other: '#6b7280',
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getStats().then(data => {
      setStats(data)
      setLoading(false)
    }).catch(() => setLoading(false))
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
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Dashboard</h1>
          <p className="mt-1 text-gray-400">Security assessment overview</p>
        </div>
        <Link
          to="/new-scan"
          className="flex items-center gap-2 rounded-xl bg-cyan-600 px-5 py-2.5 font-medium text-white hover:bg-cyan-700 transition-colors"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </Link>
      </div>

      {/* Quick Start */}
      <QuickStart onNavigate={navigate} />

      {/* Stats Row */}
      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          title="Total Scans"
          value={stats?.total_scans || 0}
          icon={Scan}
          color="cyan"
          trend={null}
        />
        <StatCard
          title="Critical Findings"
          value={stats?.severity_breakdown?.critical || 0}
          icon={XCircle}
          color="red"
          trend={null}
        />
        <StatCard
          title="High Findings"
          value={stats?.severity_breakdown?.high || 0}
          icon={AlertTriangle}
          color="orange"
          trend={null}
        />
        <StatCard
          title="Total Findings"
          value={stats?.total_vulnerabilities || 0}
          icon={Shield}
          color="green"
          trend={null}
        />
      </div>

      {/* Charts Row */}
      <div className="mb-8 grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Trend Chart */}
        <div className="lg:col-span-2 rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Scan Activity</h2>
            <span className="text-xs text-gray-500">Last 30 days</span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.trend || []}>
                <defs>
                  <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="vulnGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis
                  dataKey="date"
                  stroke="#6b7280"
                  fontSize={10}
                  tickFormatter={(v) => v.slice(5)}
                />
                <YAxis stroke="#6b7280" fontSize={10} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111827',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="scans"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fill="url(#scanGradient)"
                  name="Scans"
                />
                <Area
                  type="monotone"
                  dataKey="vulns"
                  stroke="#f97316"
                  strokeWidth={2}
                  fill="url(#vulnGradient)"
                  name="Vulnerabilities"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Type Breakdown Pie */}
        <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Scan Types</h2>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={buildTypeData(stats?.type_breakdown)}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {buildTypeData(stats?.type_breakdown).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111827',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 space-y-2">
            {buildTypeData(stats?.type_breakdown).map((item) => (
              <div key={item.name} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="h-3 w-3 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-sm text-gray-400">{item.name}</span>
                </div>
                <span className="text-sm font-medium text-white">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Active Scans */}
        <ActiveScans scans={stats?.active_scans || []} />

        {/* Recent Scans */}
        <RecentScans scans={stats?.recent_scans || []} />
      </div>

      {/* Severity Breakdown */}
      <div className="mt-8 rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Findings by Severity</h2>
        <SeverityBar breakdown={stats?.severity_breakdown} total={stats?.total_vulnerabilities || 0} />
      </div>
    </div>
  )
}

// ─── Quick Start ────────────────────────────────────────────────────────────

function QuickStart({ onNavigate }: { onNavigate: (path: string) => void }) {
  const items = [
    {
      label: 'Web App',
      desc: 'Scan a website',
      icon: Globe,
      color: 'cyan',
      path: '/new-scan',
    },
    {
      label: 'API Test',
      desc: 'Test an endpoint',
      icon: Code,
      color: 'purple',
      path: '/api-testing',
    },
    {
      label: 'Git Repo',
      desc: 'Analyze source code',
      icon: GitBranch,
      color: 'green',
      path: '/new-scan',
    },
    {
      label: 'Mobile App',
      desc: 'Scan APK/IPA',
      icon: Smartphone,
      color: 'orange',
      path: '/mobile-testing',
    },
  ]

  const colorMap: Record<string, string> = {
    cyan: 'bg-cyan-900/30 text-cyan-400 hover:bg-cyan-900/50',
    purple: 'bg-purple-900/30 text-purple-400 hover:bg-purple-900/50',
    green: 'bg-green-900/30 text-green-400 hover:bg-green-900/50',
    orange: 'bg-orange-900/30 text-orange-400 hover:bg-orange-900/50',
  }

  return (
    <div className="mb-8">
      <h2 className="text-sm font-semibold text-gray-400 mb-3">Quick Start</h2>
      <div className="grid grid-cols-4 gap-3">
        {items.map((item) => {
          const Icon = item.icon
          return (
            <button
              key={item.label}
              onClick={() => onNavigate(item.path)}
              className={`flex items-center gap-3 rounded-xl border border-gray-800 p-4 text-left transition-all hover:scale-[1.02] ${colorMap[item.color]}`}
            >
              <Icon className="h-5 w-5" />
              <div>
                <p className="text-sm font-medium text-white">{item.label}</p>
                <p className="text-xs text-gray-500">{item.desc}</p>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

// ─── Active Scans ───────────────────────────────────────────────────────────

function ActiveScans({ scans }: { scans: any[] }) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/50">
      <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-blue-400" />
          <h2 className="text-lg font-semibold text-white">Active Scans</h2>
        </div>
        {scans.length > 0 && (
          <span className="rounded-full bg-blue-900/50 px-2.5 py-0.5 text-xs font-medium text-blue-400">
            {scans.length} running
          </span>
        )}
      </div>
      <div className="divide-y divide-gray-800">
        {scans.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <Scan className="mx-auto h-10 w-10 text-gray-700" />
            <p className="mt-3 text-sm text-gray-500">No active scans</p>
          </div>
        ) : (
          scans.map((scan) => (
            <Link
              key={scan.id}
              to={`/pentest/${scan.id}`}
              className="flex items-center justify-between px-6 py-4 hover:bg-gray-800/50 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
                <div>
                  <p className="text-sm font-medium text-white truncate max-w-[250px]">{scan.target}</p>
                  <p className="text-xs text-gray-500">{scan.id}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-400 capitalize">{scan.scan_mode}</span>
                <span className="rounded-full bg-blue-900/50 px-2 py-0.5 text-xs text-blue-400">
                  {scan.type}
                </span>
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  )
}

// ─── Recent Scans ───────────────────────────────────────────────────────────

function RecentScans({ scans }: { scans: any[] }) {
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-400" />
      case 'running': return <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
      case 'failed': return <XCircle className="h-4 w-4 text-red-400" />
      default: return <Clock className="h-4 w-4 text-gray-400" />
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'webapp': return <Globe className="h-3.5 w-3.5" />
      case 'api': return <Code className="h-3.5 w-3.5" />
      case 'git': return <GitBranch className="h-3.5 w-3.5" />
      case 'mobile': return <Smartphone className="h-3.5 w-3.5" />
      default: return <Scan className="h-3.5 w-3.5" />
    }
  }

  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/50">
      <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
        <h2 className="text-lg font-semibold text-white">Recent Scans</h2>
        <Link to="/pentests" className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
          View all <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
      <div className="divide-y divide-gray-800">
        {scans.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <Scan className="mx-auto h-10 w-10 text-gray-700" />
            <p className="mt-3 text-sm text-gray-500">No scans yet</p>
            <Link to="/new-scan" className="mt-2 inline-block text-sm text-cyan-400 hover:text-cyan-300">
              Start your first scan
            </Link>
          </div>
        ) : (
          scans.map((scan) => (
            <Link
              key={scan.id}
              to={`/pentest/${scan.id}`}
              className="flex items-center justify-between px-6 py-4 hover:bg-gray-800/50 transition-colors"
            >
              <div className="flex items-center gap-3">
                {getStatusIcon(scan.status)}
                <div>
                  <p className="text-sm font-medium text-white truncate max-w-[250px]">{scan.target}</p>
                  <p className="text-xs text-gray-500">{scan.id}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1 text-gray-500">
                  {getTypeIcon(scan.type)}
                  <span className="text-xs capitalize">{scan.type}</span>
                </div>
                <span className="text-xs text-gray-500">
                  {scan.started_at ? new Date(scan.started_at).toLocaleDateString() : '-'}
                </span>
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  )
}

// ─── Severity Bar ───────────────────────────────────────────────────────────

function SeverityBar({
  breakdown,
  total,
}: {
  breakdown: Record<string, number>
  total: number
}) {
  const items = [
    { key: 'critical', label: 'Critical', color: SEVERITY_COLORS.critical },
    { key: 'high', label: 'High', color: SEVERITY_COLORS.high },
    { key: 'medium', label: 'Medium', color: SEVERITY_COLORS.medium },
    { key: 'low', label: 'Low', color: SEVERITY_COLORS.low },
  ]

  return (
    <div>
      {/* Bar */}
      <div className="mb-4 flex h-4 overflow-hidden rounded-full bg-gray-800">
        {items.map((item) => {
          const count = breakdown?.[item.key] || 0
          const pct = total > 0 ? (count / total) * 100 : 0
          return pct > 0 ? (
            <div
              key={item.key}
              style={{ width: `${pct}%`, backgroundColor: item.color }}
              className="transition-all duration-500"
              title={`${item.label}: ${count}`}
            />
          ) : null
        })}
      </div>

      {/* Legend */}
      <div className="flex items-center justify-between">
        {items.map((item) => {
          const count = breakdown?.[item.key] || 0
          return (
            <div key={item.key} className="flex items-center gap-2">
              <div className="h-3 w-3 rounded-full" style={{ backgroundColor: item.color }} />
              <span className="text-sm text-gray-400">{item.label}</span>
              <span className="text-sm font-medium text-white">{count}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Stat Card ──────────────────────────────────────────────────────────────

function StatCard({
  title,
  value,
  icon: Icon,
  color,
  trend,
}: {
  title: string
  value: number
  icon: any
  color: string
  trend: number | null
}) {
  const colorClasses: Record<string, string> = {
    cyan: 'bg-cyan-500/10 text-cyan-400',
    red: 'bg-red-500/10 text-red-400',
    orange: 'bg-orange-500/10 text-orange-400',
    green: 'bg-green-500/10 text-green-400',
  }

  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-5">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-gray-400">{title}</p>
        <div className={`rounded-xl p-2 ${colorClasses[color]}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <div className="mt-3 flex items-end gap-2">
        <p className="text-3xl font-bold text-white">{value}</p>
        {trend !== null && (
          <span className={`mb-1 text-xs font-medium ${trend >= 0 ? 'text-green-400' : 'text-red-400'}`}>
            {trend >= 0 ? '+' : ''}{trend}%
          </span>
        )}
      </div>
    </div>
  )
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function buildTypeData(breakdown: Record<string, number> | undefined) {
  if (!breakdown) return []
  return [
    { name: 'Web App', value: breakdown.webapp || 0, color: TYPE_COLORS.webapp },
    { name: 'API', value: breakdown.api || 0, color: TYPE_COLORS.api },
    { name: 'Git', value: breakdown.git || 0, color: TYPE_COLORS.git },
    { name: 'Mobile', value: breakdown.mobile || 0, color: TYPE_COLORS.mobile },
  ].filter((d) => d.value > 0)
}
