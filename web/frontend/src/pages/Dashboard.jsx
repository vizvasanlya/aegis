import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Bug, CheckCircle, Clock, Zap, ExternalLink, AlertTriangle, ArrowUpDown,
} from 'lucide-react';
import {
  StatusBadge, SeverityBadge, StatCard, Card, EmptyState, SearchInput, Select,
  SeverityBar, Duration, Skeleton, useToast, formatDate, formatCost, formatNumber,
} from '../components/ui';
import { fetchScans, fetchStats } from '../lib/api';

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'completed', label: 'Completed' },
  { value: 'running', label: 'Running' },
  { value: 'failed', label: 'Failed' },
  { value: 'stopped', label: 'Stopped' },
  { value: 'interrupted', label: 'Interrupted' },
];

const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest First' },
  { value: 'oldest', label: 'Oldest First' },
  { value: 'vulns', label: 'Most Vulnerabilities' },
];

function ScanRow({ scan }) {
  return (
    <Link
      to={`/scan/${scan.id}`}
      className="block bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-5 hover:border-green-500/30 hover:shadow-lg hover:shadow-green-500/5 transition-all group"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2">
            <h3 className="text-gray-900 dark:text-white font-medium group-hover:text-green-400 transition-colors truncate">
              {scan.run_name}
            </h3>
            <StatusBadge status={scan.status} />
          </div>

          <p className="text-sm text-gray-500 dark:text-gray-500 truncate mb-3">
            {scan.targets?.map(t => t.value).filter(Boolean).join(' → ') || 'No targets'}
          </p>

          {/* Severity bar */}
          {scan.vulnerability_count > 0 && (
            <div className="mb-3">
              <SeverityBar breakdown={scan.severity_breakdown} />
            </div>
          )}

          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500 dark:text-gray-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {formatDate(scan.start_time)}
            </span>
            {scan.duration_seconds != null && (
              <span className="flex items-center gap-1">
                <Zap className="w-3 h-3" />
                <Duration seconds={scan.duration_seconds} />
              </span>
            )}
            <span className="flex items-center gap-1">
              <Bug className="w-3 h-3" />
              {scan.vulnerability_count} vuln{scan.vulnerability_count !== 1 ? 's' : ''}
            </span>
            {scan.llm_usage?.total_tokens > 0 && (
              <span className="flex items-center gap-1 font-mono">
                {formatNumber(scan.llm_usage.total_tokens)} tokens · {formatCost(scan.llm_usage.cost)}
              </span>
            )}
            <span className="bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded text-gray-500 dark:text-gray-400 font-medium">
              {scan.scan_mode}
            </span>
          </div>
        </div>

        <ExternalLink className="w-4 h-4 text-gray-300 dark:text-gray-600 group-hover:text-green-400 transition-colors flex-shrink-0 mt-1" />
      </div>
    </Link>
  );
}

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sortBy, setSortBy] = useState('newest');
  const toast = useToast();

  const loadData = useCallback(async () => {
    try {
      const [scansData, statsData] = await Promise.all([
        fetchScans({ search, status: statusFilter, sort: sortBy }),
        fetchStats(),
      ]);
      setScans(scansData);
      setStats(statsData);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [search, statusFilter, sortBy]);

  useEffect(() => { loadData(); }, [loadData]);

  // Auto-refresh every 30s for running scans
  useEffect(() => {
    const hasRunning = scans.some(s => s.status === 'running');
    if (!hasRunning) return;
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [scans, loadData]);

  if (loading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-20" count={3} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-xl p-8 text-center">
        <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-red-600 dark:text-red-400 font-medium">Failed to load data</p>
        <p className="text-gray-500 text-sm mt-1">{error}</p>
        <p className="text-gray-400 text-xs mt-3">
          Make sure the backend is running: <code className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded text-green-600 dark:text-green-400">uv run python web/backend/main.py</code>
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Scan Dashboard</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">Overview of all penetration test scans</p>
        </div>
        <button
          onClick={() => { setLoading(true); loadData(); toast('Refreshing...', 'info', 2000); }}
          className="px-4 py-2 text-sm font-medium bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors text-gray-700 dark:text-gray-300"
        >
          ↻ Refresh
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Total Scans"
            value={stats.total_scans}
            icon={Shield}
            color="text-green-500"
          />
          <StatCard
            label="Vulnerabilities"
            value={stats.total_vulnerabilities}
            icon={Bug}
            color="text-red-500"
            subtitle={`${stats.severity_breakdown?.critical || 0} critical`}
          />
          <StatCard
            label="Total Cost"
            value={formatCost(stats.total_cost)}
            icon={Zap}
            color="text-purple-500"
            subtitle={`${formatNumber(stats.total_tokens)} tokens`}
          />
          <StatCard
            label="Avg Duration"
            value={<Duration seconds={stats.average_duration_seconds} />}
            icon={Clock}
            color="text-blue-500"
          />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="flex-1">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Search scans by name, target, or status..."
          />
        </div>
        <Select
          value={statusFilter}
          onChange={setStatusFilter}
          options={STATUS_OPTIONS.filter(o => o.value)}
          placeholder="All Statuses"
        />
        <Select
          value={sortBy}
          onChange={setSortBy}
          options={SORT_OPTIONS}
        />
      </div>

      {/* Scan list */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Recent Scans
            <span className="ml-2 text-sm font-normal text-gray-500">({scans.length})</span>
          </h2>
        </div>

        {scans.length === 0 ? (
          <EmptyState
            icon={Shield}
            title="No scans found"
            description={search || statusFilter ? 'Try adjusting your filters' : 'Run a scan with strix --target https://example.com'}
            action={
              (search || statusFilter) ? (
                <button onClick={() => { setSearch(''); setStatusFilter(''); }} className="text-green-500 hover:text-green-400 text-sm">
                  Clear filters
                </button>
              ) : null
            }
          />
        ) : (
          <div className="space-y-3">
            {scans.map(scan => (
              <ScanRow key={scan.id} scan={scan} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
