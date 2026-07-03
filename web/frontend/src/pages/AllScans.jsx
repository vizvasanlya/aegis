import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Bug, Clock, Zap, ExternalLink, AlertTriangle, FileText } from 'lucide-react';
import {
  StatusBadge, SeverityBadge, StatCard, EmptyState, SearchInput, Select,
  SeverityBar, Duration, Skeleton, useToast, formatDate, formatCost, formatNumber,
} from '../components/ui';
import { fetchScans } from '../lib/api';

const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest First' },
  { value: 'oldest', label: 'Oldest First' },
  { value: 'vulns', label: 'Most Vulnerabilities' },
];

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'completed', label: 'Completed' },
  { value: 'running', label: 'Running' },
  { value: 'failed', label: 'Failed' },
  { value: 'stopped', label: 'Stopped' },
  { value: 'interrupted', label: 'Interrupted' },
];

export default function AllScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sortBy, setSortBy] = useState('newest');
  const toast = useToast();

  const loadData = useCallback(async () => {
    try {
      const data = await fetchScans({ search, status: statusFilter, sort: sortBy });
      setScans(data);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [search, statusFilter, sortBy]);

  useEffect(() => { loadData(); }, [loadData]);

  // Auto-refresh for running scans
  useEffect(() => {
    const hasRunning = scans.some(s => s.status === 'running');
    if (!hasRunning) return;
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [scans, loadData]);

  if (loading) return <div className="space-y-4"><Skeleton className="h-8 w-64" /><Skeleton className="h-12" count={5} /></div>;

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-xl p-8 text-center">
        <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-red-600 dark:text-red-400 font-medium">Failed to load scans</p>
        <p className="text-gray-500 text-sm mt-1">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">All Scans</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">Browse and search all penetration test scans</p>
        </div>
        <button
          onClick={() => { setLoading(true); loadData(); }}
          className="px-4 py-2 text-sm font-medium bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors text-gray-700 dark:text-gray-300"
        >
          ↻ Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="flex-1">
          <SearchInput value={search} onChange={setSearch} placeholder="Search by name, target, status..." />
        </div>
        <Select value={statusFilter} onChange={setStatusFilter} options={STATUS_OPTIONS.filter(o => o.value)} placeholder="All Statuses" />
        <Select value={sortBy} onChange={setSortBy} options={SORT_OPTIONS} />
      </div>

      {/* Table */}
      {scans.length === 0 ? (
        <EmptyState
          icon={Shield}
          title="No scans found"
          description={search || statusFilter ? 'Try adjusting your filters' : 'No scans have been run yet'}
          action={(search || statusFilter) ? <button onClick={() => { setSearch(''); setStatusFilter(''); }} className="text-green-500 hover:text-green-400 text-sm">Clear filters</button> : null}
        />
      ) : (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Scan</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Vulns</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider hidden sm:table-cell">Duration</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider hidden md:table-cell">Cost</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider hidden lg:table-cell">Started</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Mode</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id} className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/30 transition-colors">
                    <td className="py-3 px-4">
                      <Link to={`/scan/${scan.id}`} className="group">
                        <div className="font-medium text-gray-900 dark:text-white group-hover:text-green-500 transition-colors truncate max-w-[300px]">
                          {scan.run_name}
                        </div>
                        <div className="text-xs text-gray-500 dark:text-gray-500 truncate max-w-[300px]">
                          {scan.targets?.map(t => t.value).filter(Boolean).join(', ') || '—'}
                        </div>
                      </Link>
                    </td>
                    <td className="py-3 px-4"><StatusBadge status={scan.status} /></td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-gray-900 dark:text-white">{scan.vulnerability_count}</span>
                        {scan.vulnerability_count > 0 && <SeverityBadge severity={Object.entries(scan.severity_breakdown || {}).filter(([,v]) => v > 0).sort((a,b) => b[1]-a[1])[0]?.[0]} />}
                      </div>
                    </td>
                    <td className="py-3 px-4 hidden sm:table-cell">
                      <span className="text-gray-600 dark:text-gray-400"><Duration seconds={scan.duration_seconds} /></span>
                    </td>
                    <td className="py-3 px-4 hidden md:table-cell">
                      <span className="font-mono text-gray-600 dark:text-gray-400">{formatCost(scan.llm_usage?.cost)}</span>
                    </td>
                    <td className="py-3 px-4 hidden lg:table-cell">
                      <span className="text-gray-500 dark:text-gray-500 text-xs">{formatDate(scan.start_time)}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded text-xs text-gray-500 dark:text-gray-400 font-medium">{scan.scan_mode}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-800 text-xs text-gray-500 dark:text-gray-500">
            Showing {scans.length} scan{scans.length !== 1 ? 's' : ''}
          </div>
        </div>
      )}
    </div>
  );
}
