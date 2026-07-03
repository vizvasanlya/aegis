import { useState, useEffect } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Bug, AlertTriangle, Shield, ExternalLink, ArrowLeft } from 'lucide-react';
import {
  SeverityBadge, Card, EmptyState, SearchInput, Select, Skeleton,
  useToast, SeverityBar, formatDate,
} from '../components/ui';
import { fetchScans, fetchVulnerabilities } from '../lib/api';

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

function VulnRow({ vuln, scanId, scanName }) {
  const sev = (vuln.severity || 'unknown').toLowerCase();
  const borderColors = {
    critical: 'border-l-red-500',
    high: 'border-l-orange-500',
    medium: 'border-l-yellow-500',
    low: 'border-l-blue-500',
  };

  return (
    <Link
      to={`/vulnerability/${scanId}/${vuln.id || vuln._file}`}
      className={`block bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 hover:border-green-500/30 hover:shadow-lg transition-all border-l-4 ${borderColors[sev] || 'border-l-gray-500'}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <h4 className="text-gray-900 dark:text-white font-medium truncate">
              {vuln.title || vuln.vulnerability_name || vuln.id}
            </h4>
            <SeverityBadge severity={vuln.severity} />
          </div>
          {vuln.description && (
            <p className="text-sm text-gray-500 dark:text-gray-400 line-clamp-1 mt-1">{vuln.description}</p>
          )}
          <div className="flex items-center gap-3 mt-2 text-xs text-gray-500 dark:text-gray-500 flex-wrap">
            <span className="bg-green-500/10 text-green-500 px-2 py-0.5 rounded">{scanName}</span>
            {vuln.cvss && <span className="font-mono">CVSS {vuln.cvss}</span>}
            {vuln.cwe && <span>{vuln.cwe}</span>}
            {vuln.endpoint && <span className="font-mono truncate max-w-[200px]">{vuln.endpoint}</span>}
            {vuln.timestamp && <span>{formatDate(vuln.timestamp)}</span>}
          </div>
        </div>
        <ExternalLink className="w-4 h-4 text-gray-300 dark:text-gray-600 flex-shrink-0 mt-1" />
      </div>
    </Link>
  );
}

export default function AllVulnerabilities() {
  const [allVulns, setAllVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const toast = useToast();

  useEffect(() => {
    async function load() {
      try {
        const scans = await fetchScans();
        const vulnResults = await Promise.all(
          scans.filter(s => s.vulnerability_count > 0).map(async (scan) => {
            const vulns = await fetchVulnerabilities(scan.id);
            return vulns.map(v => ({ ...v, _scanId: scan.id, _scanName: scan.run_name }));
          })
        );
        setAllVulns(vulnResults.flat());
        setError(null);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  // Aggregate severity counts
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  allVulns.forEach(v => {
    const sev = (v.severity || 'unknown').toLowerCase();
    if (sev in severityCounts) severityCounts[sev]++;
  });

  // Filter
  const filtered = allVulns.filter(v => {
    if (severityFilter && (v.severity || 'unknown').toLowerCase() !== severityFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        (v.title || v.vulnerability_name || '').toLowerCase().includes(q) ||
        (v.description || '').toLowerCase().includes(q) ||
        (v.cwe || '').toLowerCase().includes(q) ||
        (v.endpoint || '').toLowerCase().includes(q) ||
        (v._scanName || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  if (loading) return <div className="space-y-4"><Skeleton className="h-8 w-64" /><Skeleton className="h-24" /><Skeleton className="h-12" count={5} /></div>;

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-xl p-8 text-center">
        <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-red-600 dark:text-red-400 font-medium">Failed to load vulnerabilities</p>
        <p className="text-gray-500 text-sm mt-1">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Vulnerabilities</h1>
        <p className="text-gray-500 dark:text-gray-400 mt-1">
          {allVulns.length} vulnerabilities across all scans
        </p>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Critical', count: severityCounts.critical, color: 'text-red-500', bg: 'bg-red-500/5 border-red-500/20' },
          { label: 'High', count: severityCounts.high, color: 'text-orange-500', bg: 'bg-orange-500/5 border-orange-500/20' },
          { label: 'Medium', count: severityCounts.medium, color: 'text-yellow-500', bg: 'bg-yellow-500/5 border-yellow-500/20' },
          { label: 'Low', count: severityCounts.low, color: 'text-blue-500', bg: 'bg-blue-500/5 border-blue-500/20' },
        ].map(s => (
          <button
            key={s.label}
            onClick={() => setSeverityFilter(severityFilter === s.label.toLowerCase() ? '' : s.label.toLowerCase())}
            className={`p-4 rounded-xl border text-left transition-all ${
              severityFilter === s.label.toLowerCase()
                ? `${s.bg} border-2`
                : 'bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-800 hover:border-gray-300 dark:hover:border-gray-700'
            }`}
          >
            <p className={`text-2xl font-bold ${s.color}`}>{s.count}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wider mt-1">{s.label}</p>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="flex-1">
          <SearchInput value={search} onChange={setSearch} placeholder="Search by title, CWE, endpoint, scan name..." />
        </div>
        {severityFilter && (
          <button
            onClick={() => setSeverityFilter('')}
            className="px-3 py-2 text-xs font-medium text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
          >
            Clear severity filter
          </button>
        )}
      </div>

      {/* Vuln list */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={Bug}
          title="No vulnerabilities found"
          description={search || severityFilter ? 'Try adjusting your filters' : 'No vulnerabilities have been discovered yet'}
          action={(search || severityFilter) ? <button onClick={() => { setSearch(''); setSeverityFilter(''); }} className="text-green-500 hover:text-green-400 text-sm">Clear filters</button> : null}
        />
      ) : (
        <div className="space-y-3">
          {filtered.map((vuln, i) => (
            <VulnRow key={`${vuln._scanId}-${vuln.id || vuln._file || i}`} vuln={vuln} scanId={vuln._scanId} scanName={vuln._scanName} />
          ))}
        </div>
      )}

      <div className="text-xs text-gray-500 dark:text-gray-500 text-center">
        Showing {filtered.length} of {allVulns.length} vulnerabilities
      </div>
    </div>
  );
}
