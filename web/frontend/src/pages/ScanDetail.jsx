import { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft, Shield, Bug, Clock, Server, FileText, Terminal,
  AlertTriangle, Zap, Download, ExternalLink, ChevronDown, ChevronUp,
} from 'lucide-react';import { StatusBadge, SeverityBadge, Card, SeverityBar, Duration, Tabs,
  Skeleton, useToast, useTheme, ScanIdProvider, useScanId, formatDate, formatCost, formatNumber,
} from '../components/ui';
import { fetchScan, getExportUrl, getSseUrl } from '../lib/api';

function VulnRow({ vuln, expanded, onToggle, scanId }) {
  const sev = (vuln.severity || 'unknown').toLowerCase();
  const borderColors = {
    critical: 'border-l-red-500',
    high: 'border-l-orange-500',
    medium: 'border-l-yellow-500',
    low: 'border-l-blue-500',
  };

  return (
    <div className={`bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-hidden border-l-4 ${borderColors[sev] || 'border-l-gray-500'}`}>
      <button
        onClick={onToggle}
        className="w-full p-4 text-left hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h4 className="text-gray-900 dark:text-white font-medium truncate">
                {vuln.vulnerability_name || vuln.title || vuln.id}
              </h4>
              <SeverityBadge severity={vuln.severity} />
            </div>
            {vuln.description && (
              <p className="text-sm text-gray-500 dark:text-gray-400 line-clamp-1 mt-1">
                {vuln.description}
              </p>
            )}
            <div className="flex items-center gap-3 mt-2 text-xs text-gray-500 dark:text-gray-500">
              {vuln.cvss && <span className="font-mono">CVSS {vuln.cvss}</span>}
              {vuln.cwe && <span>{vuln.cwe}</span>}
              {vuln.endpoint && <span className="font-mono truncate max-w-[200px]">{vuln.endpoint}</span>}
              {vuln.method && <span className="bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded font-mono text-xs">{vuln.method}</span>}
            </div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <Link
              to={`/vulnerability/${scanId}/${vuln.id || vuln._file}`}
              onClick={e => e.stopPropagation()}
              className="p-1 text-gray-400 hover:text-green-400 transition-colors"
              title="View full details"
            >
              <ExternalLink className="w-4 h-4" />
            </Link>
            {expanded ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
          </div>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-gray-100 dark:border-gray-800 pt-4 space-y-4">
          {vuln.description && (
            <div>
              <h5 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">Description</h5>
              <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{vuln.description}</p>
            </div>
          )}
          {vuln.impact && (
            <div>
              <h5 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">Impact</h5>
              <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{vuln.impact}</p>
            </div>
          )}
          {vuln.technical_analysis && (
            <div>
              <h5 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">Technical Analysis</h5>
              <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap font-mono">{vuln.technical_analysis}</p>
            </div>
          )}
          {vuln.poc_description && (
            <div>
              <h5 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">Proof of Concept</h5>
              <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{vuln.poc_description}</p>
            </div>
          )}
          {vuln.remediation_steps && (
            <div>
              <h5 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">Remediation</h5>
              <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{vuln.remediation_steps}</p>
            </div>
          )}
          {vuln.code_locations && vuln.code_locations.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">Code Locations</h5>
              <div className="space-y-1">
                {vuln.code_locations.map((loc, i) => (
                  <code key={i} className="block text-xs font-mono text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 rounded px-2 py-1">{loc}</code>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function LiveLogViewer({ scanId, initialLog }) {
  const [log, setLog] = useState(initialLog || '');
  const [isLive, setIsLive] = useState(false);
  const logRef = useRef(null);
  const eventSourceRef = useRef(null);

  useEffect(() => {
    if (!isLive) {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      return;
    }

    const es = new EventSource(getSseUrl(scanId));
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setLog(prev => prev + `\n[Live Update] Status: ${data.status} | Vulns: ${data.vulnerability_count} | Tokens: ${data.total_tokens || 0}`);
      } catch { /* ignore parse errors */ }
    };

    es.onerror = () => {
      setIsLive(false);
      es.close();
    };

    return () => es.close();
  }, [isLive, scanId]);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [log]);

  return (
    <Card title="Scan Log" icon={Terminal} action={
      <button
        onClick={() => setIsLive(!isLive)}
        className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
          isLive
            ? 'bg-green-500/10 text-green-400 border border-green-500/20'
            : 'bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
        }`}
      >
        {isLive ? '● Live' : '○ Enable Live'}
      </button>
    }>
      <pre
        ref={logRef}
        className="text-xs font-mono overflow-x-auto max-h-[500px] overflow-y-auto whitespace-pre-wrap bg-gray-50 dark:bg-gray-950 rounded-lg p-4 border border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400"
      >
        {log || 'No log data available'}
      </pre>
    </Card>
  );
}

export default function ScanDetail() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [expandedVulns, setExpandedVulns] = useState(new Set());
  const [vulnFilter, setVulnFilter] = useState('all');
  const toast = useToast();

  useEffect(() => {
    async function fetchScanData() {
      try {
        const data = await fetchScan(scanId);
        setScan(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    fetchScanData();
  }, [scanId]);

  const toggleVuln = (id) => {
    setExpandedVulns(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const expandAll = () => {
    const vulns = filteredVulns();
    setExpandedVulns(new Set(vulns.map((v, i) => v.id || String(i))));
  };

  const collapseAll = () => setExpandedVulns(new Set());

  const filteredVulns = () => {
    if (!scan?.vulnerabilities) return [];
    if (vulnFilter === 'all') return scan.vulnerabilities;
    return scan.vulnerabilities.filter(v => (v.severity || 'unknown').toLowerCase() === vulnFilter);
  };

  if (loading) return <div className="space-y-6"><Skeleton className="h-8 w-96" /><Skeleton className="h-48" /><Skeleton className="h-12" /></div>;

  if (error) {
    return (
      <div className="text-center py-20">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <p className="text-red-400">{error}</p>
        <Link to="/" className="text-green-500 hover:text-green-400 mt-4 inline-block text-sm">← Back to dashboard</Link>
      </div>
    );
  }

  const vulns = scan.vulnerabilities || [];
  const usage = scan.llm_usage || {};
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', count: vulns.length },
    { id: 'log', label: 'Scan Log' },
    { id: 'usage', label: 'LLM Usage' },
  ];    return (
    <ScanIdProvider scanId={scanId}>
    <div className="space-y-6">
      {/* Back */}
      <Link to="/" className="inline-flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors">
        <ArrowLeft className="w-4 h-4" />
        Back to dashboard
      </Link>

      {/* Header */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{scan.run_name}</h1>
            <p className="text-gray-500 dark:text-gray-400 mt-1">
              {scan.targets?.map(t => t.value).filter(Boolean).join(' → ') || 'No targets'}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <StatusBadge status={scan.status} size="lg" />
            <div className="flex gap-1">
              <a
                href={getExportUrl(scanId, 'json')}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                title="Export JSON"
              >
                <Download className="w-3.5 h-3.5" />
              </a>
              <a
                href={getExportUrl(scanId, 'csv')}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                title="Export CSV"
              >
                <FileText className="w-3.5 h-3.5" />
              </a>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 mt-6">
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-500 uppercase tracking-wider">Started</p>
            <p className="text-sm text-gray-700 dark:text-gray-300 mt-1">{formatDate(scan.start_time)}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-500 uppercase tracking-wider">Duration</p>
            <p className="text-sm text-gray-700 dark:text-gray-300 mt-1"><Duration seconds={scan.duration_seconds} /></p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-500 uppercase tracking-wider">Mode</p>
            <p className="text-sm text-gray-700 dark:text-gray-300 mt-1 capitalize">{scan.scan_mode}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-500 uppercase tracking-wider">Vulnerabilities</p>
            <p className="text-sm font-bold text-red-500 mt-1">{vulns.length}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-500 uppercase tracking-wider">Cost</p>
            <p className="text-sm font-bold text-purple-500 mt-1">{formatCost(usage.cost)}</p>
          </div>
        </div>

        {/* Severity breakdown */}
        {vulns.length > 0 && (
          <div className="mt-6">
            <SeverityBar breakdown={scan.severity_breakdown} />
          </div>
        )}
      </div>

      {/* Tabs */}
      <Tabs tabs={tabs} active={activeTab} onChange={setActiveTab} />

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card title="Targets" icon={Server}>
            {scan.targets?.length > 0 ? (
              <div className="space-y-3">
                {scan.targets.map((t, i) => (
                  <div key={i} className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <span className="text-xs font-mono bg-gray-200 dark:bg-gray-700 px-2 py-1 rounded text-gray-600 dark:text-gray-300">{t.type}</span>
                    <span className="text-sm text-gray-700 dark:text-gray-300 truncate">{t.value}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 text-sm">No targets recorded</p>
            )}
          </Card>

          <Card title="LLM Usage" icon={Zap}>
            {usage.total_tokens ? (
              <div className="space-y-3">
                {[
                  ['Total Tokens', formatNumber(usage.total_tokens)],
                  ['Input Tokens', formatNumber(usage.input_tokens)],
                  ['Output Tokens', formatNumber(usage.output_tokens)],
                  ['Requests', formatNumber(usage.requests)],
                ].map(([label, value]) => (
                  <div key={label} className="flex justify-between text-sm">
                    <span className="text-gray-500 dark:text-gray-400">{label}</span>
                    <span className="text-gray-900 dark:text-white font-mono">{value}</span>
                  </div>
                ))}
                <div className="flex justify-between text-sm border-t border-gray-200 dark:border-gray-700 pt-3">
                  <span className="text-gray-500 dark:text-gray-400">Estimated Cost</span>
                  <span className="text-green-500 font-mono font-bold">{formatCost(usage.cost)}</span>
                </div>
              </div>
            ) : (
              <p className="text-gray-500 text-sm">No usage data recorded</p>
            )}
          </Card>

          {scan.instruction && (
            <Card title="Instructions" icon={FileText} className="lg:col-span-2">
              <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap font-mono bg-gray-50 dark:bg-gray-950 rounded-lg p-4 border border-gray-200 dark:border-gray-800">
                {scan.instruction}
              </p>
            </Card>
          )}
        </div>
      )}

      {/* Vulnerabilities Tab */}
      {activeTab === 'vulnerabilities' && (
        <div className="space-y-4">
          {vulns.length > 0 && (
            <div className="flex items-center justify-between gap-4">
              <div className="flex gap-2 flex-wrap">
                {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
                  <button
                    key={sev}
                    onClick={() => setVulnFilter(sev)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                      vulnFilter === sev
                        ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                        : 'bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
                    }`}
                  >
                    {sev === 'all' ? `All (${vulns.length})` : `${sev} (${scan.severity_breakdown?.[sev] || 0})`}
                  </button>
                ))}
              </div>
              <button
                onClick={() => {
                  const all = filteredVulns();
                  if (expandedVulns.size === all.length) setExpandedVulns(new Set());
                  else setExpandedVulns(new Set(all.map((v, i) => v.id || v._file || i)));
                }}
                className="text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
              >
                {expandedVulns.size === filteredVulns().length ? 'Collapse all' : 'Expand all'}
              </button>
            </div>
          )}

          {filteredVulns().length === 0 ? (
            <Card>
              <div className="text-center py-8">
                <Bug className="w-10 h-10 text-gray-300 dark:text-gray-700 mx-auto mb-3" />
                <p className="text-gray-500 text-lg">No vulnerabilities{vulnFilter !== 'all' ? ` with severity "${vulnFilter}"` : ''}</p>
              </div>
            </Card>
          ) : (
            <div className="space-y-3">
              {filteredVulns().map((vuln, i) => (
                <VulnRow
                  key={vuln.id || vuln._file || i}
                  vuln={vuln}
                  expanded={expandedVulns.has(vuln.id || vuln._file || i)}
                  onToggle={() => toggleVuln(vuln.id || vuln._file || i)}
                  scanId={scanId}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Log Tab */}
      {activeTab === 'log' && (
        <LiveLogViewer scanId={scanId} initialLog={scan.log} />
      )}

      {/* Usage Tab */}
      {activeTab === 'usage' && (
        <Card title="LLM Usage Details" icon={Zap}>
          {usage.request_usage_entries?.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-800">
                    <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">#</th>
                    <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Input</th>
                    <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Output</th>
                    <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Total</th>
                  </tr>
                </thead>
                <tbody>
                  {usage.request_usage_entries.map((entry, i) => (
                    <tr key={i} className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/30">
                      <td className="py-3 px-4 font-mono text-gray-500">{i + 1}</td>
                      <td className="py-3 px-4 font-mono text-gray-700 dark:text-gray-300">{formatNumber(entry.input_tokens)}</td>
                      <td className="py-3 px-4 font-mono text-gray-700 dark:text-gray-300">{formatNumber(entry.output_tokens)}</td>
                      <td className="py-3 px-4 font-mono font-medium text-gray-900 dark:text-white">{formatNumber((entry.input_tokens || 0) + (entry.output_tokens || 0))}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex justify-between text-sm"><span className="text-gray-500">Total Tokens</span><span className="font-mono text-gray-900 dark:text-white">{formatNumber(usage.total_tokens)}</span></div>
              <div className="flex justify-between text-sm"><span className="text-gray-500">Input Tokens</span><span className="font-mono text-gray-900 dark:text-white">{formatNumber(usage.input_tokens)}</span></div>
              <div className="flex justify-between text-sm"><span className="text-gray-500">Output Tokens</span><span className="font-mono text-gray-900 dark:text-white">{formatNumber(usage.output_tokens)}</span></div>
              <div className="flex justify-between text-sm border-t border-gray-200 dark:border-gray-700 pt-3"><span className="text-gray-500">Total Cost</span><span className="font-mono font-bold text-green-500">{formatCost(usage.cost)}</span></div>
            </div>
          )}
        </Card>
      )}
    </div>
    </ScanIdProvider>
  );
}
