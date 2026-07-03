import { Shield, ExternalLink, Clock, Bug, Play, AlertTriangle, CheckCircle, XCircle, Search, Menu, X, ChevronDown, Moon, Sun, ArrowLeft } from 'lucide-react';
import React, { useState, useEffect, createContext, useContext } from 'react';

// ── Theme Context ────────────────────────────────────────────────────────────

const ThemeContext = createContext();

export function ThemeProvider({ children }) {
  const [dark, setDark] = useState(() => {
    const saved = localStorage.getItem('strix-theme');
    return saved ? saved === 'dark' : true;
  });

  useEffect(() => {
    localStorage.setItem('strix-theme', dark ? 'dark' : 'light');
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);

  return (
    <ThemeContext.Provider value={{ dark, toggle: () => setDark(d => !d) }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}

// ── Status Badge ─────────────────────────────────────────────────────────────

const STATUS_STYLES = {
  completed: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', icon: CheckCircle },
  running:   { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20', icon: Play },
  interrupted: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', icon: AlertTriangle },
  failed:    { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', icon: XCircle },
  stopped:   { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', icon: AlertTriangle },
  unknown:   { color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/20', icon: Shield },
};

export function StatusBadge({ status, size = 'sm' }) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.unknown;
  const Icon = style.icon;
  const sizeClasses = size === 'lg' ? 'px-3 py-1.5 text-sm' : 'px-2.5 py-1 text-xs';
  const iconSize = size === 'lg' ? 'w-4 h-4' : 'w-3 h-3';
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full font-medium border ${style.bg} ${style.color} ${style.border} ${sizeClasses}`}>
      <Icon className={iconSize} />
      {status}
    </span>
  );
}

// ── Severity Badge ───────────────────────────────────────────────────────────

const SEVERITY_STYLES = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', label: 'CRITICAL' },
  high:     { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', label: 'HIGH' },
  medium:   { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', label: 'MEDIUM' },
  low:      { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30', label: 'LOW' },
  unknown:  { color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/30', label: 'UNKNOWN' },
};

export function SeverityBadge({ severity, size = 'sm' }) {
  const sev = (severity || 'unknown').toLowerCase();
  const style = SEVERITY_STYLES[sev] || SEVERITY_STYLES.unknown;
  const sizeClasses = size === 'lg' ? 'px-3 py-1.5 text-sm' : 'px-2 py-0.5 text-xs';
  return (
    <span className={`inline-flex items-center rounded-md font-bold uppercase tracking-wider border ${style.bg} ${style.color} ${style.border} ${sizeClasses}`}>
      {style.label}
    </span>
  );
}

// ── Card ─────────────────────────────────────────────────────────────────────

export function Card({ title, icon: Icon, children, action, className = '' }) {
  return (
    <div className={`bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 overflow-hidden ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200 dark:border-gray-800">
          <div className="flex items-center gap-2">
            {Icon && <Icon className="w-4 h-4 text-gray-400" />}
            <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300">{title}</h3>
          </div>
          {action}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}

// ── Stat Card ────────────────────────────────────────────────────────────────

export function StatCard({ label, value, icon: Icon, color = 'text-white', subtitle }) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-5 hover:shadow-lg transition-shadow">
      <div className="flex items-center gap-3">
        <div className={`p-2.5 rounded-lg bg-gray-100 dark:bg-gray-800 ${color}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div>
          <p className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wider">{label}</p>
          <p className={`text-2xl font-bold ${color}`}>{value}</p>
          {subtitle && <p className="text-xs text-gray-500 dark:text-gray-500 mt-0.5">{subtitle}</p>}
        </div>
      </div>
    </div>
  );
}

// ── Loading Skeleton ─────────────────────────────────────────────────────────

export function Skeleton({ className = '', count = 1 }) {
  return (
    <div className="animate-pulse space-y-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className={`bg-gray-200 dark:bg-gray-800 rounded-lg ${className}`} />
      ))}
    </div>
  );
}

export function PageSkeleton() {
  return (
    <div className="space-y-6 p-6">
      <Skeleton className="h-8 w-64" />
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
      </div>
      <Skeleton className="h-12" count={4} />
    </div>
  );
}

// ── Error Boundary ───────────────────────────────────────────────────────────

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[400px] flex items-center justify-center p-8">
          <div className="text-center">
            <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Something went wrong</h2>
            <p className="text-gray-500 text-sm mb-4">{this.state.error?.message}</p>
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              Try again
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// ── Toast / Notification ─────────────────────────────────────────────────────

const ToastContext = createContext();

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = (message, type = 'info', duration = 4000) => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration);
  };

  const removeToast = (id) => setToasts(prev => prev.filter(t => t.id !== id));

  return (
    <ToastContext.Provider value={addToast}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 space-y-2">
        {toasts.map(toast => (
          <div
            key={toast.id}
            className={`flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg border backdrop-blur-sm text-sm font-medium animate-in slide-in-from-right ${
              toast.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
              toast.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-400' :
              'bg-blue-500/10 border-blue-500/20 text-blue-400'
            }`}
          >
            {toast.message}
            <button onClick={() => removeToast(toast.id)} className="ml-2 opacity-60 hover:opacity-100">×</button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

// ── Empty State ──────────────────────────────────────────────────────────────

export function EmptyState({ icon: Icon = Shield, title, description, action }) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-16 text-center">
      <Icon className="w-14 h-14 text-gray-300 dark:text-gray-700 mx-auto mb-4" />
      <p className="text-gray-600 dark:text-gray-400 text-lg font-medium">{title}</p>
      {description && <p className="text-gray-500 dark:text-gray-600 text-sm mt-2 max-w-md mx-auto">{description}</p>}
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}

// ── Search Input ─────────────────────────────────────────────────────────────

export function SearchInput({ value, onChange, placeholder = 'Search...' }) {
  return (
    <div className="relative">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full pl-10 pr-4 py-2.5 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg text-sm text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/30 focus:border-green-500 transition-all"
      />
      {value && (
        <button
          onClick={() => onChange('')}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
        >
          ×
        </button>
      )}
    </div>
  );
}

// ── Select ───────────────────────────────────────────────────────────────────

export function Select({ value, onChange, options, placeholder }) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className="px-3 py-2.5 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg text-sm text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-green-500/30 focus:border-green-500 appearance-none cursor-pointer"
    >
      {placeholder && <option value="">{placeholder}</option>}
      {options.map(opt => (
        <option key={opt.value} value={opt.value}>{opt.label}</option>
      ))}
    </select>
  );
}

// ── Tabs ─────────────────────────────────────────────────────────────────────

export function Tabs({ tabs, active, onChange }) {
  return (
    <div className="flex gap-1 bg-gray-100 dark:bg-gray-900 rounded-lg p-1 border border-gray-200 dark:border-gray-800">
      {tabs.map(tab => (
        <button
          key={tab.id}
          onClick={() => onChange(tab.id)}
          className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            active === tab.id
              ? 'bg-white dark:bg-gray-800 text-gray-900 dark:text-white shadow-sm'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
          }`}
        >
          {tab.label}
          {tab.count != null && (
            <span className={`ml-1.5 px-1.5 py-0.5 rounded text-xs ${
              active === tab.id ? 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300' : 'text-gray-400'
            }`}>
              {tab.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

// ── Severity Bar Chart ───────────────────────────────────────────────────────

export function SeverityBar({ breakdown }) {
  const total = Object.values(breakdown || {}).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  const segments = [
    { key: 'critical', color: 'bg-red-500', count: breakdown.critical || 0 },
    { key: 'high', color: 'bg-orange-500', count: breakdown.high || 0 },
    { key: 'medium', color: 'bg-yellow-500', count: breakdown.medium || 0 },
    { key: 'low', color: 'bg-blue-500', count: breakdown.low || 0 },
  ].filter(s => s.count > 0);

  return (
    <div className="space-y-2">
      <div className="flex h-3 rounded-full overflow-hidden bg-gray-200 dark:bg-gray-800">
        {segments.map(seg => (
          <div
            key={seg.key}
            className={`${seg.color} transition-all duration-500`}
            style={{ width: `${(seg.count / total) * 100}%` }}
            title={`${seg.key}: ${seg.count}`}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-3 text-xs">
        {segments.map(seg => (
          <span key={seg.key} className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${seg.color}`} />
            <span className="text-gray-500 dark:text-gray-400 capitalize">{seg.key}</span>
            <span className="font-mono text-gray-700 dark:text-gray-300">{seg.count}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Duration Display ─────────────────────────────────────────────────────────

export function Duration({ seconds }) {
  if (seconds == null) return <span className="text-gray-400">—</span>;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return <span>{h}h {m}m</span>;
  if (m > 0) return <span>{m}m {s}s</span>;
  return <span>{s}s</span>;
}

// ── Scan ID Context ──────────────────────────────────────────────────────────

const ScanIdContext = createContext(null);

export function ScanIdProvider({ scanId, children }) {
  return <ScanIdContext.Provider value={scanId}>{children}</ScanIdContext.Provider>;
}

export function useScanId() {
  return useContext(ScanIdContext);
}

// Re-export icons for convenience
export { Shield, ExternalLink, Clock, Bug, Play, AlertTriangle, CheckCircle, XCircle, Search, Menu, X, ChevronDown, Moon, Sun, ArrowLeft };

// Re-export formatting utilities from api.js
export { formatDate, formatCost, formatNumber } from '../lib/api';
