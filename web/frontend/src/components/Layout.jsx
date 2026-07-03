import { useState, useCallback, useEffect } from 'react';
import { Outlet, useLocation, Link } from 'react-router-dom';
import { Shield, LayoutDashboard, Bug, FileText, Settings, Moon, Sun, Menu, X, Activity } from 'lucide-react';
import { useTheme, useToast, ToastProvider, ErrorBoundary, ThemeProvider } from './ui';

const NAV_ITEMS = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/scans', label: 'All Scans', icon: FileText },
  { path: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
];

function NavLink({ item, isActive }) {
  const Icon = item.icon;
  return (
    <Link
      to={item.path}
      className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
        isActive
          ? 'bg-green-500/10 text-green-400 border border-green-500/20'
          : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800'
      }`}
    >
      <Icon className="w-4 h-4" />
      {item.label}
    </Link>
  );
}

function Header() {
  const { dark, toggle } = useTheme();
  const location = useLocation();

  return (
    <header className="bg-white/80 dark:bg-gray-950/80 backdrop-blur-xl border-b border-gray-200 dark:border-gray-800 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="p-1.5 bg-green-500/10 rounded-lg border border-green-500/20 group-hover:bg-green-500/20 transition-colors">
              <Shield className="w-6 h-6 text-green-500" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-gray-900 dark:text-white">
                STRIX
              </span>
              <span className="text-lg font-light text-green-500 ml-1">Dashboard</span>
            </div>
          </Link>

          <div className="flex items-center gap-2">
            {NAV_ITEMS.map(item => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path ||
                (item.path === '/scans' && location.pathname.startsWith('/scan/')) ||
                (item.path === '/vulnerabilities' && location.pathname.startsWith('/vulnerability/'));
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`hidden sm:flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-green-500/10 text-green-400'
                      : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </Link>
              );
            })}

            <div className="w-px h-6 bg-gray-200 dark:bg-gray-800 mx-2 hidden sm:block" />

            <button
              onClick={toggle}
              className="p-2 rounded-lg text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              title={dark ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {dark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>

            <a
              href="https://docs.strix.ai"
              target="_blank"
              rel="noreferrer"
              className="hidden sm:flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            >
              <Activity className="w-4 h-4" />
              Docs
            </a>
          </div>
        </div>
      </div>
    </header>
  );
}

function LayoutInner() {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100 transition-colors">
      <Header />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <ErrorBoundary>
          <Outlet />
        </ErrorBoundary>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-200 dark:border-gray-800 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between text-xs text-gray-400 dark:text-gray-600">
            <span>Strix Dashboard v2.0</span>
            <div className="flex items-center gap-4">
              <a href="https://github.com/usestrix/strix" target="_blank" rel="noreferrer" className="hover:text-gray-600 dark:hover:text-gray-300 transition-colors">GitHub</a>
              <a href="https://docs.strix.ai" target="_blank" rel="noreferrer" className="hover:text-gray-600 dark:hover:text-gray-300 transition-colors">Docs</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function Layout() {
  return (
    <ThemeProvider>
      <ToastProvider>
        <LayoutInner />
      </ToastProvider>
    </ThemeProvider>
  );
}
