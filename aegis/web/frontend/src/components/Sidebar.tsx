import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Shield,
  Github,
  Plug,
  BookOpen,
  Settings,
  Terminal,
  Scan,
  Key,
  Plus,
  Code,
  Smartphone,
  Network,
} from 'lucide-react'
import { clsx } from 'clsx'

const navSections = [
  {
    title: 'Overview',
    items: [
      { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    ],
  },
  {
    title: 'Launch',
    items: [
      { path: '/new-scan', label: 'New Scan', icon: Plus },
    ],
  },
  {
    title: 'Security',
    items: [
      { path: '/pentests', label: 'Pentests', icon: Scan },
      { path: '/vulnerabilities', label: 'Vulnerabilities', icon: Shield },
      { path: '/api-testing', label: 'API Testing', icon: Code },
      { path: '/mobile-testing', label: 'Mobile Testing', icon: Smartphone },
      { path: '/credentials', label: 'Credentials', icon: Key },
      { path: '/logs', label: 'Logs', icon: Terminal },
    ],
  },
  {
    title: 'Integrations',
    items: [
      { path: '/git-repos', label: 'Git Repos', icon: Github },
      { path: '/integrations', label: 'Providers', icon: Plug },
    ],
  },
  {
    title: 'Resources',
    items: [
      { path: '/knowledge', label: 'Knowledge Base', icon: BookOpen },
      { path: '/settings', label: 'Settings', icon: Settings },
    ],
  },
]

export default function Sidebar() {
  const location = useLocation()

  return (
    <aside className="flex w-64 flex-col border-r border-gray-800 bg-gray-900">
      {/* Logo */}
      <div className="flex h-16 items-center gap-3 border-b border-gray-800 px-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600">
          <Shield className="h-5 w-5 text-white" />
        </div>
        <div>
          <span className="text-lg font-bold text-white">AEGIS</span>
          <span className="ml-2 rounded bg-cyan-900/50 px-1.5 py-0.5 text-[10px] font-medium text-cyan-400">
            v1.0
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        {navSections.map((section) => (
          <div key={section.title} className="mb-6">
            <p className="mb-2 px-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
              {section.title}
            </p>
            <ul className="space-y-1">
              {section.items.map((item) => {
                const Icon = item.icon
                const isActive = location.pathname === item.path ||
                  (item.path === '/pentests' && location.pathname.startsWith('/pentest')) ||
                  (item.path === '/api-testing' && location.pathname.startsWith('/api-testing')) ||
                  (item.path === '/mobile-testing' && location.pathname.startsWith('/mobile-testing'))
                return (
                  <li key={item.path}>
                    <Link
                      to={item.path}
                      className={clsx(
                        'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                        isActive
                          ? 'bg-cyan-900/30 text-cyan-400'
                          : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                      )}
                    >
                      <Icon className="h-4 w-4" />
                      {item.label}
                    </Link>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-gray-800 p-4">
        <div className="rounded-lg bg-gray-800/50 p-3">
          <p className="text-xs text-gray-400">Docker Status</p>
          <div className="mt-1 flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-green-400"></div>
            <span className="text-xs text-gray-300">Connected</span>
          </div>
        </div>
      </div>
    </aside>
  )
}
