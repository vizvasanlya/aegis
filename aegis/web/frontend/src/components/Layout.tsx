import { Link, useLocation } from 'react-router-dom'
import { 
  LayoutDashboard, 
  Scan, 
  Shield, 
  Plus, 
  Github, 
  Settings,
  Terminal
} from 'lucide-react'
import { clsx } from 'clsx'

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/scans', label: 'Scans', icon: Scan },
  { path: '/vulnerabilities', label: 'Vulnerabilities', icon: Shield },
  { path: '/new-scan', label: 'New Scan', icon: Plus },
  { path: '/git-scan', label: 'Git Scan', icon: Github },
  { path: '/settings', label: 'Settings', icon: Settings },
]

interface LayoutProps {
  children: React.ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur">
        <div className="flex h-16 items-center px-6">
          <Link to="/" className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <span className="text-xl font-bold">AEGIS</span>
          </Link>
          
          <nav className="ml-10 flex gap-1">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={clsx(
                    'flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-gray-800 text-white'
                      : 'text-gray-400 hover:bg-gray-800/50 hover:text-white'
                  )}
                >
                  <Icon className="h-4 w-4" />
                  {item.label}
                </Link>
              )
            })}
          </nav>

          <div className="ml-auto flex items-center gap-4">
            <div className="flex items-center gap-2 rounded-lg bg-gray-800 px-3 py-1.5">
              <Terminal className="h-4 w-4 text-green-400" />
              <span className="text-sm text-gray-300">v1.0.0</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="mx-auto max-w-7xl px-6 py-8">
        {children}
      </main>
    </div>
  )
}
