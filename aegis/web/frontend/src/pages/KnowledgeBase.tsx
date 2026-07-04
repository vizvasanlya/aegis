import { useEffect, useState } from 'react'
import { 
  BookOpen, 
  Search, 
  Shield,
  Code,
  Terminal,
  Globe,
  Lock,
  Database,
  ChevronRight,
  Loader2
} from 'lucide-react'
import { api } from '../lib/api'

const categoryIcons: Record<string, any> = {
  vulnerabilities: Shield,
  tooling: Terminal,
  scan_modes: Code,
  coordination: Globe,
  cloud: Database,
  custom: Lock,
  frameworks: Code,
  protocols: Globe,
  reconnaissance: Search,
  technologies: Database,
}

const categoryDescriptions: Record<string, string> = {
  vulnerabilities: 'Security vulnerability testing techniques',
  tooling: 'Security tools and their usage',
  scan_modes: 'Different scanning approaches',
  coordination: 'Multi-agent orchestration',
  cloud: 'Cloud security testing',
  custom: 'Custom testing methodologies',
  frameworks: 'Framework-specific testing',
  protocols: 'Protocol security testing',
  reconnaissance: 'Information gathering techniques',
  technologies: 'Technology-specific testing',
}

export default function KnowledgeBase() {
  const [skills, setSkills] = useState<Record<string, string[]>>({})
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.listSkills().then(data => {
      setSkills(data)
      setLoading(false)
    })
  }, [])

  const filtered = Object.entries(skills).filter(([category, items]) =>
    category.toLowerCase().includes(search.toLowerCase()) ||
    items.some(item => item.toLowerCase().includes(search.toLowerCase()))
  )

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Knowledge Base</h1>
        <p className="mt-1 text-gray-400">Available skills and testing methodologies</p>
      </div>

      {/* Search */}
      <div className="mb-6 relative">
        <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search skills..."
          className="w-full rounded-xl border border-gray-800 bg-gray-900/50 py-3 pl-12 pr-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
        />
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filtered.map(([category, items]) => {
            const Icon = categoryIcons[category] || Shield
            const description = categoryDescriptions[category] || 'Testing knowledge'
            const isExpanded = expanded === category
            return (
              <div
                key={category}
                className="rounded-xl border border-gray-800 bg-gray-900/50"
              >
                <button
                  onClick={() => setExpanded(isExpanded ? null : category)}
                  className="flex w-full items-center gap-4 p-5 text-left"
                >
                  <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-cyan-900/30">
                    <Icon className="h-6 w-6 text-cyan-400" />
                  </div>
                  <div className="flex-1">
                    <p className="font-semibold text-white capitalize">{category}</p>
                    <p className="text-sm text-gray-400">{description}</p>
                    <p className="text-xs text-gray-500 mt-1">{items.length} skills</p>
                  </div>
                  <ChevronRight
                    className={`h-5 w-5 text-gray-500 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                  />
                </button>
                
                {isExpanded && (
                  <div className="border-t border-gray-800 px-5 py-3">
                    <ul className="space-y-2">
                      {items.map((item, idx) => (
                        <li key={idx} className="flex items-center gap-2 text-sm text-gray-300">
                          <div className="h-1.5 w-1.5 rounded-full bg-cyan-500" />
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )
          })}
          {filtered.length === 0 && (
            <div className="col-span-full py-12 text-center text-gray-500">
              No skills found
            </div>
          )}
        </div>
      )}
    </div>
  )
}
