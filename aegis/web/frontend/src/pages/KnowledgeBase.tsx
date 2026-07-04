import { useState } from 'react'
import { 
  BookOpen, 
  Search, 
  Shield,
  Code,
  Terminal,
  Globe,
  Lock,
  Database,
  ChevronRight
} from 'lucide-react'

const categories = [
  {
    id: 'owasp',
    title: 'OWASP Top 10',
    icon: Shield,
    description: 'Critical web application security risks',
    items: [
      'A01: Broken Access Control',
      'A02: Cryptographic Failures',
      'A03: Injection',
      'A04: Insecure Design',
      'A05: Security Misconfiguration',
      'A06: Vulnerable Components',
      'A07: Auth Failures',
      'A08: Data Integrity Failures',
      'A09: Logging Failures',
      'A10: SSRF',
    ],
  },
  {
    id: 'tools',
    title: 'Security Tools',
    icon: Terminal,
    description: 'Tools available in the sandbox',
    items: [
      'Nmap - Network scanning',
      'SQLMap - SQL injection',
      'Nuclei - Vulnerability scanning',
      'FFUF - Web fuzzing',
      'Subfinder - Subdomain discovery',
      'HTTPX - HTTP probing',
      'Semgrep - Static analysis',
      'Gitleaks - Secret detection',
    ],
  },
  {
    id: 'techniques',
    title: 'Attack Techniques',
    icon: Code,
    description: 'Common attack methodologies',
    items: [
      'SQL Injection',
      'Cross-Site Scripting (XSS)',
      'Server-Side Request Forgery (SSRF)',
      'Remote Code Execution (RCE)',
      'Privilege Escalation',
      'Authentication Bypass',
      'Business Logic Flaws',
      'Race Conditions',
    ],
  },
  {
    id: 'protocols',
    title: 'Protocols',
    icon: Globe,
    description: 'Protocol-specific testing',
    items: [
      'HTTP/HTTPS Testing',
      'WebSocket Security',
      'GraphQL Attacks',
      'gRPC Testing',
      'DNS Zone Transfer',
      'SMB Vulnerabilities',
    ],
  },
  {
    id: 'cloud',
    title: 'Cloud Security',
    icon: Database,
    description: 'Cloud platform security',
    items: [
      'AWS Metadata Exploitation',
      'GCP IAM Abuse',
      'Azure Managed Identity',
      'Container Security',
      'Kubernetes Testing',
    ],
  },
  {
    id: 'compliance',
    title: 'Compliance',
    icon: Lock,
    description: 'Security standards and compliance',
    items: [
      'PCI DSS Requirements',
      'SOC 2 Controls',
      'ISO 27001',
      'NIST Framework',
      'GDPR Data Protection',
    ],
  },
]

export default function KnowledgeBase() {
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)

  const filtered = categories.filter(cat =>
    cat.title.toLowerCase().includes(search.toLowerCase()) ||
    cat.items.some(item => item.toLowerCase().includes(search.toLowerCase()))
  )

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Knowledge Base</h1>
        <p className="mt-1 text-gray-400">Security testing knowledge and references</p>
      </div>

      {/* Search */}
      <div className="mb-6 relative">
        <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search knowledge base..."
          className="w-full rounded-xl border border-gray-800 bg-gray-900/50 py-3 pl-12 pr-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
        />
      </div>

      {/* Categories */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        {filtered.map((category) => {
          const Icon = category.icon
          const isExpanded = expanded === category.id
          return (
            <div
              key={category.id}
              className="rounded-xl border border-gray-800 bg-gray-900/50"
            >
              <button
                onClick={() => setExpanded(isExpanded ? null : category.id)}
                className="flex w-full items-center gap-4 p-5 text-left"
              >
                <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-cyan-900/30">
                  <Icon className="h-6 w-6 text-cyan-400" />
                </div>
                <div className="flex-1">
                  <p className="font-semibold text-white">{category.title}</p>
                  <p className="text-sm text-gray-400">{category.description}</p>
                </div>
                <ChevronRight
                  className={`h-5 w-5 text-gray-500 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                />
              </button>
              
              {isExpanded && (
                <div className="border-t border-gray-800 px-5 py-3">
                  <ul className="space-y-2">
                    {category.items.map((item, idx) => (
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
      </div>
    </div>
  )
}
