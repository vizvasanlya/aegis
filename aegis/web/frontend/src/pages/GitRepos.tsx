import { useState } from 'react'
import { 
  Github, 
  Gitlab, 
  Plus, 
  Scan, 
  Trash2, 
  RefreshCw,
  ExternalLink
} from 'lucide-react'

const mockRepos = [
  { id: 1, name: 'frontend-app', url: 'https://github.com/myorg/frontend-app', provider: 'github', lastScan: '2 hours ago', findings: 12 },
  { id: 2, name: 'api-service', url: 'https://github.com/myorg/api-service', provider: 'github', lastScan: '1 day ago', findings: 5 },
  { id: 3, name: 'auth-module', url: 'https://gitlab.com/myorg/auth-module', provider: 'gitlab', lastScan: '3 days ago', findings: 8 },
]

export default function GitRepos() {
  const [repos, setRepos] = useState(mockRepos)
  const [showAddModal, setShowAddModal] = useState(false)
  const [newRepoUrl, setNewRepoUrl] = useState('')

  const handleAddRepo = () => {
    if (newRepoUrl) {
      const provider = newRepoUrl.includes('gitlab') ? 'gitlab' : 'github'
      setRepos([
        ...repos,
        {
          id: Date.now(),
          name: newRepoUrl.split('/').pop()?.replace('.git', '') || 'repo',
          url: newRepoUrl,
          provider,
          lastScan: 'Never',
          findings: 0,
        },
      ])
      setNewRepoUrl('')
      setShowAddModal(false)
    }
  }

  const handleScan = (repoId: number) => {
    // Trigger scan
    console.log('Scanning repo:', repoId)
  }

  return (
    <div className="p-8">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Git Repositories</h1>
          <p className="mt-1 text-gray-400">Manage connected repositories for scanning</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 font-medium text-white hover:bg-cyan-700 transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add Repository
        </button>
      </div>

      {/* Repository List */}
      <div className="space-y-3">
        {repos.map((repo) => (
          <div
            key={repo.id}
            className="flex items-center justify-between rounded-xl border border-gray-800 bg-gray-900/50 px-6 py-4"
          >
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gray-800">
                {repo.provider === 'github' ? (
                  <Github className="h-6 w-6 text-white" />
                ) : (
                  <Gitlab className="h-6 w-6 text-orange-500" />
                )}
              </div>
              <div>
                <p className="font-medium text-white">{repo.name}</p>
                <p className="text-sm text-gray-400">{repo.url}</p>
              </div>
            </div>
            
            <div className="flex items-center gap-6">
              <div className="text-right">
                <p className="text-sm text-gray-400">Last scan</p>
                <p className="text-sm text-white">{repo.lastScan}</p>
              </div>
              <div className="text-right">
                <p className="text-sm text-gray-400">Findings</p>
                <p className="text-sm text-white">{repo.findings}</p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => handleScan(repo.id)}
                  className="rounded-lg bg-cyan-600 px-3 py-2 text-sm font-medium text-white hover:bg-cyan-700 transition-colors"
                >
                  <Scan className="h-4 w-4" />
                </button>
                <button className="rounded-lg bg-gray-800 px-3 py-2 text-sm text-gray-400 hover:bg-gray-700 hover:text-white transition-colors">
                  <RefreshCw className="h-4 w-4" />
                </button>
                <button className="rounded-lg bg-gray-800 px-3 py-2 text-sm text-gray-400 hover:bg-gray-700 hover:text-red-400 transition-colors">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Add Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-full max-w-md rounded-xl border border-gray-800 bg-gray-900 p-6">
            <h2 className="text-xl font-semibold text-white">Add Repository</h2>
            <p className="mt-1 text-sm text-gray-400">Enter a Git repository URL</p>
            
            <input
              type="text"
              value={newRepoUrl}
              onChange={(e) => setNewRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              className="mt-4 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            />
            
            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => setShowAddModal(false)}
                className="rounded-lg px-4 py-2 text-sm text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleAddRepo}
                className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-700"
              >
                Add Repository
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
