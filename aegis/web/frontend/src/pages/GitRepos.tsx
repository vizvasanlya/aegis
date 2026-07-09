import { useEffect, useState } from 'react'
import { 
  Github, 
  Gitlab, 
  Plus, 
  Scan, 
  Trash2, 
  RefreshCw,
  ExternalLink,
  Loader2
} from 'lucide-react'
import { api, formatDate } from '../lib/api'

export default function GitRepos() {
  const [repos, setRepos] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [newRepoUrl, setNewRepoUrl] = useState('')
  const [scanning, setScanning] = useState<number | null>(null)

  useEffect(() => {
    loadRepos()
  }, [])

  const loadRepos = async () => {
    setLoading(true)
    try {
      const data = await api.listRepos()
      setRepos(data)
    } finally {
      setLoading(false)
    }
  }

  const handleAddRepo = async () => {
    if (!newRepoUrl) return
    
    try {
      await api.addRepo({ url: newRepoUrl })
      setNewRepoUrl('')
      setShowAddModal(false)
      loadRepos()
    } catch (err) {
      alert('Failed to add repository')
    }
  }

  const handleDelete = async (id: number) => {
    if (confirm('Remove this repository?')) {
      await api.deleteRepo(id)
      loadRepos()
    }
  }

  const handleScan = async (id: number) => {
    setScanning(id)
    try {
      await api.scanRepo(id)
      loadRepos()
    } finally {
      setScanning(null)
    }
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

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
        </div>
      ) : repos.length === 0 ? (
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 py-16 text-center">
          <Github className="mx-auto h-12 w-12 text-gray-600" />
          <p className="mt-4 text-lg text-gray-400">No repositories connected</p>
          <p className="mt-1 text-sm text-gray-500">Add a GitHub or GitLab repository to get started</p>
          <button
            onClick={() => setShowAddModal(true)}
            className="mt-4 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-700"
          >
            Add Repository
          </button>
        </div>
      ) : (
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
                  <p className="text-sm text-gray-400 truncate max-w-md">{repo.url}</p>
                </div>
              </div>
              
              <div className="flex items-center gap-6">
                <div className="text-right">
                  <p className="text-xs text-gray-500">Last scan</p>
                  <p className="text-sm text-white">
                    {formatDate(repo.last_scan)}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-gray-500">Findings</p>
                  <p className="text-sm text-white">{repo.findings || 0}</p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleScan(repo.id)}
                    disabled={scanning === repo.id}
                    className="rounded-lg bg-cyan-600 px-3 py-2 text-sm text-white hover:bg-cyan-700 disabled:opacity-50 transition-colors"
                  >
                    {scanning === repo.id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Scan className="h-4 w-4" />
                    )}
                  </button>
                  <button
                    onClick={() => handleDelete(repo.id)}
                    className="rounded-lg bg-gray-800 px-3 py-2 text-sm text-gray-400 hover:bg-gray-700 hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-gray-800 bg-gray-900 p-6 shadow-2xl">
            <h2 className="text-xl font-semibold text-white">Add Repository</h2>
            <p className="mt-1 text-sm text-gray-400">Enter a GitHub or GitLab repository URL</p>
            
            <input
              type="text"
              value={newRepoUrl}
              onChange={(e) => setNewRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              className="mt-4 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              autoFocus
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
                disabled={!newRepoUrl}
                className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-700 disabled:opacity-50"
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
