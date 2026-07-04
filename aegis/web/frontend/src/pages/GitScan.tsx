import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Github, Play, Loader2 } from 'lucide-react'
import { api } from '../lib/api'

export default function GitScan() {
  const navigate = useNavigate()
  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('main')
  const [scanMode, setScanMode] = useState('standard')
  const [instruction, setInstruction] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!repoUrl) return

    setLoading(true)
    try {
      const result = await api.scanGitRepo({
        repo_url: repoUrl,
        branch,
        scan_mode: scanMode,
        instruction: instruction || undefined,
      })
      navigate(`/scans/${result.scan_id}`)
    } catch (err) {
      alert('Failed to start scan')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="mx-auto max-w-2xl">
      <div className="flex items-center gap-3">
        <Github className="h-8 w-8" />
        <div>
          <h1 className="text-3xl font-bold">Git Repository Scan</h1>
          <p className="mt-1 text-gray-400">Scan a GitHub repository for vulnerabilities</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="mt-8 space-y-6">
        {/* Repository URL */}
        <div>
          <label className="block text-sm font-medium text-gray-300">
            Repository URL
          </label>
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            required
          />
        </div>

        {/* Branch */}
        <div>
          <label className="block text-sm font-medium text-gray-300">
            Branch
          </label>
          <input
            type="text"
            value={branch}
            onChange={(e) => setBranch(e.target.value)}
            placeholder="main"
            className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        {/* Scan Mode */}
        <div>
          <label className="block text-sm font-medium text-gray-300">
            Scan Mode
          </label>
          <select
            value={scanMode}
            onChange={(e) => setScanMode(e.target.value)}
            className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white focus:border-cyan-500 focus:outline-none"
          >
            <option value="quick">Quick (10-15 min)</option>
            <option value="standard">Standard (20-30 min)</option>
            <option value="deep">Deep (30-60 min)</option>
          </select>
        </div>

        {/* Instructions */}
        <div>
          <label className="block text-sm font-medium text-gray-300">
            Custom Instructions (Optional)
          </label>
          <textarea
            value={instruction}
            onChange={(e) => setInstruction(e.target.value)}
            placeholder="Focus on authentication, check for SQL injection..."
            rows={3}
            className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={loading || !repoUrl}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-3 font-medium text-white hover:bg-cyan-700 disabled:opacity-50"
        >
          {loading ? (
            <Loader2 className="h-5 w-5 animate-spin" />
          ) : (
            <Play className="h-5 w-5" />
          )}
          {loading ? 'Starting Scan...' : 'Scan Repository'}
        </button>
      </form>
    </div>
  )
}
