import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Play, Loader2 } from 'lucide-react'
import { api } from '../lib/api'

export default function NewScan() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [scanMode, setScanMode] = useState('standard')
  const [instruction, setInstruction] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!target) return

    setLoading(true)
    try {
      const result = await api.createScan({
        target,
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
      <h1 className="text-3xl font-bold">New Scan</h1>
      <p className="mt-1 text-gray-400">Start a new security assessment</p>

      <form onSubmit={handleSubmit} className="mt-8 space-y-6">
        {/* Target */}
        <div>
          <label className="block text-sm font-medium text-gray-300">
            Target URL or Path
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com or ./path/to/code"
            className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            required
          />
          <p className="mt-1 text-xs text-gray-500">
            Supports URLs, GitHub repos, local directories, and IP addresses
          </p>
        </div>

        {/* Scan Mode */}
        <div>
          <label className="block text-sm font-medium text-gray-300">
            Scan Mode
          </label>
          <div className="mt-2 grid grid-cols-3 gap-3">
            {[
              { value: 'quick', label: 'Quick', desc: '10-15 min' },
              { value: 'standard', label: 'Standard', desc: '20-30 min' },
              { value: 'deep', label: 'Deep', desc: '30-60 min' },
            ].map((mode) => (
              <button
                key={mode.value}
                type="button"
                onClick={() => setScanMode(mode.value)}
                className={`rounded-lg border p-4 text-left transition-colors ${
                  scanMode === mode.value
                    ? 'border-cyan-500 bg-cyan-900/30'
                    : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                }`}
              >
                <p className="font-medium">{mode.label}</p>
                <p className="text-xs text-gray-400">{mode.desc}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Instructions */}
        <div>
          <label className="block text-sm font-medium text-gray-300">
            Custom Instructions (Optional)
          </label>
          <textarea
            value={instruction}
            onChange={(e) => setInstruction(e.target.value)}
            placeholder="Focus on authentication vulnerabilities, test with admin credentials..."
            rows={3}
            className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={loading || !target}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-3 font-medium text-white hover:bg-cyan-700 disabled:opacity-50"
        >
          {loading ? (
            <Loader2 className="h-5 w-5 animate-spin" />
          ) : (
            <Play className="h-5 w-5" />
          )}
          {loading ? 'Starting Scan...' : 'Start Scan'}
        </button>
      </form>
    </div>
  )
}
