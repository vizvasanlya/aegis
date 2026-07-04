import { useEffect, useState } from 'react'
import { Terminal, RefreshCw, Download } from 'lucide-react'
import { api } from '../lib/api'

export default function Logs() {
  const [scans, setScans] = useState<any[]>([])
  const [selectedScan, setSelectedScan] = useState<string>('')
  const [logs, setLogs] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.listScans().then(setScans)
  }, [])

  const loadLogs = async (scanId: string) => {
    setSelectedScan(scanId)
    setLoading(true)
    try {
      const data = await api.getLogs(scanId, 1000)
      setLogs(data.logs)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex h-full flex-col p-8">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Logs</h1>
          <p className="mt-1 text-gray-400">View scan logs and execution details</p>
        </div>
        {selectedScan && (
          <button className="flex items-center gap-2 rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-300 hover:bg-gray-700 transition-colors">
            <Download className="h-4 w-4" />
            Export
          </button>
        )}
      </div>

      <div className="flex flex-1 gap-6 overflow-hidden">
        {/* Scan List */}
        <div className="w-64 flex-shrink-0 rounded-xl border border-gray-800 bg-gray-900/50">
          <div className="border-b border-gray-800 px-4 py-3">
            <p className="text-sm font-medium text-white">Select Scan</p>
          </div>
          <div className="overflow-y-auto">
            {scans.map((scan) => (
              <button
                key={scan.id}
                onClick={() => loadLogs(scan.id)}
                className={`w-full px-4 py-3 text-left text-sm transition-colors ${
                  selectedScan === scan.id
                    ? 'bg-cyan-900/30 text-cyan-400'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <p className="font-medium truncate">{scan.target}</p>
                <p className="text-xs text-gray-500">{scan.id}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Log Viewer */}
        <div className="flex-1 rounded-xl border border-gray-800 bg-gray-900/50">
          {selectedScan ? (
            <div className="flex h-full flex-col">
              <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-cyan-400" />
                  <span className="text-sm font-medium text-white">{selectedScan}</span>
                </div>
                <button
                  onClick={() => loadLogs(selectedScan)}
                  className="rounded p-1 text-gray-400 hover:bg-gray-800 hover:text-white"
                >
                  <RefreshCw className="h-4 w-4" />
                </button>
              </div>
              <div className="flex-1 overflow-auto p-4">
                {loading ? (
                  <p className="text-gray-500">Loading logs...</p>
                ) : (
                  <pre className="font-mono text-xs text-gray-300 whitespace-pre-wrap">
                    {logs || 'No logs available for this scan'}
                  </pre>
                )}
              </div>
            </div>
          ) : (
            <div className="flex h-full items-center justify-center text-gray-500">
              Select a scan to view logs
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
