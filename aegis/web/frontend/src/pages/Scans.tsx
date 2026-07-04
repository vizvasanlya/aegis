import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Scan, Trash2, ExternalLink } from 'lucide-react'
import { api } from '../lib/api'

export default function Scans() {
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.listScans().then(data => {
      setScans(data)
      setLoading(false)
    })
  }, [])

  const handleDelete = async (id: string) => {
    if (confirm('Delete this scan?')) {
      await api.deleteScan(id)
      setScans(scans.filter(s => s.id !== id))
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Scans</h1>
        <Link
          to="/new-scan"
          className="rounded-lg bg-cyan-600 px-4 py-2 font-medium text-white hover:bg-cyan-700"
        >
          New Scan
        </Link>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900/50">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800 text-left text-sm text-gray-400">
              <th className="px-6 py-4">Target</th>
              <th className="px-6 py-4">Mode</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Started</th>
              <th className="px-6 py-4">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {scans.map((scan) => (
              <tr key={scan.id} className="hover:bg-gray-800/50">
                <td className="px-6 py-4">
                  <Link to={`/scans/${scan.id}`} className="font-medium hover:text-cyan-400">
                    {scan.target}
                  </Link>
                </td>
                <td className="px-6 py-4 text-gray-400">{scan.scan_mode}</td>
                <td className="px-6 py-4">
                  <StatusBadge status={scan.status} />
                </td>
                <td className="px-6 py-4 text-gray-400">
                  {scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}
                </td>
                <td className="px-6 py-4">
                  <div className="flex gap-2">
                    <Link
                      to={`/scans/${scan.id}`}
                      className="rounded p-1 text-gray-400 hover:bg-gray-800 hover:text-white"
                    >
                      <ExternalLink className="h-4 w-4" />
                    </Link>
                    <button
                      onClick={() => handleDelete(scan.id)}
                      className="rounded p-1 text-gray-400 hover:bg-gray-800 hover:text-red-400"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {scans.length === 0 && !loading && (
          <div className="px-6 py-12 text-center text-gray-500">
            No scans found. Start your first scan!
          </div>
        )}
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: 'bg-green-900/50 text-green-400',
    running: 'bg-blue-900/50 text-blue-400',
    failed: 'bg-red-900/50 text-red-400',
    pending: 'bg-yellow-900/50 text-yellow-400',
  }

  return (
    <span className={`rounded-full px-2 py-1 text-xs font-medium ${styles[status] || 'bg-gray-800 text-gray-400'}`}>
      {status}
    </span>
  )
}
