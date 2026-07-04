import { useEffect, useState } from 'react'
import { 
  Key, 
  Plus, 
  Trash2, 
  Edit, 
  Eye, 
  EyeOff,
  Globe,
  User,
  Lock,
  CreditCard,
  Hash,
  Loader2,
  Shield,
  ExternalLink,
  Check,
  AlertCircle
} from 'lucide-react'
import { api } from '../lib/api'

const credentialTypes = [
  { id: 'credentials', label: 'Username/Password', icon: User, description: 'Login credentials for web applications' },
  { id: 'api_key', label: 'API Key', icon: Key, description: 'API keys for REST/GraphQL endpoints' },
  { id: 'token', label: 'Bearer Token', icon: CreditCard, description: 'JWT or OAuth tokens' },
  { id: 'cookie', label: 'Cookies', icon: Hash, description: 'Browser cookies for session' },
]

export default function Credentials() {
  const [credentials, setCredentials] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [showValues, setShowValues] = useState<Record<number, boolean>>({})
  
  const [form, setForm] = useState({
    name: '',
    site_url: '',
    credential_type: 'credentials',
    username: '',
    password: '',
    api_key: '',
    token: '',
    cookies: '',
    notes: '',
  })

  useEffect(() => {
    loadCredentials()
  }, [])

  const loadCredentials = async () => {
    setLoading(true)
    try {
      const data = await api.listCredentials()
      setCredentials(data)
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    try {
      if (editingId) {
        await api.updateCredential(editingId, form)
      } else {
        await api.createCredential(form)
      }
      setShowModal(false)
      setEditingId(null)
      resetForm()
      loadCredentials()
    } catch (err) {
      alert('Failed to save credential')
    }
  }

  const handleDelete = async (id: number) => {
    if (confirm('Delete this credential?')) {
      await api.deleteCredential(id)
      loadCredentials()
    }
  }

  const handleEdit = async (id: number) => {
    const data = await api.getCredential(id)
    setForm({
      name: data.name,
      site_url: data.site_url,
      credential_type: data.credential_type,
      username: data.username || '',
      password: data.password || '',
      api_key: data.api_key || '',
      token: data.token || '',
      cookies: data.cookies || '',
      notes: data.notes || '',
    })
    setEditingId(id)
    setShowModal(true)
  }

  const resetForm = () => {
    setForm({
      name: '',
      site_url: '',
      credential_type: 'credentials',
      username: '',
      password: '',
      api_key: '',
      token: '',
      cookies: '',
      notes: '',
    })
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'credentials': return User
      case 'api_key': return Key
      case 'token': return CreditCard
      case 'cookie': return Hash
      default: return Key
    }
  }

  return (
    <div className="p-8">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Credentials</h1>
          <p className="mt-1 text-gray-400">Securely store credentials for authenticated testing</p>
        </div>
        <button
          onClick={() => { resetForm(); setEditingId(null); setShowModal(true) }}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 font-medium text-white hover:bg-cyan-700 transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add Credential
        </button>
      </div>

      {/* Security Notice */}
      <div className="mb-6 flex items-start gap-3 rounded-xl border border-cyan-900/50 bg-cyan-900/10 p-4">
        <Shield className="h-5 w-5 text-cyan-400 mt-0.5 flex-shrink-0" />
        <div>
          <p className="text-sm font-medium text-cyan-400">Secure Storage</p>
          <p className="text-xs text-gray-400 mt-1">
            Credentials are encrypted before storage. Never share your credentials or commit them to version control.
          </p>
        </div>
      </div>

      {/* Credentials List */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
        </div>
      ) : credentials.length === 0 ? (
        <div className="rounded-2xl border border-gray-800 bg-gray-900/50 py-20 text-center">
          <Key className="mx-auto h-16 w-16 text-gray-700" />
          <h3 className="mt-4 text-lg font-medium text-gray-400">No credentials stored</h3>
          <p className="mt-2 text-sm text-gray-500">Add credentials to enable authenticated testing</p>
          <button
            onClick={() => setShowModal(true)}
            className="mt-6 rounded-lg bg-cyan-600 px-5 py-2.5 font-medium text-white hover:bg-cyan-700"
          >
            Add First Credential
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {credentials.map((cred) => {
            const TypeIcon = getTypeIcon(cred.credential_type)
            return (
              <div
                key={cred.id}
                className="rounded-xl border border-gray-800 bg-gray-900/50 p-5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gray-800">
                      <TypeIcon className="h-6 w-6 text-cyan-400" />
                    </div>
                    <div>
                      <p className="font-medium text-white">{cred.name}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <Globe className="h-3 w-3 text-gray-500" />
                        <span className="text-sm text-gray-400">{cred.site_url}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="rounded-full bg-gray-800 px-2.5 py-1 text-xs text-gray-400">
                      {credentialTypes.find(t => t.id === cred.credential_type)?.label}
                    </span>
                    <button
                      onClick={() => handleEdit(cred.id)}
                      className="rounded-lg p-2 text-gray-400 hover:bg-gray-800 hover:text-white transition-colors"
                    >
                      <Edit className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => handleDelete(cred.id)}
                      className="rounded-lg p-2 text-gray-400 hover:bg-gray-800 hover:text-red-400 transition-colors"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                {cred.notes && (
                  <p className="mt-3 text-sm text-gray-500">{cred.notes}</p>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-2xl border border-gray-800 bg-gray-900 p-6 shadow-2xl">
            <h2 className="text-xl font-semibold text-white">
              {editingId ? 'Edit Credential' : 'Add Credential'}
            </h2>
            <p className="mt-1 text-sm text-gray-400">Store credentials securely for authenticated testing</p>
            
            <div className="mt-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300">Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g., Production Admin"
                  className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300">Site URL</label>
                <input
                  type="text"
                  value={form.site_url}
                  onChange={(e) => setForm({ ...form, site_url: e.target.value })}
                  placeholder="https://example.com"
                  className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Credential Type</label>
                <div className="grid grid-cols-2 gap-2">
                  {credentialTypes.map((type) => {
                    const Icon = type.icon
                    return (
                      <button
                        key={type.id}
                        onClick={() => setForm({ ...form, credential_type: type.id })}
                        className={`rounded-lg border p-3 text-left transition-colors ${
                          form.credential_type === type.id
                            ? 'border-cyan-500 bg-cyan-900/30'
                            : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <Icon className="h-4 w-4 text-gray-400" />
                          <span className="text-sm font-medium text-white">{type.label}</span>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Type-specific fields */}
              {form.credential_type === 'credentials' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-300">Username</label>
                    <input
                      type="text"
                      value={form.username}
                      onChange={(e) => setForm({ ...form, username: e.target.value })}
                      placeholder="admin@example.com"
                      className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300">Password</label>
                    <input
                      type="password"
                      value={form.password}
                      onChange={(e) => setForm({ ...form, password: e.target.value })}
                      placeholder="••••••••"
                      className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                    />
                  </div>
                </>
              )}

              {form.credential_type === 'api_key' && (
                <div>
                  <label className="block text-sm font-medium text-gray-300">API Key</label>
                  <input
                    type="password"
                    value={form.api_key}
                    onChange={(e) => setForm({ ...form, api_key: e.target.value })}
                    placeholder="sk-..."
                    className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              )}

              {form.credential_type === 'token' && (
                <div>
                  <label className="block text-sm font-medium text-gray-300">Bearer Token</label>
                  <input
                    type="password"
                    value={form.token}
                    onChange={(e) => setForm({ ...form, token: e.target.value })}
                    placeholder="eyJhbGciOiJIUzI1NiJ9..."
                    className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              )}

              {form.credential_type === 'cookie' && (
                <div>
                  <label className="block text-sm font-medium text-gray-300">Cookies</label>
                  <textarea
                    value={form.cookies}
                    onChange={(e) => setForm({ ...form, cookies: e.target.value })}
                    placeholder="session=abc123; token=xyz789"
                    rows={3}
                    className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none resize-none"
                  />
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-300">Notes (Optional)</label>
                <textarea
                  value={form.notes}
                  onChange={(e) => setForm({ ...form, notes: e.target.value })}
                  placeholder="Additional notes about these credentials..."
                  rows={2}
                  className="mt-2 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none resize-none"
                />
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => { setShowModal(false); setEditingId(null); resetForm() }}
                className="rounded-lg px-4 py-2 text-sm text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={!form.name || !form.site_url}
                className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-cyan-700 disabled:opacity-50"
              >
                <Check className="h-4 w-4" />
                {editingId ? 'Update' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
