import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Vulnerabilities from './pages/Vulnerabilities'
import NewScan from './pages/NewScan'
import GitRepos from './pages/GitRepos'
import Integrations from './pages/Integrations'
import KnowledgeBase from './pages/KnowledgeBase'
import Settings from './pages/Settings'
import Logs from './pages/Logs'

function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-950">
        <Sidebar />
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/new-scan" element={<NewScan />} />
            <Route path="/git-repos" element={<GitRepos />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/knowledge" element={<KnowledgeBase />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/logs" element={<Logs />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App
