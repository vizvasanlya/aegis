import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import Pentests from './pages/Pentests'
import PentestDetail from './pages/PentestDetail'
import Vulnerabilities from './pages/Vulnerabilities'
import Credentials from './pages/Credentials'
import GitRepos from './pages/GitRepos'
import ApiTesting from './pages/ApiTesting'
import MobileTesting from './pages/MobileTesting'
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
            <Route path="/new-scan" element={<NewScan />} />
            <Route path="/pentests" element={<Pentests />} />
            <Route path="/pentest/:id" element={<PentestDetail />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/credentials" element={<Credentials />} />
            <Route path="/git-repos" element={<GitRepos />} />
            <Route path="/api-testing" element={<ApiTesting />} />
            <Route path="/mobile-testing" element={<MobileTesting />} />
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
