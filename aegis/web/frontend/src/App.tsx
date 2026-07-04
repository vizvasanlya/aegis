import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Vulnerabilities from './pages/Vulnerabilities'
import NewScan from './pages/NewScan'
import Settings from './pages/Settings'
import GitScan from './pages/GitScan'

function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/new-scan" element={<NewScan />} />
          <Route path="/git-scan" element={<GitScan />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}

export default App
