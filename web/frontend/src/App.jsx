import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import AllScans from './pages/AllScans';
import ScanDetail from './pages/ScanDetail';
import AllVulnerabilities from './pages/AllVulnerabilities';
import VulnerabilityDetail from './pages/VulnerabilityDetail';
import './index.css';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans" element={<AllScans />} />
          <Route path="/scan/:scanId" element={<ScanDetail />} />
          <Route path="/vulnerabilities" element={<AllVulnerabilities />} />
          <Route path="/vulnerability/:scanId/:vulnId" element={<VulnerabilityDetail />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
