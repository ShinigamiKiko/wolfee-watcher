import './styles/main.scss';

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Topbar } from './components/Topbar';
import { Sidebar } from './components/Sidebar';
import { ToastStack } from './components/Toast';
import { Modal } from './components/Modal';
import { RequireAuth } from './components/RequireAuth';
import { BridgeProvider } from './context/BridgeContext';
import { ScannerProvider } from './context/ScannerContext';
import { SensorProvider } from './context/SensorContext';

import { Login }         from './pages/Login';
import { Dashboard }     from './pages/Dashboard';
import { Violations }    from './pages/violations';
import { Compliance }    from './pages/compliance';
import { VulnMgmt }      from './pages/vuln/VulnMgmt';
import { ConfigMgmt }    from './pages/ConfigMgmt';
import { Risk }          from './pages/risk';
import { PolicyMgmt }    from './pages/PolicyMgmt';
import { SystemHealth }  from './pages/SystemHealth';
import { NetworkRuntime } from './pages/network/NetworkPolicy';
import { MyProfile }     from './pages/MyProfile';
import { Audit }          from './pages/audit';
import { Alerts }        from './pages/alerts';
import { Honeypot }      from './pages/honeypot';
import { SBOM }          from './pages/sbom';
import { Forensics }     from './pages/forensics';
import { Tracepoints }   from './pages/tracepoints';
import { Syscalls }      from './pages/syscalls';
import { Lsm }           from './pages/lsm';
import { RBAC }          from './pages/rbac';
import { Settings }      from './pages/Settings';

function AuthedShell() {
  return (
    <BridgeProvider>
      <ScannerProvider>
        <SensorProvider>
          <Topbar />
          <div className="layout">
            <Sidebar />
            <main className="main">
              <Routes>
                <Route path="/"            element={<Dashboard />} />
                <Route path="/violations"  element={<Violations />} />
                <Route path="/compliance"  element={<Compliance />} />
                <Route path="/vulnmgmt"    element={<VulnMgmt />} />
                <Route path="/configmgmt"  element={<ConfigMgmt />} />
                <Route path="/risk"        element={<Risk />} />
                <Route path="/policymgmt"  element={<PolicyMgmt />} />
                <Route path="/syshealth"   element={<SystemHealth />} />
                <Route path="/net-runtime" element={<NetworkRuntime />} />
                <Route path="/alerts"      element={<Alerts />} />
                <Route path="/audit"       element={<Audit />} />
                <Route path="/honeypot"    element={<Honeypot />} />
                <Route path="/forensics"   element={<Forensics />} />
                <Route path="/syscalls"    element={<Syscalls />} />
                <Route path="/tracepoints" element={<Tracepoints />} />
                <Route path="/lsm"         element={<Lsm />} />
                <Route path="/rbac"        element={<RBAC />} />
                <Route path="/sbom"        element={<SBOM />} />
                <Route path="/settings"    element={<Settings />} />
                <Route path="/profile"     element={<MyProfile />} />
                <Route path="*"            element={<Navigate to="/" replace />} />
              </Routes>
            </main>
          </div>
          <ToastStack />
          <Modal />
        </SensorProvider>
      </ScannerProvider>
    </BridgeProvider>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<RequireAuth><AuthedShell /></RequireAuth>} />
      </Routes>
    </BrowserRouter>
  );
}
