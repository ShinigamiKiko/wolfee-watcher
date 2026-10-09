import './styles/main.scss';

import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Topbar } from './components/Topbar';
import { Sidebar } from './components/Sidebar';
import { ToastStack } from './components/Toast';
import { Modal } from './components/Modal';
import { RequireAuth } from './components/RequireAuth';
import { BridgeProvider } from './context/BridgeContext';
import { ScannerProvider } from './context/ScannerContext';
import { SensorProvider } from './context/SensorContext';
import { ClusterProvider, useClusters } from './context/ClusterContext';
import { ClusterBanner } from './components/ClusterPicker';
import { RouteErrorBoundary } from './components/ErrorBoundary';

import { Login }         from './pages/Login';

const RELOAD_KEY = 'kvisior.chunk-reload';

const page = (load, name) => lazy(() => load().then(m => {
  try { sessionStorage.removeItem(RELOAD_KEY); } catch {}
  return { default: m[name] };
}).catch(err => {
  try {
    if (!sessionStorage.getItem(RELOAD_KEY)) {
      sessionStorage.setItem(RELOAD_KEY, '1');
      window.location.reload();
      return new Promise(() => {});
    }
  } catch {}
  throw err;
}));

const Dashboard = page(() => import('./pages/Dashboard'), 'Dashboard');
const Violations = page(() => import('./pages/violations'), 'Violations');
const Compliance = page(() => import('./pages/compliance'), 'Compliance');
const VulnMgmt = page(() => import('./pages/vuln/VulnMgmt'), 'VulnMgmt');
const ConfigMgmt = page(() => import('./pages/ConfigMgmt'), 'ConfigMgmt');
const Risk = page(() => import('./pages/risk'), 'Risk');
const PolicyMgmt = page(() => import('./pages/PolicyMgmt'), 'PolicyMgmt');
const SystemHealth = page(() => import('./pages/SystemHealth'), 'SystemHealth');
const NetworkRuntime = page(() => import('./pages/network/NetworkPolicy'), 'NetworkRuntime');
const MyProfile = page(() => import('./pages/MyProfile'), 'MyProfile');
const Audit = page(() => import('./pages/audit'), 'Audit');
const AuditLogs = page(() => import('./pages/auditlogs'), 'AuditLogs');
const AlertLog = page(() => import('./pages/alertlog'), 'AlertLog');
const Alerts = page(() => import('./pages/alerts'), 'Alerts');
const Honeypot = page(() => import('./pages/honeypot'), 'Honeypot');
const SBOM = page(() => import('./pages/sbom'), 'SBOM');
const Forensics = page(() => import('./pages/forensics'), 'Forensics');
const Tracepoints = page(() => import('./pages/tracepoints'), 'Tracepoints');
const Syscalls = page(() => import('./pages/syscalls'), 'Syscalls');
const Lsm = page(() => import('./pages/lsm'), 'Lsm');
const RBAC = page(() => import('./pages/rbac'), 'RBAC');
const Settings = page(() => import('./pages/Settings'), 'Settings');

function AuthedShell() {
  return (
    <ClusterProvider>
      <ClusteredShell />
    </ClusterProvider>
  );
}

function ClusteredShell() {
  const { current } = useClusters();
  return (
    <BridgeProvider key={current}>
      <ScannerProvider>
        <SensorProvider>
          <div className="layout">
            <Sidebar />
            <div className="shell-main">
            <Topbar />
            <ClusterBanner />
            <main className="main">
              <RouteErrorBoundary>
              <Suspense fallback={<div className="page-loading">Loading…</div>}>
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
                <Route path="/auditlogs"   element={<AuditLogs />} />
                <Route path="/alertlog"    element={<AlertLog />} />
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
              </Suspense>
              </RouteErrorBoundary>
            </main>
            </div>
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
