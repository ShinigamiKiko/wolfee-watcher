import { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { apiFetch } from '../data/cluster';
import { Icon } from './Icon';
import '../assets/logo/logo.scss';

export const SECTIONS = [
  {
    label: 'Overview',
    items: [
      { id: 'dashboard',  label: 'Dashboard' },
    ],
  },
  {
    label: 'Security',
    items: [
      { id: 'violations', label: 'Violations' },
      { id: 'compliance', label: 'Compliance' },
      { id: 'audit',      label: 'Audit' },
      { id: 'auditlogs',  label: 'Audit logs' },
      { id: 'alertlog',   label: 'Alert Log' },
      { id: 'honeypot',   label: 'Honeypot' },
      { id: 'alerts',     label: 'Anomaly' },
      { id: 'forensics',  label: 'Forensics' },
      { id: 'rbac',       label: 'RBAC' },
    ],
  },
  {
    label: 'Network',
    items: [
      { id: 'net-runtime', label: 'Network Runtime' },
    ],
  },
  {
    label: 'Management',
    items: [
      { id: 'vulnmgmt',   label: 'Vulnerability Mgmt' },
      { id: 'configmgmt', label: 'Configuration Mgmt' },
      { id: 'risk',       label: 'Risk' },
      { id: 'policymgmt', label: 'Policy Management' },
    ],
  },
  {
    label: 'Platform',
    items: [
      { id: 'syshealth',  label: 'System Health' },
      { id: 'settings',   label: 'Settings' },
    ],
  },
];

const EXTRA_TITLES = { profile: 'My Profile', syscalls: 'Syscalls', tracepoints: 'Tracepoints', lsm: 'LSM Hooks', sbom: 'SBOM' };

export const itemPath = id => (id === 'dashboard' ? '/' : `/${id}`);

export function pageTitle(pathname) {
  const id = pathname === '/' ? 'dashboard' : pathname.split('/')[1];
  for (const s of SECTIONS) {
    const hit = s.items.find(i => i.id === id);
    if (hit) return hit.label;
  }
  return EXTRA_TITLES[id] || '';
}

const COLLAPSE_KEY = 'kvisior.sidebar.collapsed';

const readCollapsed = () => {
  try { return localStorage.getItem(COLLAPSE_KEY) === '1'; } catch { return false; }
};

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [version, setVersion] = useState('');
  const location = useLocation();

  useEffect(() => {
    let cancelled = false;
    apiFetch('/v1/version', { credentials: 'same-origin' })
      .then(r => (r.ok ? r.json() : null))
      .then(d => { if (!cancelled && d?.version) setVersion(d.version); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    try { localStorage.setItem(COLLAPSE_KEY, collapsed ? '1' : '0'); } catch {}
  }, [collapsed]);

  const isActive = id => location.pathname === itemPath(id);

  return (
    <nav className={`sidebar${collapsed ? ' sidebar--collapsed' : ''}`} aria-label="Main navigation">
      <Link to="/" className="sb-brand" title="wolfee-watcher">
        <span className="logo-icon" role="img" aria-label="wolfee-watcher" />
        <span className="sb-brand-text">WOLFEE-WATCHER</span>
        {version && <span className="sb-version">v{version}</span>}
      </Link>

      <ul className="nav-list">
        {SECTIONS.map(section => (
          <li key={section.label} className="nav-section">
            <div className="nav-section-label">{section.label}</div>
            <ul>
              {section.items.map(item => (
                <li key={item.id}>
                  <Link to={itemPath(item.id)} title={collapsed ? item.label : undefined}
                    className={`nav-item${isActive(item.id) ? ' active' : ''}`}
                    aria-current={isActive(item.id) ? 'page' : undefined}>
                    <Icon name={`nav-${item.id}`} size={18} />
                    <span className="nav-label">{item.label}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>

      <div className="sidebar-footer">
        <Link to="/profile" title={collapsed ? 'My Profile' : undefined}
          className={`nav-item${location.pathname === '/profile' ? ' active' : ''}`}>
          <Icon name="nav-profile" size={18} />
          <span className="nav-label">My Profile</span>
        </Link>
        <button type="button" className="nav-item sb-collapse" onClick={() => setCollapsed(c => !c)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-expanded={!collapsed}>
          <Icon name="chevron-left" size={17} />
          <span className="nav-label">Collapse</span>
        </button>
      </div>
    </nav>
  );
}
