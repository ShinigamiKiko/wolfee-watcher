import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';

const Icon = ({ d, size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    {Array.isArray(d) ? d.map((p,i) => <path key={i} d={p}/>) : <path d={d}/>}
  </svg>
);

const ICONS = {
  dashboard:  ['M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z','M9 22V12h6v10'],
  violations: 'M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01',
  compliance: 'M22 11.08V12a10 10 0 11-5.93-9.14M22 4L12 14.01l-3-3',
  vulnmgmt:   ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'],
  configmgmt: ['M12 2L2 7l10 5 10-5-10-5z','M2 17l10 5 10-5','M2 12l10 5 10-5'],
  risk:       ['M18 20V10','M12 20V4','M6 20v-6'],
  policymgmt: ['M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z','M14 2v6h6','M16 13H8','M16 17H8','M10 9H8'],
  syshealth:  'M22 12h-4l-3 9L9 3l-3 9H2',
  audit:      ['M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'],
  honeypot:   'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14H9V8h2v8zm4 0h-2V8h2v8z',
  forensics:  ['M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18'],
  syscalls:   ['M4 17l6-5-6-5','M12 19h8'],
  tracepoints:['M3 12h4l3 8 4-16 3 8h4'],
  lsm:        ['M5 11h14a1 1 0 011 1v8a1 1 0 01-1 1H5a1 1 0 01-1-1v-8a1 1 0 011-1z','M8 11V7a4 4 0 018 0v4','M12 15v3'],
  sbom:       ['M20 7H4a2 2 0 00-2 2v10a2 2 0 002 2h16a2 2 0 002-2V9a2 2 0 00-2-2z','M16 3H8L4 7h16l-4-4z','M8 12h8M8 15h5'],
  rbac:       ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z','M9 12l2 2 4-4'],
  alerts:     ['M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9','M13.73 21a2 2 0 01-3.46 0'],
  settings:   ['M12 15a3 3 0 100-6 3 3 0 000 6z','M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z'],
  profile:    ['M20 21a8 8 0 00-16 0','M12 11a4 4 0 100-8 4 4 0 000 8z'],
};

const SECTIONS = [
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
      { id: 'honeypot',   label: 'Honeypot' },
      { id: 'alerts', label: 'Anomaly' },
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

export function Sidebar() {
  const [expanded, setExpanded] = useState(false);
  const location = useLocation();

  const getItemPath = (id) => (id === 'dashboard' ? '/' : `/${id}`);
  const isActive = (id) => location.pathname === getItemPath(id);

  return (
    <nav
      className={`sidebar${expanded ? ' sidebar-expanded' : ''}`}
      onMouseEnter={() => setExpanded(true)}
      onMouseLeave={() => setExpanded(false)}
    >
      <ul style={{ listStyle:'none', padding:0, margin:0, flex:1 }}>
        {SECTIONS.map(section => (
          <div key={section.label} className="nav-section">
            <div className="nav-section-label">{section.label}</div>
            {section.items.map(item => {
              const to = getItemPath(item.id);

              return (
                <li key={item.id} style={{ listStyle:'none' }}>
                  <Link
                    to={to}
                    className={`nav-item${isActive(item.id) ? ' active' : ''}`}
                  >
                    <span className="nav-icon">
                      <Icon d={ICONS[item.id] || ICONS.dashboard} />
                    </span>
                    <span className="nav-label">{item.label}</span>
                  </Link>
                </li>
              );
            })}
          </div>
        ))}
      </ul>

      <div className="sidebar-footer">
        <li style={{ listStyle:'none' }}>
          <Link
            to="/profile"
            className={`nav-item${location.pathname === '/profile' ? ' active' : ''}`}
          >
            <span className="nav-icon"><Icon d={ICONS.profile} /></span>
            <span className="nav-label">My Profile</span>
          </Link>
        </li>
      </div>
    </nav>
  );
}
