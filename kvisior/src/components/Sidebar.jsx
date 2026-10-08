import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Icon, ICONS } from './Icon';

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
      { id: 'auditlogs',  label: 'Audit logs' },
      { id: 'alertlog',   label: 'Alert Log' },
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
      <ul className="nav-list">
        {SECTIONS.map(section => (
          <div key={section.label} className="nav-section">
            <div className="nav-section-label">{section.label}</div>
            {section.items.map(item => {
              const to = getItemPath(item.id);

              return (
                <li key={item.id}>
                  <Link
                    to={to}
                    className={`nav-item${isActive(item.id) ? ' active' : ''}`}
                  >
                    <span className="nav-icon">
                      <Icon name={ICONS[item.id] ? item.id : 'dashboard'} size={16} />
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
        <li>
          <Link
            to="/profile"
            className={`nav-item${location.pathname === '/profile' ? ' active' : ''}`}
          >
            <span className="nav-icon"><Icon name="profile" size={16} /></span>
            <span className="nav-label">My Profile</span>
          </Link>
        </li>
      </div>
    </nav>
  );
}
