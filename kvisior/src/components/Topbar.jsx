import { apiFetch } from '../data/cluster';
import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePerms } from '../context/PermissionsContext';
import { ClusterPicker } from './ClusterPicker';
import '../assets/logo/logo.scss';
import { Icon } from './Icon';

export function Topbar() {
  const navigate = useNavigate();
  const { me, signOut } = usePerms();
  const [menuOpen, setMenuOpen] = useState(false);
  const [version, setVersion] = useState('');
  const ref = useRef(null);

  useEffect(() => {
    let cancelled = false;
    apiFetch('/v1/version', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (!cancelled && d?.version) setVersion(d.version); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const handleLogout = async () => {
    setMenuOpen(false);
    await signOut();
    navigate('/login', { replace: true });
  };

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setMenuOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const username = me?.username || 'admin';
  const fullName = me?.full_name || username;
  const email    = me?.email || `${username}@cluster.local`;
  const role     = me?.effective_role || 'admin';
  const initials = (fullName || username).split(/\s+/).map(s => s[0]).join('').slice(0,2).toUpperCase();

  return (
    <header className="topbar">
      <div className="logo" onClick={() => navigate('/')}>
        <div className="logo-icon" role="img" aria-label="wolfee-watcher" />
        <div className="logo-text">wolfee<span>-watcher</span></div>
        {version && (
          <span className="logo-version">v{version}</span>
        )}
      </div>
      <div className="topbar-divider" />
      <ClusterPicker />
      <div className="topbar-right">
        <div className="dropdown-wrap" ref={ref}>
          <div className="user-btn" onClick={() => setMenuOpen(v => !v)}>
            <div className="user-avatar">{initials}</div>
            <span className="user-name">{username}@cluster</span>
            <Icon name="chevron-down" className="t-muted" />
          </div>
          <div className={`dropdown-menu ${menuOpen ? 'open' : ''}`}>
            <div className="dropdown-user-info">
              <div className="dropdown-name">{fullName}</div>
              <div className="dropdown-email">{email}</div>
              <div className="dropdown-role">{role === 'admin' ? 'Admin' : 'Read-Only'}{me?.group_name ? ` · ${me.group_name}` : ''}</div>
            </div>
            <div className="dropdown-divider" />
            <div className="dropdown-item" onClick={() => { navigate('/profile'); setMenuOpen(false); }}><Icon name="user" /> My profile</div>
            <div className="dropdown-divider" />
            <div className="dropdown-item t-danger" onClick={handleLogout}><Icon name="escape" /> Log out</div>
          </div>
        </div>
      </div>
    </header>
  );
}
