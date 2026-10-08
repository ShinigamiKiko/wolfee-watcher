import { useState, useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { usePerms } from '../context/PermissionsContext';
import { ClusterPicker } from './ClusterPicker';
import { pageTitle } from './Sidebar';
import { Icon } from './Icon';

export function Topbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const { me, signOut } = usePerms();
  const [menuOpen, setMenuOpen] = useState(false);
  const ref = useRef(null);

  const handleLogout = async () => {
    setMenuOpen(false);
    await signOut();
    navigate('/login', { replace: true });
  };

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setMenuOpen(false); };
    const esc = (e) => { if (e.key === 'Escape') setMenuOpen(false); };
    document.addEventListener('mousedown', handler);
    document.addEventListener('keydown', esc);
    return () => { document.removeEventListener('mousedown', handler); document.removeEventListener('keydown', esc); };
  }, []);

  const username = me?.username || 'admin';
  const fullName = me?.full_name || username;
  const email    = me?.email || `${username}@cluster.local`;
  const role     = me?.effective_role || 'admin';
  const initials = (fullName || username).split(/\s+/).map(s => s[0]).join('').slice(0,2).toUpperCase();

  return (
    <header className="topbar">
      <h1 className="topbar-title">{pageTitle(location.pathname)}</h1>
      <div className="topbar-right">
        <ClusterPicker />
        <div className="dropdown-wrap" ref={ref}>
          <button type="button" className="user-btn" onClick={() => setMenuOpen(v => !v)} aria-haspopup="menu" aria-expanded={menuOpen}>
            <span className="user-avatar">{initials}</span>
            <span className="user-name">{username}</span>
            <Icon name="chevron-down" className="t-muted" />
          </button>
          <div className={`dropdown-menu ${menuOpen ? 'open' : ''}`} role="menu">
            <div className="dropdown-user-info">
              <div className="dropdown-name">{fullName}</div>
              <div className="dropdown-email">{email}</div>
            </div>
            <div className="dropdown-divider" />
            <button type="button" role="menuitem" className="dropdown-item" onClick={() => { navigate('/profile'); setMenuOpen(false); }}><Icon name="user" /> My profile</button>
            <button type="button" role="menuitem" className="dropdown-item t-danger" onClick={handleLogout}><Icon name="log-out" /> Sign out</button>
          </div>
        </div>
        <span className={`role-pill${role === 'admin' ? '' : ' role-pill--ro'}`}>{role === 'admin' ? 'admin' : 'read-only'}{me?.group_name ? ` · ${me.group_name}` : ''}</span>
      </div>
    </header>
  );
}
