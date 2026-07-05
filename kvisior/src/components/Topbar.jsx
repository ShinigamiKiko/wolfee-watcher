import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePerms } from '../context/PermissionsContext';
import '../assets/logo/logo.scss';

export function Topbar() {
  const navigate = useNavigate();
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
        <div className="logo-icon" role="img" aria-label="Wolf Vision" />
        <div className="logo-text">Wolf<span>Vision</span></div>
        <span style={{fontSize:10,fontWeight:600,color:'var(--text-muted)',letterSpacing:'.04em',marginLeft:6,opacity:.6}}>v1.0</span>
      </div>
      <div className="topbar-divider" />
      <div className="topbar-right">
        <div className="dropdown-wrap" ref={ref}>
          <div className="user-btn" onClick={() => setMenuOpen(v => !v)}>
            <div className="user-avatar">{initials}</div>
            <span className="user-name">{username}@cluster</span>
            <span style={{fontSize:10,color:'var(--text-muted)'}}>▾</span>
          </div>
          <div className={`dropdown-menu ${menuOpen ? 'open' : ''}`}>
            <div className="dropdown-user-info">
              <div className="dropdown-name">{fullName}</div>
              <div className="dropdown-email">{email}</div>
              <div className="dropdown-role">{role === 'admin' ? 'Admin' : 'Read-Only'}{me?.group_name ? ` · ${me.group_name}` : ''}</div>
            </div>
            <div className="dropdown-divider" />
            <div className="dropdown-item" onClick={() => { navigate('/profile'); setMenuOpen(false); }}>👤 My profile</div>
            <div className="dropdown-divider" />
            <div className="dropdown-item" style={{color:'var(--danger)'}} onClick={handleLogout}>⏏ Log out</div>
          </div>
        </div>
      </div>
    </header>
  );
}
