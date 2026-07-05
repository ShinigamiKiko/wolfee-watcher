import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { usePerms } from '../context/PermissionsContext';
import '../assets/logo/logo.scss';

export function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { signIn } = usePerms();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e?.preventDefault?.();
    if (!username || !password) { setError('Username and password required'); return; }
    setBusy(true); setError(null);
    try {
      await signIn(username, password);
      const next = location.state?.from || '/';
      navigate(next, { replace: true });
    } catch (e) {
      setError(String(e.message || e) || 'Login failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-base)',
      padding: 20,
    }}>
      <form onSubmit={submit} style={{
        width: '100%',
        maxWidth: 380,
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border)',
        borderRadius: 12,
        padding: 32,
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}>
        <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:8}}>
          <div className="logo-icon logo-icon--md" role="img" aria-label="WolfVision" />
          <div>
            <div style={{fontSize:18,fontWeight:700,color:'var(--text-primary)'}}>WolfVision</div>
            <div style={{fontSize:11,color:'var(--text-muted)'}}>Sign in to continue</div>
          </div>
        </div>

        <div>
          <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>Username</label>
          <input
            type="text"
            autoFocus
            autoComplete="username"
            value={username}
            onChange={e => setUsername(e.target.value)}
            disabled={busy}
            style={{width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:8,padding:'10px 12px',fontSize:13,color:'var(--text-primary)',outline:'none',fontFamily:'DM Sans,sans-serif'}}
          />
        </div>

        <div>
          <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>Password</label>
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            disabled={busy}
            style={{width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:8,padding:'10px 12px',fontSize:13,color:'var(--text-primary)',outline:'none',fontFamily:'DM Sans,sans-serif'}}
          />
        </div>

        {error && (
          <div style={{fontSize:12,padding:'8px 10px',borderRadius:6,background:'rgba(239,68,68,.1)',border:'1px solid rgba(239,68,68,.3)',color:'var(--danger)'}}>
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={busy}
          className="btn btn-primary"
          style={{marginTop:4,opacity:busy?0.6:1,cursor:busy?'wait':'pointer'}}
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
