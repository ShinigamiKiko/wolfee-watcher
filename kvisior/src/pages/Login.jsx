import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { usePerms } from '../context/PermissionsContext';
import '../assets/logo/logo.scss';
import '../styles/login.scss';

const REMEMBER_KEY = 'sw_remember_user';

function IconUser() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  );
}

function IconLock() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

function IconEye({ off }) {
  return off ? (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </svg>
  ) : (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

function IconShield() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

export function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { signIn } = usePerms();
  const [username, setUsername] = useState(() => localStorage.getItem(REMEMBER_KEY) || '');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(() => !!localStorage.getItem(REMEMBER_KEY));
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e?.preventDefault?.();
    if (!username || !password) { setError('Username and password required'); return; }
    setBusy(true); setError(null);
    try {
      await signIn(username, password);
      if (remember) localStorage.setItem(REMEMBER_KEY, username);
      else localStorage.removeItem(REMEMBER_KEY);
      const next = location.state?.from || '/';
      navigate(next, { replace: true });
    } catch (e) {
      setError(String(e.message || e) || 'Login failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <div className="login__stars" aria-hidden="true" />
      <div className="login__grid" aria-hidden="true" />

      <div className="login__status" aria-hidden="true">
        System secure<br />
        Encryption: on<br />
        Status: active
      </div>

      <form className="login__card" onSubmit={submit}>
        <div className="logo-icon logo-icon--lg login__logo" role="img" aria-label="wolfee-watcher" />

        <h1 className="login__title">wolfee<span>-watcher</span></h1>
        <p className="login__sub">Sign in to continue</p>

        <div className="login__field">
          <label className="login__label" htmlFor="login-username">Username</label>
          <div className="login__wrap">
            <span className="login__icon"><IconUser /></span>
            <input
              id="login-username"
              className="login__input"
              type="text"
              autoFocus
              autoComplete="username"
              placeholder="Enter your username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              disabled={busy}
            />
          </div>
        </div>

        <div className="login__field">
          <label className="login__label" htmlFor="login-password">Password</label>
          <div className="login__wrap">
            <span className="login__icon"><IconLock /></span>
            <input
              id="login-password"
              className="login__input"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
              placeholder="Enter your password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              disabled={busy}
            />
            <button
              type="button"
              className="login__eye"
              onClick={() => setShowPassword(v => !v)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              tabIndex={-1}
            >
              <IconEye off={showPassword} />
            </button>
          </div>
        </div>

        <label className="login__remember">
          <input
            className="login__checkbox"
            type="checkbox"
            checked={remember}
            onChange={e => setRemember(e.target.checked)}
          />
          Remember me
        </label>

        {error && <div className="login__error">{error}</div>}

        <button type="submit" className="login__btn" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>

        <div className="login__divider" />

        <div className="login__footer">
          <IconShield />
          Secured by <b>Wolfee Security</b>
        </div>
      </form>
    </div>
  );
}
