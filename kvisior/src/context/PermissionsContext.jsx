import { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react';

const PermCtx = createContext(null);
export const usePerms = () => useContext(PermCtx);

export function actingHeaders(extra = {}) {
  return { ...extra };
}

async function jsonOrThrow(res) {
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return body;
}

export function PermissionsProvider({ children }) {
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/auth/me', { credentials: 'same-origin' });
      if (res.status === 401) {
        setMe(null);
        setError(null);
        return;
      }
      const body = await jsonOrThrow(res);
      setMe(body);
      setError(null);
    } catch (e) {
      setMe(null);
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
    const t = setInterval(reload, 10 * 60 * 1000);
    return () => clearInterval(t);
  }, [reload]);

  useEffect(() => {
    const handler = () => setMe(null);
    window.addEventListener('sw-auth-failed', handler);
    return () => window.removeEventListener('sw-auth-failed', handler);
  }, []);

  const signIn = useCallback(async (username, password) => {
    const res = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ username, password }),
    });
    const body = await jsonOrThrow(res);
    setMe(body);
    setError(null);
    return body;
  }, []);

  const signOut = useCallback(async () => {
    try {
      await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
    } catch { }
    setMe(null);
  }, []);

  const value = useMemo(() => {
    const perms = me?.permissions || {};
    return {
      me,
      loading,
      error,
      reload,
      signIn,
      signOut,
      can: (key) => !!perms[key],
      role: me?.effective_role || null,
      isAdmin: me?.effective_role === 'admin',
      authenticated: !!me,
    };
  }, [me, loading, error, reload, signIn, signOut]);

  return <PermCtx.Provider value={value}>{children}</PermCtx.Provider>;
}
