import { actingHeaders } from '../../context/PermissionsContext';

export async function apiJSON(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    credentials: 'same-origin',
    headers: actingHeaders({
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

export const formatDate = (d) => d
  ? new Date(d).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' })
  : '—';
