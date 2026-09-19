const STORAGE_KEY = 'ww.cluster';
const DEFAULT_CLUSTER = 'default';

let current = DEFAULT_CLUSTER;
try {
  const saved = window.localStorage.getItem(STORAGE_KEY);
  if (saved) current = saved;
} catch { /* private mode */ }

const listeners = new Set();

export function getCluster() {
  return current;
}

export function setCluster(id) {
  if (!id || id === current) return;
  current = id;
  try { window.localStorage.setItem(STORAGE_KEY, id); } catch { /* private mode */ }
  listeners.forEach(fn => fn(id));
}

export function onClusterChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function apiFetch(url, opts = {}) {
  const headers = { ...(opts.headers || {}), 'X-Cluster-ID': current };
  return fetch(url, { credentials: 'same-origin', ...opts, headers });
}

export function sseUrl(path) {
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}cluster=${encodeURIComponent(current)}`;
}

export async function listClusters() {
  const r = await apiFetch('/api/clusters');
  if (!r.ok) throw new Error(`clusters: HTTP ${r.status}`);
  const data = await r.json();
  return {
    clusters: data.clusters || [],
    local: data.local || DEFAULT_CLUSTER,
  };
}

export async function saveCluster(body) {
  const r = await apiFetch('/api/clusters', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`save cluster: HTTP ${r.status}`);
}

export async function deleteCluster(id) {
  const r = await apiFetch(`/api/clusters/${encodeURIComponent(id)}`, { method: 'DELETE' });
  if (!r.ok) throw new Error(`delete cluster: HTTP ${r.status}`);
}
