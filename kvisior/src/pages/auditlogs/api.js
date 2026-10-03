import { apiFetch } from '../../data/cluster';

async function parse(res) {
  if (res.status === 204) return null;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return body;
}

function query(params) {
  const parts = [];
  for (const [key, value] of Object.entries(params || {})) {
    if (value === '' || value == null || value === false) continue;
    parts.push(`${key}=${encodeURIComponent(value === true ? 1 : value)}`);
  }
  return parts.length ? `?${parts.join('&')}` : '';
}

function send(method, url, body) {
  return apiFetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  }).then(parse);
}

export const fetchEvents  = params => apiFetch(`/v1/audit/events${query(params)}`).then(parse);
export const fetchSummary = params => apiFetch(`/v1/audit/summary${query(params)}`).then(parse);
export const fetchGroups  = params => apiFetch(`/v1/audit/groups${query(params)}`).then(parse);
export const fetchSources = ()     => apiFetch('/v1/audit/sources').then(parse);
export const fetchRules   = ()     => apiFetch('/api/audit/rules').then(parse);

export const createRule   = rule        => send('POST', '/api/audit/rules', rule);
export const updateRule   = (id, rule)  => send('PUT', `/api/audit/rules/${encodeURIComponent(id)}`, rule);
export const patchRule    = (id, flags) => send('PATCH', `/api/audit/rules/${encodeURIComponent(id)}`, flags);
export const deleteRule   = id          => send('DELETE', `/api/audit/rules/${encodeURIComponent(id)}`);
export const restoreRules = ()          => send('POST', '/api/audit/rules/restore');
