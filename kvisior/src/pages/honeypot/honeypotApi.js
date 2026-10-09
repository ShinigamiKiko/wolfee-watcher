import { apiFetch } from '../../data/cluster';

async function failure(r, what) {
  let msg = '';
  try {
    const body = await r.json();
    msg = body?.error || '';
  } catch {}
  return new Error(msg || `${what}: HTTP ${r.status}`);
}

async function apiList() {
  const r = await apiFetch('/honey/api/honeypots', { credentials: 'same-origin' });
  if (!r.ok) throw await failure(r, 'list');
  return r.json();
}

async function apiCreate(spec) {
  const r = await apiFetch('/honey/api/honeypots', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(spec),
  });
  if (!r.ok) throw await failure(r, 'create');
  return r.json();
}

async function apiDelete(name, ns) {
  const r = await apiFetch(`/honey/api/honeypots/${encodeURIComponent(name)}?namespace=${encodeURIComponent(ns)}`, {
    method: 'DELETE',
    credentials: 'same-origin',
  });
  if (!r.ok) throw await failure(r, 'delete');
  return r.json();
}

async function apiEvents(name, ns) {
  const r = await apiFetch(`/honey/api/honeypots/${encodeURIComponent(name)}/events?namespace=${encodeURIComponent(ns)}`, {
    credentials: 'same-origin',
  });
  if (!r.ok) throw await failure(r, 'events');
  return r.json();
}

async function apiPersistedEvents(name, ns) {
  const r = await apiFetch(`/v1/honeypot-events?ns=${encodeURIComponent(ns)}&name=${encodeURIComponent(name)}`, {
    credentials: 'same-origin',
  });
  if (!r.ok) throw await failure(r, 'persisted');
  return r.json();
}

async function apiHideEvent(name, ns, id) {
  const r = await apiFetch('/v1/honeypot-hidden', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ ns, name, id }),
  });
  if (!r.ok) throw await failure(r, 'hide');
}

async function apiHiddenEvents(name, ns) {
  const r = await apiFetch(`/v1/honeypot-hidden?ns=${encodeURIComponent(ns)}&name=${encodeURIComponent(name)}`, {
    credentials: 'same-origin',
  });
  if (!r.ok) throw await failure(r, 'hidden');
  return r.json();
}

export { apiList, apiCreate, apiDelete, apiEvents, apiPersistedEvents, apiHideEvent, apiHiddenEvents };
