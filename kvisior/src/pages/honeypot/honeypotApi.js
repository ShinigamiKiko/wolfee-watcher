
async function apiList() {
  const r = await fetch('/honey/api/honeypots', { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`list: HTTP ${r.status}`);
  return r.json();
}

async function apiCreate(spec) {
  const r = await fetch('/honey/api/honeypots', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(spec),
  });
  if (!r.ok) throw new Error(`create: HTTP ${r.status}`);
  return r.json();
}

async function apiDelete(name, ns) {
  const r = await fetch(`/honey/api/honeypots/${name}?namespace=${ns}`, {
    method: 'DELETE',
    credentials: 'same-origin',
  });
  if (!r.ok) throw new Error(`delete: HTTP ${r.status}`);
  return r.json();
}

async function apiEvents(name, ns) {
  const r = await fetch(`/honey/api/honeypots/${name}/events?namespace=${ns}`, {
    credentials: 'same-origin',
  });
  if (!r.ok) throw new Error(`events: HTTP ${r.status}`);
  return r.json();
}

async function apiPersistedEvents(name, ns) {
  const r = await fetch(`/v1/honeypot-events?ns=${encodeURIComponent(ns)}&name=${encodeURIComponent(name)}`, {
    credentials: 'same-origin',
  });
  if (!r.ok) throw new Error(`persisted: HTTP ${r.status}`);
  return r.json();
}

async function apiHideEvent(name, ns, id) {
  const r = await fetch('/v1/honeypot-hidden', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ ns, name, id }),
  });
  if (!r.ok) throw new Error(`hide: HTTP ${r.status}`);
}

async function apiHiddenEvents(name, ns) {
  const r = await fetch(`/v1/honeypot-hidden?ns=${encodeURIComponent(ns)}&name=${encodeURIComponent(name)}`, {
    credentials: 'same-origin',
  });
  if (!r.ok) throw new Error(`hidden: HTTP ${r.status}`);
  return r.json();
}

export { apiList, apiCreate, apiDelete, apiEvents, apiPersistedEvents, apiHideEvent, apiHiddenEvents };
