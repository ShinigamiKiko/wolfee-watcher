async function apiGetSilents() {
  const res = await fetch('/anomaly/api/silents', { credentials: 'same-origin' });
  if (!res.ok) throw new Error(`silents: ${res.status}`);
  const data = await res.json();
  return data.items || [];
}

async function apiPostSilent(type, key, summary) {
  const res = await fetch('/anomaly/api/silents', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body:    JSON.stringify({ type, key, summary }),
  });
  if (!res.ok) throw new Error(`silents POST: ${res.status}`);
}

async function apiDeleteSilent(type, key) {
  const res = await fetch(`/anomaly/api/silents?type=${encodeURIComponent(type)}&key=${encodeURIComponent(key)}`, {
    method: 'DELETE',
    credentials: 'same-origin',
  });
  if (!res.ok) throw new Error(`silents DELETE: ${res.status}`);
}

async function apiDeleteAnomaly(id) {
  const res = await fetch(`/anomaly/api/anomalies/delete?id=${encodeURIComponent(id)}`, {
    method: 'POST',
    credentials: 'same-origin',
  });
  if (!res.ok) throw new Error(`anomaly DELETE: ${res.status}`);
}

async function apiSilenceAnomaly(id) {
  const res = await fetch(`/anomaly/api/anomalies/silence?id=${encodeURIComponent(id)}`, {
    method: 'POST',
    credentials: 'same-origin',
  });
  if (!res.ok) throw new Error(`anomaly silence: ${res.status}`);
}

async function apiUnsilenceAnomaly(id) {
  const res = await fetch(`/anomaly/api/anomalies/unsilence?id=${encodeURIComponent(id)}`, {
    method: 'POST',
    credentials: 'same-origin',
  });
  if (!res.ok) throw new Error(`anomaly unsilence: ${res.status}`);
}

async function apiGetSilentAnomalies() {
  const res = await fetch('/anomaly/api/anomalies/silent', { credentials: 'same-origin' });
  if (!res.ok) throw new Error(`silent anomalies: ${res.status}`);
  const data = await res.json();
  return data.events || [];
}

async function apiIngestAnomaly(ev) {
  const res = await fetch('/anomaly/api/anomalies/ingest', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body:    JSON.stringify(ev),
  });
  if (!res.ok) throw new Error(`anomaly ingest: ${res.status}`);
  const data = await res.json();
  return data.id;
}

export {
  apiGetSilents, apiPostSilent, apiDeleteSilent, apiDeleteAnomaly,
  apiSilenceAnomaly, apiUnsilenceAnomaly, apiGetSilentAnomalies, apiIngestAnomaly,
};
