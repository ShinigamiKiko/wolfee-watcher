
const BASE = '/scanner';

export async function listImages() {
  const r = await fetch(`${BASE}/images`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`images: HTTP ${r.status}`);
  return r.json();
}

export async function getResults() {
  const r = await fetch(`${BASE}/results`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`results: HTTP ${r.status}`);
  return r.json();
}

export async function getHistories() {
  const r = await fetch(`${BASE}/histories`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`histories: HTTP ${r.status}`);
  return r.json();
}

export async function getImageResult(ref) {
  const r = await fetch(`${BASE}/results?image=${encodeURIComponent(ref)}`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`result: HTTP ${r.status}`);
  return r.json();
}

export async function triggerScan(images = []) {
  const r = await fetch(`${BASE}/scan`, {
    method:      'POST',
    credentials: 'same-origin',
    headers:     { 'Content-Type': 'application/json' },
    body:        JSON.stringify({ images }),
  });
  if (r.status === 409) throw new Error('Scan already in progress');
  if (!r.ok) throw new Error(`scan: HTTP ${r.status}`);
  return r.json();
}

export async function stopScan() {
  const r = await fetch(`${BASE}/scan/stop`, { method: 'POST', credentials: 'same-origin' });
  if (!r.ok) throw new Error(`stop: HTTP ${r.status}`);
  return r.json();
}

export async function scannerHealth() {
  const r = await fetch(`${BASE}/health`, { credentials: 'same-origin' });
  if (!r.ok) return null;
  return r.json();
}

export function subscribeScanStream(onEvent) {
  const es = new EventSource(`${BASE}/stream`);
  es.onmessage = (e) => {
    try { onEvent(JSON.parse(e.data)); }
    catch {}
  };
  es.onerror = () => es.close();
  return () => es.close();
}

export function epssLabel(score) {
  const pct = (score * 100).toFixed(2) + '%';
  if (score >= 0.5) return { text: pct, color: 'var(--danger)' };
  if (score >= 0.1) return { text: pct, color: 'var(--warning)' };
  return { text: pct, color: 'var(--text-muted)' };
}

export function sevColor(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'var(--danger)';
    case 'HIGH':     return 'var(--warning)';
    case 'MEDIUM':   return '#a78bfa';
    case 'LOW':      return 'var(--accent-3)';
    default:         return 'var(--text-muted)';
  }
}

export function sortByRisk(cves) {
  return [...cves].sort((a, b) => {
    if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
    return b.cvssV3Score - a.cvssV3Score;
  });
}

export function fmtDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms/1000).toFixed(1)}s`;
  return `${Math.floor(ms/60000)}m ${Math.floor((ms%60000)/1000)}s`;
}

export async function getSchedule() {
  const r = await fetch(`${BASE}/schedule`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`schedule: HTTP ${r.status}`);
  return r.json();
}

export async function saveSchedule(schedule) {
  const r = await fetch(`${BASE}/schedule`, {
    method:      'PUT',
    credentials: 'same-origin',
    headers:     { 'Content-Type': 'application/json' },
    body:        JSON.stringify(schedule),
  });
  if (!r.ok) throw new Error(`schedule: HTTP ${r.status}`);
  return r.json();
}
