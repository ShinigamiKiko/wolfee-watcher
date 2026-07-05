
export function fmtTs(ts) {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2,'0');
  const mm = String(d.getMinutes()).padStart(2,'0');
  const ss = String(d.getSeconds()).padStart(2,'0');
  const ms = String(d.getMilliseconds()).padStart(3,'0');
  return { time: `${hh}:${mm}:${ss}`, ms: `.${ms}` };
}

export function relTime(ts) {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
}

function fmtDate(d) {
  return d ? `${d.toLocaleDateString()} ${d.toLocaleTimeString()}` : '';
}

export function fmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
}

export function fmtDateOnly(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? '—' : d.toLocaleDateString('ru-RU');
}
export function fmtClock(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? '—' : d.toLocaleTimeString('ru-RU');
}
export function fmtDateTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? '—' : `${d.toLocaleDateString('ru-RU')} ${d.toLocaleTimeString('ru-RU')}`;
}

export function podName(p)       { return p?.metadata?.name      || p?.name      || ''; }
export function podNS(p)         { return p?.metadata?.namespace || p?.namespace || ''; }
export function podContainers(p) { return (p?.spec?.containers || []).map(c => c.name).filter(Boolean); }
