import { apiFetch } from '../../data/cluster';

export async function safeFetch(url) {
  const res = await apiFetch(url, { credentials: 'same-origin' });
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    const preview = text.slice(0, 120).replace(/\s+/g, ' ').trim();
    return { error: `Server returned non-JSON response: ${preview}` };
  }
}

function isPod(item) {
  if (!item?.raw) return false;
  const kind = item.raw.kind || '';
  const sub  = (item.sub || '').toLowerCase();
  return kind === 'Pod' || sub.startsWith('pod ') || sub === 'pod';
}
function isNode(item) {
  if (!item?.raw) return false;
  const kind = item.raw.kind || '';
  const sub  = (item.sub || '').toLowerCase();
  return kind === 'Node' || sub.startsWith('node ') || sub === 'node';
}
function getContainers(raw) {
  return (raw?.spec?.containers || []).map(c => c.name).filter(Boolean);
}

function logLevel(line) {
  const ll = line.toLowerCase();
  if (ll.includes('error') || ll.includes('fatal') || ll.includes('panic')) return 'log-line--error';
  if (ll.includes('warn')) return 'log-line--warn';
  if (ll.includes('info') || /^\d{4}-\d{2}-\d{2}/.test(line)) return 'log-line--info';
  return undefined;
}

function colorizeLog(raw) {
  if (!raw) return null;
  return raw.split('\n').map((line, i) => <div key={i} className={logLevel(line)}>{line || ' '}</div>);
}

export { isPod, isNode, getContainers, colorizeLog };
