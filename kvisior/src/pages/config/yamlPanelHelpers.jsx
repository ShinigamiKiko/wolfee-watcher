async function safeFetch(url) {
  const res = await fetch(url, { credentials: 'same-origin' });
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

export const ST = {
  btnLoad: {
    borderRadius: 7, padding: '5px 14px', fontSize: 12, fontWeight: 600,
    cursor: 'pointer', border: 'none', fontFamily: 'DM Sans, sans-serif',
    background: 'linear-gradient(135deg,var(--accent),#0099cc)', color: '#000',
  },
  btnPull: {
    borderRadius: 7, padding: '5px 12px', fontSize: 12, fontWeight: 500,
    cursor: 'pointer', border: '1px solid var(--border-active)',
    fontFamily: 'DM Sans, sans-serif',
    background: 'rgba(0,200,255,.12)', color: 'var(--accent)',
  },
  btnCopy: {
    borderRadius: 7, padding: '5px 10px', fontSize: 12,
    cursor: 'pointer', border: '1px solid var(--border)',
    fontFamily: 'DM Sans, sans-serif',
    background: 'var(--bg-elevated)', color: 'var(--text-muted)',
  },
  dtInput: {
    background: 'var(--bg-elevated)', border: '1px solid var(--border)',
    borderRadius: 7, padding: '4px 8px', fontSize: 11,
    color: 'var(--text-primary)', outline: 'none',
    fontFamily: 'JetBrains Mono, monospace',
    colorScheme: 'dark', cursor: 'pointer',
  },
  dtLabel: {
    fontSize: 10, fontWeight: 600, letterSpacing: '.07em',
    textTransform: 'uppercase', color: 'var(--text-muted)',
    marginBottom: 2, display: 'block',
  },
  logBox: {
    flex: 1, overflowY: 'auto', overflowX: 'auto',
    background: '#080b11', borderRadius: 8, padding: '12px 14px',
    fontSize: 11, lineHeight: 1.75, fontFamily: 'JetBrains Mono, monospace',
    color: 'var(--text-secondary)', whiteSpace: 'pre',
    border: '1px solid var(--border)', minHeight: 160,
  },
  errBox: {
    background: 'rgba(239,68,68,.08)', border: '1px solid rgba(239,68,68,.25)',
    borderRadius: 8, padding: '10px 14px', fontSize: 12, color: '#fc8181',
    fontFamily: 'JetBrains Mono,monospace', marginBottom: 8, flexShrink: 0,
  },
};

function colorizeLog(raw) {
  if (!raw) return null;
  return raw.split('\n').map((line, i) => {
    let color = 'var(--text-secondary)';
    const ll = line.toLowerCase();
    if (ll.includes('error') || ll.includes('fatal') || ll.includes('panic')) color = '#fc8181';
    else if (ll.includes('warn'))                                               color = '#fbbf24';
    else if (ll.includes('info') || /^\d{4}-\d{2}-\d{2}/.test(line))          color = 'var(--text-primary)';
    return <div key={i} style={{ color, minHeight: '1em' }}>{line || '\u00a0'}</div>;
  });
}

export { isPod, isNode, getContainers, colorizeLog };
