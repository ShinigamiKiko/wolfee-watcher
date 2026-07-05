const PAGE_SIZES = [40, 70, 100];

function Pager({ total, page, setPage, pageSize, setPageSize }) {
  if (!total) return null;
  const tp = Math.max(1, Math.ceil(total / pageSize));
  const cp = Math.min(page, tp);
  const btn = (disabled) => ({
    background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6,
    padding: '4px 10px', color: disabled ? 'var(--text-muted)' : 'var(--text-primary)',
    fontSize: 12, fontFamily: 'DM Sans,sans-serif',
    cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.5 : 1,
  });
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', borderTop: '1px solid var(--border)', background: 'var(--bg-surface)', fontSize: 12, color: 'var(--text-muted)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span>Rows per page:</span>
        <select
          value={pageSize}
          onChange={e => { setPageSize(parseInt(e.target.value, 10)); setPage(1); }}
          style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 8px', color: 'var(--text-primary)', fontSize: 12, fontFamily: 'DM Sans,sans-serif', outline: 'none', cursor: 'pointer' }}
        >
          {PAGE_SIZES.map(n => <option key={n} value={n}>{n}</option>)}
        </select>
        <span style={{ marginLeft: 12 }}>
          {(cp - 1) * pageSize + 1}–{Math.min(cp * pageSize, total)} of {total.toLocaleString()}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <button onClick={() => setPage(1)} disabled={cp <= 1} style={btn(cp <= 1)}>« First</button>
        <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={cp <= 1} style={btn(cp <= 1)}>‹ Prev</button>
        <span style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, padding: '0 8px' }}>{cp} / {tp}</span>
        <button onClick={() => setPage(p => Math.min(tp, p + 1))} disabled={cp >= tp} style={btn(cp >= tp)}>Next ›</button>
        <button onClick={() => setPage(tp)} disabled={cp >= tp} style={btn(cp >= tp)}>Last »</button>
      </div>
    </div>
  );
}

export { PAGE_SIZES, Pager };
