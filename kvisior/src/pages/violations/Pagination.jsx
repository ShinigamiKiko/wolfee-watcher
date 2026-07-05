const navBtnStyle = (active, disabled) => ({
  minWidth: 28, height: 26, padding: '0 6px',
  fontSize: 12, cursor: disabled ? 'default' : 'pointer',
  background: active ? 'rgba(0,200,255,.15)' : 'transparent',
  border: `0.5px solid ${active ? 'rgba(0,200,255,.3)' : 'transparent'}`,
  borderRadius: 4,
  color: disabled ? 'var(--text-muted)' : active ? 'var(--accent)' : 'var(--color-text-secondary)',
  fontWeight: active ? 700 : 400,
  opacity: disabled ? 0.35 : 1,
  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
  transition: 'background .12s',
});

export function Pagination({ total, pageSize, page, onPageChange, onPageSizeChange }) {
  if (total === 0) return null;

  const totalPages = pageSize > 0 ? Math.ceil(total / pageSize) : 1;
  const from = pageSize > 0 ? (page - 1) * pageSize + 1 : 1;
  const to   = pageSize > 0 ? Math.min(page * pageSize, total) : total;

  const pageNums = [];
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) pageNums.push(i);
  } else {
    pageNums.push(1);
    if (page > 3) pageNums.push('…');
    for (let i = Math.max(2, page - 1); i <= Math.min(totalPages - 1, page + 1); i++) pageNums.push(i);
    if (page < totalPages - 2) pageNums.push('…');
    pageNums.push(totalPages);
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '9px 14px', borderTop: '1px solid var(--border)',
      flexWrap: 'wrap', gap: 8, flexShrink: 0,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
        <span style={{ fontSize: 11, color: 'var(--text-muted)', marginRight: 8, whiteSpace: 'nowrap' }}>Строк:</span>
        {[40, 70, 100, 0].map((n, i, arr) => (
          <button key={n}
            onClick={() => { onPageSizeChange(n); onPageChange(1); }}
            style={{
              padding: '3px 9px', fontSize: 11, cursor: 'pointer',
              background: pageSize === n ? 'rgba(0,200,255,.15)' : 'var(--bg-elevated)',
              border: '0.5px solid var(--color-border-secondary)',
              borderRight: i === arr.length - 1 ? '0.5px solid var(--color-border-secondary)' : 'none',
              borderRadius: i === 0 ? '4px 0 0 4px' : i === arr.length - 1 ? '0 4px 4px 0' : 0,
              color: pageSize === n ? 'var(--accent)' : 'var(--color-text-secondary)',
              fontWeight: pageSize === n ? 700 : 400,
            }}>
            {n === 0 ? 'All' : n}
          </button>
        ))}
      </div>

      <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
        {from}–{to} из {total}
      </span>

      {pageSize > 0 && totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <button onClick={() => onPageChange(1)} disabled={page === 1}
            style={navBtnStyle(false, page === 1)}>«</button>
          <button onClick={() => onPageChange(page - 1)} disabled={page === 1}
            style={navBtnStyle(false, page === 1)}>‹</button>

          {pageNums.map((p, idx) =>
            p === '…'
              ? <span key={`e${idx}`} style={{ padding: '0 4px', color: 'var(--text-muted)', fontSize: 12, userSelect: 'none' }}>…</span>
              : <button key={p} onClick={() => onPageChange(p)}
                  style={navBtnStyle(page === p, false)}>
                  {p}
                </button>
          )}

          <button onClick={() => onPageChange(page + 1)} disabled={page === totalPages}
            style={navBtnStyle(false, page === totalPages)}>›</button>
          <button onClick={() => onPageChange(totalPages)} disabled={page === totalPages}
            style={navBtnStyle(false, page === totalPages)}>»</button>
        </div>
      )}
    </div>
  );
}
