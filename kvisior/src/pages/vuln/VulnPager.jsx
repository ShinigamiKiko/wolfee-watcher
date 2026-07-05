export function Pager({ total, pageSize, page, setPage, setPageSize }) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const pages = [];
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) pages.push(i);
  } else {
    pages.push(1);
    if (page > 3) pages.push('…');
    for (let i = Math.max(2, page-1); i <= Math.min(totalPages-1, page+1); i++) pages.push(i);
    if (page < totalPages-2) pages.push('…');
    pages.push(totalPages);
  }

  return (
    <div style={{ display:'flex', alignItems:'center', gap:6, flexWrap:'wrap', marginTop:10 }}>
      <span style={{ fontSize:11, color:'var(--text-muted)' }}>{total} total</span>
      <span style={{ fontSize:11, color:'var(--text-muted)' }}>·</span>
      {[10,20,50].map(n => (
        <button key={n}
          onClick={() => { setPageSize(n); setPage(1); }}
          style={{ fontSize:11, padding:'2px 7px', borderRadius:4, cursor:'pointer',
            background: pageSize===n ? 'rgba(0,200,255,.15)' : 'var(--bg-elevated)',
            border: '1px solid var(--border)',
            color: pageSize===n ? 'var(--accent)' : 'var(--text-muted)',
            fontWeight: pageSize===n ? 700 : 400 }}>
          {n}
        </button>
      ))}
      <span style={{ fontSize:11, color:'var(--text-muted)', marginLeft:4 }}>
        page {page} / {totalPages}
      </span>
      {pages.map((p, i) =>
        p === '…'
          ? <span key={`e${i}`} style={{ fontSize:12, color:'var(--text-muted)' }}>…</span>
          : <button key={p}
              onClick={() => setPage(p)}
              style={{ fontSize:11, minWidth:26, padding:'2px 4px', borderRadius:4, cursor:'pointer',
                background: page===p ? 'rgba(0,200,255,.15)' : 'transparent',
                border: page===p ? '1px solid rgba(0,200,255,.3)' : '1px solid transparent',
                color: page===p ? 'var(--accent)' : 'var(--text-muted)',
                fontWeight: page===p ? 700 : 400 }}>
              {p}
            </button>
      )}
    </div>
  );
}
