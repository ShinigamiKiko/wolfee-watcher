import { useState, useEffect, useRef } from 'react';
export function NsDropdown({ nsFilter, setNsFilter, namespaces }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const h = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  return (
    <div ref={ref} style={{ position: 'relative', flexShrink: 0 }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '4px 12px', borderRadius: 6,
          border: open ? '1px solid rgba(99,179,237,.4)' : '1px solid var(--border)',
          background: open ? 'rgba(99,179,237,.08)' : 'var(--bg-elevated, #1e2330)',
          color: nsFilter !== 'all' ? 'var(--accent)' : 'var(--text-muted)',
          fontSize: 11, fontWeight: 500, cursor: 'pointer', whiteSpace: 'nowrap',
        }}>
        <span>{nsFilter === 'all' ? 'All namespaces' : nsFilter}</span>
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
          style={{ transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .15s' }}>
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: 'calc(100% + 6px)', left: 0, zIndex: 9999,
          background: '#1a1e2a',
          border: '1px solid rgba(99,179,237,.25)',
          borderRadius: 8, boxShadow: '0 8px 32px rgba(0,0,0,.7)',
          minWidth: 200, padding: 4, maxHeight: 300, overflowY: 'auto',
        }}>
          {['all', ...namespaces].map(ns => (
            <button key={ns}
              onClick={() => { setNsFilter(ns); setOpen(false); }}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                width: '100%', padding: '8px 12px', fontSize: 12, cursor: 'pointer',
                border: 'none', borderRadius: 5, textAlign: 'left',
                background: nsFilter === ns ? 'rgba(99,179,237,.15)' : 'transparent',
                color: nsFilter === ns ? '#63b3ed' : '#94a3b8',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,.06)'; e.currentTarget.style.color = '#e2e8f0'; }}
              onMouseLeave={e => { e.currentTarget.style.background = nsFilter === ns ? 'rgba(99,179,237,.15)' : 'transparent'; e.currentTarget.style.color = nsFilter === ns ? '#63b3ed' : '#94a3b8'; }}>
              {ns === 'all' ? 'All namespaces' : ns}
              {nsFilter === ns && <span style={{ fontSize: 11, color: '#63b3ed' }}>✓</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

