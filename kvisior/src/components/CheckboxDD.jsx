import { useState, useRef, useEffect } from 'react';

export function CheckboxDD({ label, options, checked, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const h = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  return (
    <div ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          fontSize: 12, whiteSpace: 'nowrap', cursor: 'pointer',
          padding: '6px 12px', borderRadius: 8,
          background: 'var(--bg-elevated)', border: '1px solid var(--border)',
          color: 'var(--text-secondary)',
        }}
      >
        {label} ▾
      </button>

      {open && (
        <div style={{
          position: 'absolute', top: 'calc(100% + 6px)', left: 0,
          background: 'var(--bg-elevated)', border: '1px solid var(--border)',
          borderRadius: 10, padding: 6, zIndex: 300,
          boxShadow: '0 8px 32px rgba(0,0,0,.5)',
          minWidth: 140,
        }}>
          {options.map(opt => {
            const active = checked.includes(opt);
            return (
              <div
                key={opt}
                onClick={() => onChange(opt)}
                style={{
                  display: 'flex', flexDirection: 'row', alignItems: 'center',
                  gap: 10, padding: '7px 10px', borderRadius: 7, cursor: 'pointer',
                  background: active ? 'rgba(255,255,255,.05)' : 'transparent',
                  color: active ? 'var(--text-primary)' : 'var(--text-muted)',
                  fontSize: 12, userSelect: 'none',
                }}
              >
                <div style={{
                  width: 16, height: 16, borderRadius: 4, flexShrink: 0,
                  border: `2px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
                  background: active ? 'var(--accent)' : 'transparent',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'all .15s',
                }}>
                  {active && (
                    <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                      <path d="M1 4L3.5 6.5L9 1" stroke="white" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  )}
                </div>
                <span>{opt}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
