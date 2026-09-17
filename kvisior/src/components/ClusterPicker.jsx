import { useState, useEffect, useRef } from 'react';
import { useClusters } from '../context/ClusterContext';

export function ClusterPicker() {
  const { clusters, current, local, select } = useClusters();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  if (clusters.length === 0) return null;

  const active = clusters.find(c => c.id === current);
  const label = active?.name || current;

  return (
    <div className="dropdown-wrap" ref={ref} style={{ marginRight: 12 }}>
      <div className="user-btn" onClick={() => setOpen(v => !v)} title="Active cluster">
        <span style={{ fontSize: 13, opacity: .7, marginRight: 6 }}>⎈</span>
        <span className="user-name">{label}</span>
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>▾</span>
      </div>
      <div className={`dropdown-menu ${open ? 'open' : ''}`}>
        {clusters.map(c => (
          <div
            key={c.id}
            className="dropdown-item"
            style={{
              opacity: c.enabled ? 1 : .45,
              fontWeight: c.id === current ? 700 : 400,
            }}
            onClick={() => { select(c.id); setOpen(false); }}
          >
            {c.id === current ? '● ' : '○ '}{c.name || c.id}
            {c.id === local ? ' · local' : ''}
          </div>
        ))}
      </div>
    </div>
  );
}
