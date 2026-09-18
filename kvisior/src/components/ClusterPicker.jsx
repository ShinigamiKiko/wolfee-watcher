import { useState, useEffect, useRef } from 'react';
import { useClusters } from '../context/ClusterContext';

function status(c, local) {
  if (!c.enabled) return { key: 'off', label: 'disabled' };
  if (c.id === local) return { key: 'live', label: 'this kvisior' };
  if (c.endpoint) return { key: 'live', label: 'connected' };
  return { key: 'history', label: 'history only' };
}

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

  const active = clusters.find(c => c.id === current) || { id: current, name: current, enabled: true };
  const st = status(active, local);

  return (
    <div className="cluster-picker" ref={ref}>
      <button type="button" className="cluster-picker-btn" onClick={() => setOpen(v => !v)}
              title={`Cluster: ${active.name || active.id} (${st.label})`}>
        <span className="cluster-picker-label">Cluster</span>
        <span className={`cluster-dot cluster-dot-${st.key}`} />
        <span className="cluster-picker-name">{active.name || active.id}</span>
        <span className="cluster-picker-count">{clusters.length}</span>
        <span className="cluster-picker-caret">▾</span>
      </button>
      {open && (
        <div className="cluster-picker-menu">
          <div className="cluster-picker-head">Switch cluster</div>
          {clusters.map(c => {
            const s = status(c, local);
            return (
              <button type="button" key={c.id}
                      className={`cluster-picker-item ${c.id === current ? 'active' : ''}`}
                      onClick={() => { select(c.id); setOpen(false); }}>
                <span className={`cluster-dot cluster-dot-${s.key}`} />
                <span className="cluster-picker-item-name">{c.name || c.id}</span>
                <span className="cluster-picker-item-state">{s.label}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function ClusterBanner() {
  const { clusters, current, local } = useClusters();
  const active = clusters.find(c => c.id === current);
  if (!active || active.id === local || active.endpoint) return null;
  return (
    <div className="cluster-banner">
      Cluster <b>{active.name || active.id}</b> has no connected kvisior — stored history is shown,
      live views (nodes, pods, scans, honeypots) are unavailable.
    </div>
  );
}
