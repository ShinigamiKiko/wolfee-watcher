import { useState, useEffect, useRef, useMemo } from 'react';
import { useClusters } from '../context/ClusterContext';

export const DROPDOWN_LIMIT = 30;

function status(c, local) {
  if (!c.enabled) return { key: 'off', label: 'disabled' };
  if (c.id === local) return { key: 'live', label: 'this kvisior' };
  if (c.endpoint) return { key: 'live', label: 'connected' };
  return { key: 'history', label: 'history only' };
}

export function filterClusters(clusters, query) {
  const q = query.trim().toLowerCase();
  if (!q) return clusters;
  return clusters.filter(c =>
    c.id.toLowerCase().includes(q) ||
    (c.name || '').toLowerCase().includes(q) ||
    (c.description || '').toLowerCase().includes(q));
}

function ClusterRow({ c, current, local, onPick }) {
  const s = status(c, local);
  return (
    <button type="button"
            className={`cluster-picker-item ${c.id === current ? 'active' : ''}`}
            onClick={() => onPick(c.id)}>
      <span className={`cluster-dot cluster-dot-${s.key}`} />
      <span className="cluster-picker-item-name">{c.name || c.id}</span>
      <span className="cluster-picker-item-state">{s.label}</span>
    </button>
  );
}

function AllClustersModal({ clusters, current, local, onPick, onClose }) {
  const [query, setQuery] = useState('');
  const inputRef = useRef(null);
  const shown = useMemo(() => filterClusters(clusters, query), [clusters, query]);

  useEffect(() => {
    inputRef.current?.focus();
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal cluster-modal" role="dialog" aria-label="All clusters">
        <div className="modal-header">
          <div className="modal-title">All clusters <span className="cluster-modal-count">{clusters.length}</span></div>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <input ref={inputRef} className="cluster-search" type="search" placeholder="Search clusters…"
               value={query} onChange={e => setQuery(e.target.value)} />
        <div className="cluster-modal-list">
          {shown.length === 0
            ? <div className="cluster-picker-empty">No clusters match “{query}”</div>
            : shown.map(c => (
                <ClusterRow key={c.id} c={c} current={current} local={local}
                            onPick={(id) => { onPick(id); onClose(); }} />
              ))}
        </div>
      </div>
    </div>
  );
}

export function ClusterPicker() {
  const { clusters, current, local, select } = useClusters();
  const [open, setOpen] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [query, setQuery] = useState('');
  const ref = useRef(null);
  const searchRef = useRef(null);

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  useEffect(() => {
    if (open) searchRef.current?.focus();
    else setQuery('');
  }, [open]);

  const matched = useMemo(() => filterClusters(clusters, query), [clusters, query]);

  if (clusters.length === 0) return null;

  const active = clusters.find(c => c.id === current) || { id: current, name: current, enabled: true };
  const st = status(active, local);
  const visible = matched.slice(0, DROPDOWN_LIMIT);
  const hidden = matched.length - visible.length;

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
          <input ref={searchRef} className="cluster-search" type="search" placeholder="Search clusters…"
                 value={query} onChange={e => setQuery(e.target.value)} />
          <div className="cluster-picker-list">
            {visible.length === 0
              ? <div className="cluster-picker-empty">No clusters match “{query}”</div>
              : visible.map(c => (
                  <ClusterRow key={c.id} c={c} current={current} local={local}
                              onPick={(id) => { select(id); setOpen(false); }} />
                ))}
          </div>
          <div className="cluster-picker-foot">
            <span className="cluster-picker-foot-note">
              {hidden > 0 ? `${visible.length} of ${matched.length} shown` : `${matched.length} cluster${matched.length === 1 ? '' : 's'}`}
            </span>
            <button type="button" className="cluster-picker-all"
                    onClick={() => { setOpen(false); setShowAll(true); }}>
              View all
            </button>
          </div>
        </div>
      )}
      {showAll && (
        <AllClustersModal clusters={clusters} current={current} local={local}
                          onPick={select} onClose={() => setShowAll(false)} />
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
