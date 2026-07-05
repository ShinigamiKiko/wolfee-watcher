import { useState, useRef, useEffect } from 'react';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SEV_COLORS  = { critical: 'fns-chip--sev-crit', high: 'fns-chip--sev-high', medium: 'fns-chip--sev-med', low: 'fns-chip--sev-low' };

export function BinaryFilter({ filterSev, onSevChange, filterBins, onBinsChange }) {
  const [open,  setOpen]  = useState(false);
  const [draft, setDraft] = useState('');
  const ref = useRef();

  useEffect(() => {
    const h = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  const toggleSev = sev => {
    const next = new Set(filterSev);
    next.has(sev) ? next.delete(sev) : next.add(sev);
    onSevChange(next);
  };

  const addBin = () => {
    const v = draft.trim();
    if (!v) return;
    onBinsChange(new Set([...filterBins, v]));
    setDraft('');
  };

  const removeBin = b => {
    const next = new Set(filterBins);
    next.delete(b);
    onBinsChange(next);
  };

  const activeCount = filterSev.size + filterBins.size;
  const label = activeCount === 0 ? 'All binaries' : `${activeCount} filter${activeCount > 1 ? 's' : ''}`;

  return (
    <div className="fns-fdrop" ref={ref}>
      <button className="fns-btn" onClick={() => setOpen(o => !o)}>
        {label} <span className="fns-arrow">▾</span>
      </button>

      {}
      {(filterSev.size > 0 || filterBins.size > 0) && (
        <div className="fns-chips">
          {[...filterSev].map(s => (
            <span key={s} className={`fns-chip fns-chip--active ${SEV_COLORS[s]}`}
              onClick={() => toggleSev(s)}>{s} ✕</span>
          ))}
          {[...filterBins].map(b => (
            <span key={b} className="fns-chip fns-chip--active fns-chip--bin"
              onClick={() => removeBin(b)}>{b} ✕</span>
          ))}
        </div>
      )}

      {open && (
        <div className="fns-fdrop-menu">
          {}
          <div className="fns-fdrop-grp">
            <div className="fns-fdrop-grp-label">Severity</div>
            <div className="fns-fdrop-calls">
              {SEVERITIES.map(s => (
                <div key={s}
                  className={`fns-chip ${SEV_COLORS[s]} ${filterSev.has(s) ? 'fns-chip--active' : ''}`}
                  onClick={() => toggleSev(s)}>{s}</div>
              ))}
            </div>
          </div>

          {}
          <div className="fns-fdrop-grp">
            <div className="fns-fdrop-grp-label">Binary path / name</div>
            <div className="fns-bin-input-row">
              <input
                className="fns-bin-input"
                placeholder="e.g. /bin/bash or curl"
                value={draft}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addBin(); } }}
              />
              <button className="fns-btn fns-btn--accent" onClick={addBin}>+ Add</button>
            </div>
            {filterBins.size > 0 && (
              <div className="fns-fdrop-calls" style={{ marginTop: 6 }}>
                {[...filterBins].map(b => (
                  <div key={b} className="fns-chip fns-chip--active fns-chip--bin"
                    onClick={() => removeBin(b)}>{b} ✕</div>
                ))}
              </div>
            )}
          </div>

          <div className="fns-fdrop-footer">
            <button className="fns-btn" onClick={() => { onSevChange(new Set()); onBinsChange(new Set()); }}>Clear</button>
            <button className="fns-btn fns-btn--accent" onClick={() => setOpen(false)}>Apply ✓</button>
          </div>
        </div>
      )}
    </div>
  );
}
