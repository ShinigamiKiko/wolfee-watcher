import { useState, useRef, useEffect } from 'react';
import { SYSCALL_GROUPS } from './forensicsHelpers';

export function SyscallFilterDropdown({ selected, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef();

  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const toggle = (name) => {
    const next = new Set(selected);
    next.has(name) ? next.delete(name) : next.add(name);
    onChange(next);
  };

  const label = selected.size === 0 ? 'All binaries' : `${selected.size} selected`;

  return (
    <div className="fns-fdrop" ref={ref}>
      <button className="fns-btn" onClick={() => setOpen(o => !o)}>
        {label} <span className="fns-arrow">▾</span>
      </button>
      {selected.size > 0 && (
        <div className="fns-chips">
          {[...selected].map(s => <span key={s} className="fns-chip fns-chip--active">{s}</span>)}
        </div>
      )}
      {open && (
        <div className="fns-fdrop-menu">
          {Object.entries(SYSCALL_GROUPS).map(([grp, calls]) => (
            <div key={grp} className="fns-fdrop-grp">
              <div className="fns-fdrop-grp-label">{grp}</div>
              <div className="fns-fdrop-calls">
                {calls.map(sc => (
                  <div key={sc} className={`fns-chip ${selected.has(sc) ? 'fns-chip--active' : ''}`}
                    onClick={() => toggle(sc)}>{sc}</div>
                ))}
              </div>
            </div>
          ))}
          <div className="fns-fdrop-footer">
            <button className="fns-btn" onClick={() => onChange(new Set())}>Clear</button>
            <button className="fns-btn" onClick={() => onChange(new Set(Object.values(SYSCALL_GROUPS).flat()))}>All</button>
            <button className="fns-btn fns-btn--accent" onClick={() => setOpen(false)}>Apply ✓</button>
          </div>
        </div>
      )}
    </div>
  );
}
