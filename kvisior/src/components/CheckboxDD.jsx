import { useState, useRef, useEffect } from 'react';
import { Icon } from './Icon';

export function CheckboxDD({ label, options, checked, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const away = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const esc = e => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', away);
    document.addEventListener('keydown', esc);
    return () => { document.removeEventListener('mousedown', away); document.removeEventListener('keydown', esc); };
  }, [open]);

  const partial = checked.length > 0 && checked.length < options.length;

  return (
    <div ref={ref} className="menu-select">
      <button type="button" className={`btn btn-outline btn-sm${partial ? ' is-set' : ''}`} aria-haspopup="true" aria-expanded={open} onClick={() => setOpen(v => !v)}>
        {label}{partial && <span className="mono t-xs">{checked.length}/{options.length}</span>}
        <Icon name="chevron-down" className={open ? 'rot-180' : undefined} />
      </button>
      {open && (
        <div className="menu" role="group" aria-label={label}>
          {options.map(opt => (
            <label key={opt} className="menu-item menu-check">
              <input type="checkbox" checked={checked.includes(opt)} onChange={() => onChange(opt)} />
              <span>{opt}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}
