import { useState, useMemo, useRef, useEffect } from 'react';
import { useScanner } from '../../context/ScannerContext';
import { SevBadge, StatusDot } from '../../components/ui';
import { useApp } from '../../context/AppContext';
import { epssLabel, sevColor, fmtDuration } from '../../data/scanner';

const SCAN_TABS = [
  { id: 'results',    label: 'Scan Results' },
  { id: 'namespaces', label: 'Namespaces' },
  { id: 'unscanned',  label: 'Unscanned' },
  { id: 'policies',   label: 'Scan Policies' },
  { id: 'history',    label: 'Scan History' },
];

const MOCK_POLICIES = [
  { name: 'Block on Critical CVE',  scope: 'All registries',       action: 'Block deploy', ac: 'var(--danger)',  last: '2m ago', status: 'active' },
  { name: 'Warn on High CVE',       scope: 'production namespace', action: 'Alert only',   ac: 'var(--warning)', last: '8m ago', status: 'active' },
  { name: 'Block on OS EOL',        scope: 'prod-cluster',         action: 'Block deploy', ac: 'var(--danger)',  last: '1h ago', status: 'active' },
  { name: 'Require signed images',  scope: 'All clusters',         action: 'Block deploy', ac: 'var(--danger)',  last: 'Never',  status: 'warn'   },
];

const MOCK_HISTORY = [
  { started: 'Mar 06 · 09:14', images: 94, dur: '1m 12s', newC: '+8',  fixed: '-34', r: 'active' },
  { started: 'Mar 06 · 08:00', images: 94, dur: '58s',    newC: '+2',  fixed: '-12', r: 'active' },
  { started: 'Mar 05 · 23:00', images: 91, dur: '1m 04s', newC: '0',   fixed: '-7',  r: 'active' },
  { started: 'Mar 05 · 18:30', images: 91, dur: '—',      newC: '—',   fixed: '—',   r: 'error'  },
  { started: 'Mar 05 · 12:00', images: 89, dur: '1m 22s', newC: '+14', fixed: '-6',  r: 'active' },
];

function FilterDD({ label, options, checked, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);
  return (
    <div className="filter-dd" ref={ref}>
      <button className="btn btn-outline" style={{fontSize:12,whiteSpace:'nowrap'}} onClick={()=>setOpen(v=>!v)}>{label} ▾</button>
      <div className={`filter-dd-menu${open?' open':''}`}>
        {options.map(opt=>(
          <label key={opt} className="filter-dd-item">
            <input type="checkbox" checked={checked.includes(opt)} onChange={()=>onChange(opt)} />
            {opt}
          </label>
        ))}
      </div>
    </div>
  );
}


export { FilterDD };
