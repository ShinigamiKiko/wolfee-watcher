import { useState, useMemo, useRef, useEffect } from 'react';
import { SYSCALLS } from '../../data/syscalls';
import { TRACEPOINT_EVENTS } from '../../data/tracepoints';

const SEV_TABS = ['critical','high','medium','low'];

export function SeverityModal({ config, onSave, onClose }) {
  const [activeTab,    setActiveTab]    = useState('critical');
  const [activeBinSev, setActiveBinSev] = useState('high');
  const [input,        setInput]        = useState('');
  const [error,        setError]        = useState('');
  const [dropOpen,     setDropOpen]     = useState(false);
  const backdropRef = useRef();
  const dropRef     = useRef();
  const inputRef    = useRef();

  const bins = config.binaries || { critical: [], high: [], medium: [], low: [] };

  const allAssigned = useMemo(() => new Set(Object.values(config).filter(Array.isArray).flat()), [config]);
  const available   = useMemo(
    () => [...SYSCALLS, ...TRACEPOINT_EVENTS].map(s => s.name).filter(n => !allAssigned.has(n)),
    [allAssigned]);
  const filtered    = useMemo(() => available.filter(n => n.includes(input.toLowerCase())), [available, input]);

  useEffect(() => {
    const handler = e => {
      if (dropRef.current && !dropRef.current.contains(e.target) && e.target !== inputRef.current)
        setDropOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  function removeSyscall(name) {
    onSave({ ...config, [activeTab]: config[activeTab].filter(s => s !== name) });
  }

  function addSyscall(name) {
    const n = (name || input).trim().toLowerCase();
    if (!n) return;
    for (const sev of SEV_TABS) {
      if (config[sev].includes(n)) { setError(`"${n}" already in ${sev}`); return; }
    }
    onSave({ ...config, [activeTab]: [...config[activeTab], n] });
    setInput(''); setError(''); setDropOpen(false);
  }

  function removeBinary(name) {
    const next = { ...bins, [activeBinSev]: bins[activeBinSev].filter(b => b !== name) };
    onSave({ ...config, binaries: next });
  }

  function addBinary() {
    const n = input.trim();
    if (!n) return;
    for (const sev of SEV_TABS) {
      if ((bins[sev] || []).includes(n)) { setError(`"${n}" already in ${sev}`); return; }
    }
    const next = { ...bins, [activeBinSev]: [...(bins[activeBinSev] || []), n] };
    onSave({ ...config, binaries: next });
    setInput(''); setError('');
  }

  const isBinaryTab = activeTab === 'binary';
  const totalBins   = SEV_TABS.reduce((s, sv) => s + (bins[sv] || []).length, 0);

  return (
    <div className="fns-modal-backdrop" ref={backdropRef} onClick={e => { if (e.target === backdropRef.current) onClose(); }}>
      <div className="fns-modal">
        <div className="fns-modal-hdr">
          <span className="fns-modal-title">Severity · Syscall mapping</span>
          <button className="fns-modal-close" onClick={onClose}>×</button>
        </div>

        {}
        <div className="fns-modal-tabs">
          {SEV_TABS.map(sev => (
            <div key={sev} className={`fns-modal-tab fns-modal-tab--${sev} ${activeTab === sev ? 'active' : ''}`}
              onClick={() => { setActiveTab(sev); setInput(''); setError(''); setDropOpen(false); }}>
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
              <span className="fns-modal-tab-cnt">{config[sev].length}</span>
            </div>
          ))}
          <div className={`fns-modal-tab fns-modal-tab--binary ${activeTab === 'binary' ? 'active' : ''}`}
            onClick={() => { setActiveTab('binary'); setInput(''); setError(''); setDropOpen(false); }}>
            Binary
            <span className="fns-modal-tab-cnt">{totalBins}</span>
          </div>
        </div>

        {isBinaryTab ? (
          <>
            {}
            <div className="fns-modal-subtabs">
              {SEV_TABS.map(sev => (
                <div key={sev} className={`fns-modal-subtab fns-modal-subtab--${sev} ${activeBinSev === sev ? 'active' : ''}`}
                  onClick={() => { setActiveBinSev(sev); setError(''); }}>
                  {sev.charAt(0).toUpperCase() + sev.slice(1)}
                  <span className="fns-modal-tab-cnt">{(bins[sev] || []).length}</span>
                </div>
              ))}
            </div>
            <div className="fns-modal-list">
              {(bins[activeBinSev] || []).length === 0
                ? <div className="fns-empty">No binaries — add a path or name below</div>
                : (bins[activeBinSev] || []).map(b => (
                    <div key={b} className="fns-modal-row">
                      <span className="fns-modal-row-name">{b}</span>
                      <button className="fns-modal-row-del" onClick={() => removeBinary(b)}>×</button>
                    </div>
                  ))
              }
            </div>
            <div className="fns-modal-footer">
              <div className="fns-modal-add-wrap">
                <input ref={inputRef} className="fns-modal-input" placeholder="Add binary path or name…"
                  value={input}
                  onChange={e => { setInput(e.target.value); setError(''); }}
                  onKeyDown={e => { if (e.key === 'Enter') addBinary(); }}
                />
                <button className="fns-modal-add" onClick={addBinary}>+</button>
              </div>
              {error && <span className="fns-modal-error">{error}</span>}
            </div>
          </>
        ) : (
          <>
            <div className="fns-modal-list">
              {config[activeTab].length === 0
                ? <div className="fns-empty">No syscalls — click + to add</div>
                : config[activeTab].map(sc => (
                    <div key={sc} className="fns-modal-row">
                      <span className="fns-modal-row-name">{sc}</span>
                      <button className="fns-modal-row-del" onClick={() => removeSyscall(sc)}>×</button>
                    </div>
                  ))
              }
            </div>
            <div className="fns-modal-footer">
              <div className="fns-modal-add-wrap" ref={dropRef}>
                <input ref={inputRef} className="fns-modal-input" placeholder="Add syscall…"
                  value={input}
                  onChange={e => { setInput(e.target.value); setDropOpen(true); setError(''); }}
                  onFocus={() => setDropOpen(true)}
                  onKeyDown={e => { if (e.key === 'Enter') addSyscall(); if (e.key === 'Escape') setDropOpen(false); }}
                />
                <button className="fns-modal-add" onClick={() => setDropOpen(o => !o)}>+</button>
                {dropOpen && filtered.length > 0 && (
                  <div className="fns-modal-drop">
                    {filtered.map(sc => (
                      <div key={sc} className="fns-modal-drop-item" onMouseDown={() => addSyscall(sc)}>{sc}</div>
                    ))}
                  </div>
                )}
                {dropOpen && filtered.length === 0 && input && (
                  <div className="fns-modal-drop">
                    <div className="fns-modal-drop-empty">No matches — press Enter to add custom</div>
                  </div>
                )}
              </div>
              {error && <span className="fns-modal-error">{error}</span>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
