import { useEffect, useRef, useState } from 'react';

function RunDialog({ tool, onConfirm, onCancel }) {
  const [name, setName] = useState('');
  const ref = useRef(null);
  useEffect(() => ref.current?.focus(), []);
  const go = () => name.trim() && onConfirm(name.trim());
  return (
    <div className="au-overlay" onClick={onCancel}>
      <div className="au-dialog" onClick={e => e.stopPropagation()}>
        <div className="au-dialog__title">New {tool} audit</div>
        <div className="au-dialog__sub">Enter a name to identify this run</div>
        <input ref={ref} className="au-dialog__input"
          placeholder='e.g. "Pre-release" or "Weekly scan"'
          value={name} onChange={e => setName(e.target.value)}
          onKeyDown={e => { if (e.key==='Enter') go(); if (e.key==='Escape') onCancel(); }}
        />
        <div className="au-dialog__actions">
          <button className="au-dialog__cancel" onClick={onCancel}>Cancel</button>
          <button className="au-dialog__run" onClick={go} disabled={!name.trim()}>▶ Start</button>
        </div>
      </div>
    </div>
  );
}


export { RunDialog };
