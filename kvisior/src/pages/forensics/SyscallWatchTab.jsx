import { useState, useEffect, useCallback } from 'react';
import { SYSCALL_GROUPS } from './watchableSyscalls';

export function SyscallWatchTab({ ns, pod, onSelectedChange }) {
  const [selected, setSelected] = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [noStore,  setNoStore]  = useState(false);
  const [saving,   setSaving]   = useState(false);

  const fetchWatch = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`/v1/pod-watch?ns=${encodeURIComponent(ns)}&pod=${encodeURIComponent(pod)}`, { credentials: 'same-origin' });
      if (res.status === 503) { setNoStore(true); setLoading(false); return; }
      if (res.ok) {
        const data = await res.json();
        const sc = data.syscalls || [];
        setSelected(sc);
        onSelectedChange?.(sc);
      }
    } catch {}
    setLoading(false);
  }, [ns, pod, onSelectedChange]);

  useEffect(() => { fetchWatch(); }, [fetchWatch]);

  const toggleSyscall = async (sc) => {
    const isOn = selected.includes(sc);
    if (!isOn && selected.length >= 3) return;
    const next = isOn ? selected.filter(s => s !== sc) : [...selected, sc];
    setSaving(true);
    try {
      if (next.length === 0) {
        await fetch(`/v1/pod-watch?ns=${encodeURIComponent(ns)}&pod=${encodeURIComponent(pod)}`, {
          method: 'DELETE', credentials: 'same-origin',
        });
        setSelected([]);
        onSelectedChange?.([]);
      } else {
        const res = await fetch(`/v1/pod-watch?ns=${encodeURIComponent(ns)}&pod=${encodeURIComponent(pod)}`, {
          method: 'PUT',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ syscalls: next }),
        });
        if (res.ok || res.status === 204) {
          setSelected(next);
          onSelectedChange?.(next);
        }
      }
    } catch {}
    setSaving(false);
  };

  if (noStore) {
    return <div className="fns-empty" style={{ marginTop: 32 }}>Syscall watch requires PostgreSQL</div>;
  }
  if (loading) {
    return <div className="fns-empty" style={{ marginTop: 32 }}>Loading…</div>;
  }

  return (
    <div className="fns-syscall-watch">
      <div className="fns-syscall-watch-hdr">
        <span className="fns-section-title">Syscall Watch</span>
        <span className="fns-section-count">
          Captured events appear in the Binary Calls tab · {selected.length}/3 selected
          {saving && ' · saving…'}
        </span>
      </div>

      {SYSCALL_GROUPS.map(group => (
        <div key={group.label} className="fns-syscall-group">
          <div className="fns-syscall-group-label">{group.label}</div>
          <div className="fns-syscall-chips">
            {group.items.map(({ name, desc }) => {
              const on       = selected.includes(name);
              const disabled = !on && selected.length >= 3;
              return (
                <div
                  key={name}
                  className={`fns-syscall-chip${on ? ' fns-syscall-chip--on' : ''}${disabled ? ' fns-syscall-chip--disabled' : ''}`}
                  onClick={() => !disabled && toggleSyscall(name)}
                  title={disabled ? 'Max 3 syscalls selected — deselect one first' : desc}
                >
                  {name}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
