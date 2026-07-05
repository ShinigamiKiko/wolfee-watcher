import { useState, useMemo } from 'react';
import { PATH_PRESETS } from '../../data/syscalls';

export function HookPolicyForm({
  name, sev, onSave, onClose, initial,
  catalog, groups, detType, idPrefix, eventNoun, pathPlaceholder,
}) {
  const [selected,  setSelected]  = useState(initial?.syscall    || '');
  const [pathFilter, setPathFilter] = useState(initial?.pathFilter || '');
  const [ns,        setNs]        = useState(initial?.namespace   || '');
  const [alertOnly, setAlertOnly] = useState(initial?.alertOnly ?? false);

  const byGroup = useMemo(() => {
    const m = {};
    catalog.forEach(c => { (m[c.group] = m[c.group] || []).push(c); });
    return m;
  }, [catalog]);

  const selectedEvent = catalog.find(c => c.name === selected);
  const supportsPath  = (selectedEvent?.args || []).some(a => a.kind === 'path');
  const canSave       = !!selected;

  const argLabels = (selectedEvent?.args || []).map(a => a.label || a.key);
  const hasAddr   = (selectedEvent?.args || []).some(a => a.kind === 'addr');
  const argPlaceholder = hasAddr
    ? 'e.g. 10.96.0.1  or  :443'
    : (argLabels.length ? `filter by ${argLabels.join(' / ')}…` : '');

  const handleSelect = (n) => {
    setSelected(prev => (prev === n ? '' : n));
    setPathFilter('');
  };

  const autoName = selected
    ? `${eventNoun}: ${selected}${pathFilter.trim() ? ' ' + pathFilter.trim() : ''}`
    : '';

  const handleCreate = () => {
    if (!canSave) return;
    onSave({
      id:            initial?.id || `${idPrefix}-${Date.now()}`,
      name:          (name && name.trim()) || autoName,
      sev:           sev.toUpperCase(),
      detType,
      syscall:       selected,
      category:      '*',
      pathFilter:    pathFilter.trim(),
      processFilter: '',
      namespace:     ns.trim(),
      podPattern:    '',
      alertOnly,
      enabled:       initial?.enabled !== false,
    });
    onClose();
  };

  return (
    <>
      <div className="cpol-field">
        <label className="cpol-label">{eventNoun}</label>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.5 }}>
          Select one — the policy matches events whose kernel event name equals it, exactly like a syscall rule.
        </div>
        {groups.map(group => {
          const items = byGroup[group];
          if (!items?.length) return null;
          return (
            <div key={group} style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em',
                textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 5 }}>
                {group}
              </div>
              <div className="cpol-syscall-grid">
                {items.map(c => (
                  <div key={c.name}
                    className={`cpol-syscall-chip${selected === c.name ? ' sel' : ''}`}
                    title={c.desc}
                    onClick={() => handleSelect(c.name)}>
                    {c.name}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
        {selectedEvent && (
          <div className="cpol-hint" style={{ marginTop: 6 }}>
            <code>{selectedEvent.name}</code> — {selectedEvent.desc}
          </div>
        )}
      </div>

      {}
      {selected && supportsPath && (
        <div className="cpol-field">
          <label className="cpol-label">
            Path filter
            <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0,
              marginLeft: 8, fontSize: 11, color: 'var(--text-muted)' }}>— empty = any path</span>
          </label>
          <div className="cpol-syscall-grid" style={{ marginBottom: 8 }}>
            {PATH_PRESETS.map(p => (
              <div key={p.value}
                className={`cpol-syscall-chip${pathFilter === p.value ? ' sel' : ''}`}
                title={p.desc}
                onClick={() => setPathFilter(prev => prev === p.value ? '' : p.value)}>
                {p.label}
              </div>
            ))}
          </div>
          <input className="cpol-input" value={pathFilter}
            onChange={e => setPathFilter(e.target.value)}
            placeholder={pathPlaceholder || 'or type custom path…'}
            style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 13 }} />
          <div className="cpol-hint">Matches the event’s path argument — substring match</div>
        </div>
      )}

      {}
      {selected && !supportsPath && argLabels.length > 0 && (
        <div className="cpol-field">
          <label className="cpol-label">
            Argument filter
            <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0,
              marginLeft: 8, fontSize: 11, color: 'var(--text-muted)' }}>— empty = any</span>
          </label>
          <input className="cpol-input" value={pathFilter}
            onChange={e => setPathFilter(e.target.value)}
            placeholder={argPlaceholder}
            style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 13 }} />
          <div className="cpol-hint">
            Substring match against the event’s arguments: {argLabels.join(', ')}
          </div>
        </div>
      )}

      <div className="cpol-field">
        <label className="cpol-label">
          Namespace
          <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0,
            marginLeft: 8, fontSize: 11, color: 'var(--text-muted)' }}>— optional, substring</span>
        </label>
        <input className="cpol-input" value={ns} onChange={e => setNs(e.target.value)}
          placeholder="e.g. production (empty = all)" />
      </div>

      <div className="cpol-field" style={{ marginTop: 4 }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}>
          <input type="checkbox" checked={alertOnly} onChange={e => setAlertOnly(e.target.checked)}
            style={{ width: 15, height: 15, accentColor: 'var(--accent)', cursor: 'pointer' }} />
          <span className="cpol-label" style={{ margin: 0 }}>Alert</span>
        </label>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 4 }}>
        <button className="cpol-btn" onClick={onClose}>Cancel</button>
        <button className="cpol-btn primary" onClick={handleCreate} disabled={!canSave}>
          {initial ? 'Save changes' : 'Create & Enable'}
        </button>
      </div>
    </>
  );
}
