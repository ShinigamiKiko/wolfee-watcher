import { useState } from 'react';
import { AUDIT_CHECKS, AUDIT_GROUPS } from './constants';

export function AuditPolicyForm({ name, sev, onSave, onClose, initial }) {
  const [selected,  setSelected]  = useState(initial?.auditChecks?.[0] || null);
  const [namespace, setNamespace] = useState(initial?.namespace || '');
  const [alertOnly, setAlertOnly] = useState(initial?.alertOnly ?? false);

  const canSave = !!selected;

  const handleCreate = () => {
    if (!canSave) return;
    const def = AUDIT_CHECKS.find(c => c.id === selected);
    onSave({
      id:          initial?.id || `audit-${Date.now()}`,
      name:        name.trim() || def?.label || selected,
      enabled:     initial?.enabled !== false,
      detType:     'Audit',
      sev,
      auditChecks: [selected],
      namespace:   namespace.trim(),
      alertOnly,
    });
    onClose();
  };

  return (
    <>
      <div className="cpol-field">
        <label className="cpol-label">
          Namespace filter{' '}
          <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(optional)</span>
        </label>
        <input className="cpol-input"
          placeholder="e.g. production  (empty = all namespaces)"
          value={namespace} onChange={e => setNamespace(e.target.value)} />
      </div>

      <div className="cpol-field">
        <label className="cpol-label">Audit check</label>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.5 }}>
          Select one check — sentry-audit will send matching events to the UI in real time.
        </div>

        {AUDIT_GROUPS.map(group => {
          const groupChecks = AUDIT_CHECKS.filter(c => c.group === group);
          return (
            <div key={group} style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.09em',
                textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 6,
                paddingBottom: 4, borderBottom: '1px solid var(--border)' }}>
                {group}
              </div>
              {groupChecks.map(c => {
                const active = selected === c.id;
                return (
                  <div key={c.id} onClick={() => setSelected(c.id)}
                    style={{ display: 'flex', alignItems: 'flex-start', gap: 10,
                      padding: '7px 10px', marginBottom: 4, borderRadius: 7, cursor: 'pointer',
                      background: active ? 'rgba(0,200,255,.06)' : 'transparent',
                      border: `1px solid ${active ? 'rgba(0,200,255,.2)' : 'transparent'}`,
                      transition: 'all .15s' }}>
                    <input type="radio" readOnly checked={active}
                      style={{ marginTop: 3, accentColor: 'var(--accent)', flexShrink: 0 }} />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                        <span style={{ fontSize: 12, fontWeight: 500,
                          color: active ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                          {c.label}
                        </span>
                        {}
                        <span style={{ fontSize: 10, fontFamily: 'monospace',
                          color: 'var(--text-muted)', background: 'var(--bg-elevated)',
                          padding: '1px 5px', borderRadius: 4, border: '1px solid var(--border)' }}>
                          {c.kind}{c.resource ? ` · ${c.resource}` : ''}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                        {c.desc}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          );
        })}
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
