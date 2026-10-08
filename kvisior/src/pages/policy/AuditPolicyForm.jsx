import { useState } from 'react';
import { AUDIT_CHECKS, AUDIT_GROUPS } from './constants';

export function AuditPolicyForm({ name, sev, onSave, onClose, initial }) {
  const [selected,  setSelected]  = useState(initial?.auditChecks?.[0] || null);
  const [namespace, setNamespace] = useState(initial?.namespace || '');
  const [alertOnly, setAlertOnly] = useState(initial?.alertOnly ?? false);

  const canSave = !!selected;
  const check = AUDIT_CHECKS.find(c => c.id === selected);

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
          <span className="cpol-label-note">(optional)</span>
        </label>
        <input className="cpol-input"
          placeholder="e.g. production  (empty = all namespaces)"
          value={namespace} onChange={e => setNamespace(e.target.value)} />
      </div>

      <div className="cpol-field">
        <label className="cpol-label">Audit check</label>
        <div className="cpol-hint cpol-hint--lead">
          Select one check — sentry-audit will send matching events to the UI in real time.
        </div>

        {AUDIT_GROUPS.map(group => {
          const groupChecks = AUDIT_CHECKS.filter(c => c.group === group);
          if (!groupChecks.length) return null;
          return (
            <div key={group} className="mb-12">
              <div className="section-label">{group}</div>
              <div className="cpol-syscall-grid cpol-syscall-grid--wide" role="group" aria-label={`${group} checks`}>
                {groupChecks.map(c => (
                  <button key={c.id} type="button" aria-pressed={selected === c.id}
                    className={`cpol-syscall-chip${selected === c.id ? ' sel' : ''}`}
                    title={c.desc} onClick={() => setSelected(c.id)}>
                    {c.label}
                  </button>
                ))}
              </div>
            </div>
          );
        })}
        {check && (
          <div className="cpol-hint">
            <code>{check.kind}{check.resource ? ` · ${check.resource}` : ''}</code> {check.desc}
          </div>
        )}
      </div>

      <div className="cpol-field">
        <label className="check">
          <input type="checkbox" checked={alertOnly} onChange={e => setAlertOnly(e.target.checked)} />
          <span>Alert</span>
        </label>
      </div>

      <div className="cpol-actions">
        <button className="cpol-btn" onClick={onClose}>Cancel</button>
        <button className="cpol-btn primary" onClick={handleCreate} disabled={!canSave}>
          {initial ? 'Save changes' : 'Create & Enable'}
        </button>
      </div>
    </>
  );
}
