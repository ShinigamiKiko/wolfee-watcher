import { useState } from 'react';
import { DEPLOY_CHECKS, DEPLOY_GROUPS } from './constants';

export function DeployPolicyForm({ name, sev, onSave, onClose, initial }) {
  const [selCheck, setSelCheck] = useState(initial?.deployChecks?.[0] || '');
  const [ns,       setNs]       = useState(initial?.namespace || '');
  const [alertOnly, setAlertOnly] = useState(initial?.alertOnly ?? false);

  const check   = DEPLOY_CHECKS.find(c => c.id === selCheck);
  const canSave = selCheck;
  const pick = id => setSelCheck(prev => (prev === id ? '' : id));

  const handleCreate = () => {
    if (!canSave) return;
    onSave({
      id:           initial?.id || `deploy-${Date.now()}`,
      name:         (name || check?.label || '').trim(),
      sev:          sev.toUpperCase(),
      detType:      'Deploy',
      deployChecks: [selCheck],
      namespace:    ns.trim(),
      alertOnly,
      enabled:      initial?.enabled !== false,
      syscall:      '*',
      category:     '*',
    });
    onClose();
  };

  return (
    <div>
      <div className="cpol-field">
        <label className="cpol-label">
          CIS Check
          <span className="cpol-label-note">
            CIS Kubernetes Benchmark v1.10
          </span>
        </label>

        {DEPLOY_GROUPS.map(g => {
          const group = DEPLOY_CHECKS.filter(c => c.group === g);
          if (!group.length) return null;
          return (
            <div key={g} className="mb-12">
              <div className="section-label">
                {g}
              </div>
              <div className="cpol-syscall-grid cpol-syscall-grid--wide" role="group" aria-label={`${g} checks`}>
                {group.map(dc => (
                  <div key={dc.id}
                    role="button" tabIndex={0} aria-pressed={selCheck === dc.id}
                    className={`cpol-syscall-chip${selCheck === dc.id ? ' sel' : ''}`}
                    title={`CIS ${dc.cis}: ${dc.desc}`}
                    onClick={() => pick(dc.id)}
                    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(dc.id); } }}>
                    {dc.label}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
        {check && (
          <div className="cpol-hint">
            <code>CIS {check.cis}</code> {check.label} — {check.desc}
          </div>
        )}
      </div>

      <div className="cpol-field">
        <label className="cpol-label">Namespace Filter</label>
        <input className="cpol-input" value={ns} onChange={e => setNs(e.target.value)}
          placeholder="e.g. production (empty = all)" />
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
    </div>
  );
}
