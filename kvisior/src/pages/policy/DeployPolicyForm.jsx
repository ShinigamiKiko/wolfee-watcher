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
          <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0,
            marginLeft: 8, fontSize: 11, color: 'var(--text-muted)' }}>
            CIS Kubernetes Benchmark v1.10
          </span>
        </label>

        {DEPLOY_GROUPS.map(g => {
          const group = DEPLOY_CHECKS.filter(c => c.group === g);
          if (!group.length) return null;
          return (
            <div key={g} style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em',
                textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 5 }}>
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
          <div className="cpol-hint" style={{ marginTop: 6 }}>
            <code>CIS {check.cis}</code> {check.label} — {check.desc}
          </div>
        )}
      </div>

      <div className="cpol-field">
        <label className="cpol-label">Namespace Filter</label>
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
    </div>
  );
}
