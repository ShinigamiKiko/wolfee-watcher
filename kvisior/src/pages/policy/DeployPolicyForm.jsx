import { useState } from 'react';
import { DEPLOY_CHECKS, DEPLOY_GROUPS } from './constants';

export function DeployPolicyForm({ name, sev, onSave, onClose, initial }) {
  const [selCheck, setSelCheck] = useState(initial?.deployChecks?.[0] || '');
  const [ns,       setNs]       = useState(initial?.namespace || '');
  const [alertOnly, setAlertOnly] = useState(initial?.alertOnly ?? false);
  const [group,    setGroup]    = useState('Privilege');

  const check   = DEPLOY_CHECKS.find(c => c.id === selCheck);
  const canSave = selCheck;
  const grouped = DEPLOY_CHECKS.filter(c => c.group === group);

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

        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 10 }}>
          {DEPLOY_GROUPS.map(g => (
            <button key={g} onClick={() => setGroup(g)}
              style={{ padding: '3px 10px', borderRadius: 6, fontSize: 11, cursor: 'pointer', fontWeight: 500,
                background: group === g ? 'var(--accent)' : 'var(--bg-elevated)',
                color: group === g ? '#000' : 'var(--text-muted)',
                border: group === g ? 'none' : '1px solid var(--border)' }}>
              {g}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
          {grouped.map(dc => (
            <label key={dc.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 10,
              padding: '9px 12px', borderRadius: 8, cursor: 'pointer',
              background: selCheck === dc.id ? 'rgba(0,200,255,.08)' : 'var(--bg-elevated)',
              border: `1px solid ${selCheck === dc.id ? 'rgba(0,200,255,.25)' : 'var(--border)'}`,
              transition: 'all .15s' }}>
              <input type="radio" name="deployCheck" value={dc.id}
                checked={selCheck === dc.id}
                onChange={() => setSelCheck(dc.id)}
                style={{ marginTop: 3, accentColor: 'var(--accent)', flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>{dc.label}</span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono,monospace',
                    marginLeft: 'auto', flexShrink: 0 }}>{dc.cis}</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2,
                  fontFamily: 'JetBrains Mono,monospace' }}>{dc.desc}</div>
              </div>
            </label>
          ))}
        </div>
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
