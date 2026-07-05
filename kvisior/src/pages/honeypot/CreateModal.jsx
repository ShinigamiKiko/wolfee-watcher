import { SERVICES } from './honeypotConstants';

export function CreateModal({ showModal, setShowModal, formName, setFormName, formNs, setFormNs, formSvcs, toggleSvc, createErr, creating, handleCreate }) {
  if (!showModal) return null;
  return (
  <div className="hp-modal-overlay" onClick={e => e.target === e.currentTarget && setShowModal(false)}>
    <div className="hp-modal">
      <div className="hp-modal-header">
        <span className="hp-modal-title">Create Honeypot</span>
        <button className="hp-modal-close" onClick={() => setShowModal(false)}>✕</button>
      </div>
      <div className="hp-modal-body">
        <div className="hp-form-row">
          <div className="hp-form-group">
            <label className="hp-form-label">Name</label>
            <input
              className="hp-form-input"
              value={formName}
              onChange={e => setFormName(e.target.value)}
              placeholder="e.g. prod-redis-trap"
            />
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
              Trap name — the pod is created as <code>h-&lt;name&gt;</code>
            </div>
          </div>
          <div className="hp-form-group">
            <label className="hp-form-label">Namespace</label>
            <input
              className="hp-form-input"
              value={formNs}
              onChange={e => setFormNs(e.target.value)}
              placeholder="production"
            />
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
              Deploy in target namespace — not kube-system
            </div>
          </div>
        </div>

        <div className="hp-form-group">
          <label className="hp-form-label">Services to emulate</label>
          <div className="hp-svc-picker">
            {SERVICES.map(svc => (
              <div
                key={svc.name}
                className={`hp-svc-option${formSvcs.includes(svc.name) ? ' hp-svc-option--selected' : ''}`}
                onClick={() => toggleSvc(svc.name)}
              >
                <span className="hp-svc-option-icon">{svc.icon}</span>
                <div>
                  <div className="hp-svc-option-name">{svc.label}</div>
                  <div className="hp-svc-option-port">:{svc.port}</div>
                </div>
                <div className="hp-svc-check">
                  {formSvcs.includes(svc.name) && '✓'}
                </div>
              </div>
            ))}
          </div>
        </div>

        {createErr && (
          <div className="hp-create-err">{createErr}</div>
        )}
      </div>
      <div className="hp-modal-footer">
        <button className="hp-btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
        <button
          className="hp-btn-primary"
          onClick={handleCreate}
          disabled={creating || !formName.trim() || formSvcs.length === 0}
        >
          {creating ? 'Deploying…' : 'Deploy Honeypot'}
        </button>
      </div>
    </div>
  </div>
  );
}
