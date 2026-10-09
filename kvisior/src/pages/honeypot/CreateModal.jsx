import { SERVICES } from './honeypotConstants';
import { svcByName, shortImage } from './honeypotUtils';
import { Icon } from '../../components/Icon';

export function CreateModal({ showModal, setShowModal, catalog, formName, setFormName, formNs, setFormNs, formSvc, pickSvc, createErr, creating, handleCreate }) {
  if (!showModal) return null;
  const svc = svcByName(formSvc, catalog);
  const name = formName.trim() || svc.defaultName;
  return (
  <div className="hp-modal-overlay" onClick={e => e.target === e.currentTarget && setShowModal(false)}>
    <div className="hp-modal" role="dialog" aria-modal="true" aria-labelledby="hp-create-title">
      <div className="hp-modal-header">
        <span className="hp-modal-title" id="hp-create-title">Create Honeypot</span>
        <button className="hp-modal-close" onClick={() => setShowModal(false)} aria-label="Close"><Icon name="x" /></button>
      </div>
      <div className="hp-modal-body">
        <div className="hp-form-group">
          <label className="hp-form-label">Service</label>
          <div className="hp-svc-picker" role="radiogroup" aria-label="Service">
            {SERVICES.map(s => {
              const opt = svcByName(s.name, catalog);
              const on = formSvc === s.name;
              return (
                <button
                  type="button"
                  key={s.name}
                  role="radio"
                  aria-checked={on}
                  className={`hp-svc-option${on ? ' hp-svc-option--selected' : ''}`}
                  onClick={() => pickSvc(s.name)}
                >
                  <span className="hp-svc-option-icon"><Icon name={s.icon} /></span>
                  <span className="hp-svc-option-text">
                    <span className="hp-svc-option-name">{s.label}</span>
                    <span className="hp-svc-option-port">{opt.kind === 'StatefulSet' ? 'sts' : 'deploy'} · :{opt.port}</span>
                  </span>
                  <span className="hp-svc-check">{on && <Icon name="check" />}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="hp-form-row">
          <div className="hp-form-group">
            <label className="hp-form-label" htmlFor="hp-name">Name</label>
            <input
              id="hp-name"
              className="hp-form-input"
              value={formName}
              onChange={e => setFormName(e.target.value)}
              placeholder={svc.defaultName}
              spellCheck={false}
            />
          </div>
          <div className="hp-form-group">
            <label className="hp-form-label" htmlFor="hp-ns">Namespace</label>
            <input
              id="hp-ns"
              className="hp-form-input"
              value={formNs}
              onChange={e => setFormNs(e.target.value)}
              placeholder="production"
              spellCheck={false}
            />
          </div>
        </div>

        <div className="hp-plan" aria-live="polite">
          <div className="hp-plan-row">
            <span className="hp-plan-k">{svc.kind || 'Workload'}</span>
            <span className="hp-plan-v">{name}</span>
          </div>
          <div className="hp-plan-row">
            <span className="hp-plan-k">Service</span>
            <span className="hp-plan-v">{name}.{formNs.trim() || 'namespace'}.svc:{svc.port}</span>
          </div>
          <div className="hp-plan-row">
            <span className="hp-plan-k">Image</span>
            <span className="hp-plan-v">{shortImage(svc.image)}</span>
          </div>
          <div className="hp-plan-note">
            Looks like a regular Helm release: standard app.kubernetes.io labels, no trap markers.
            Tracked by workload UID; connections are correlated with the client pod and service account.
          </div>
        </div>

        {createErr && (
          <div className="hp-create-err" role="alert">{createErr}</div>
        )}
      </div>
      <div className="hp-modal-footer">
        <button className="hp-btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
        <button
          className="hp-btn-primary"
          onClick={handleCreate}
          disabled={creating || !formSvc}
        >
          {creating ? 'Deploying…' : 'Deploy honeypot'}
        </button>
      </div>
    </div>
  </div>
  );
}
