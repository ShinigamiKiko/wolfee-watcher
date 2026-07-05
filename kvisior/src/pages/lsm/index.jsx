import { PolicyBuilder } from '../policybuilder/PolicyBuilder';
import { LSM_HOOKS } from './lsmCatalog';

function lsmExtra(hook) {
  return (
    <div className="probes-dp-section">
      <div className="probes-dp-section-title">Point of use — why TOCTOU-safe</div>
      <p className="probes-dp-desc">{hook.toctou}</p>
      <div className="pb-kv">
        <span className="pb-kv-key">Backstops</span>
        <span className="pb-chips">
          {hook.backstops.map(b => <span className="pb-chip" key={b}>{b}</span>)}
        </span>
      </div>
    </div>
  );
}

export function Lsm() {
  return (
    <PolicyBuilder
      title="LSM Hooks"
      catalog={LSM_HOOKS}
      storageKey="kvisior.policy.lsm"
      renderExtra={lsmExtra}
    />
  );
}
