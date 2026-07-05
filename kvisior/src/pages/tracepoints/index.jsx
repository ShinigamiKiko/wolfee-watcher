import { PolicyBuilder } from '../policybuilder/PolicyBuilder';
import { TRACEPOINTS } from './tracepointsCatalog';

export function Tracepoints() {
  return (
    <PolicyBuilder
      title="Tracepoints"
      catalog={TRACEPOINTS}
      storageKey="kvisior.policy.tracepoints"
    />
  );
}
