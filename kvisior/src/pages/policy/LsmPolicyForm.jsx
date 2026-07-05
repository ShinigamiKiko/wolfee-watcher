import { HookPolicyForm } from './HookPolicyForm';
import { LSM_HOOKS, LSM_GROUPS } from '../lsm/lsmCatalog';

export function LsmPolicyForm(props) {
  return (
    <HookPolicyForm
      {...props}
      catalog={LSM_HOOKS}
      groups={LSM_GROUPS}
      detType="LSM"
      idPrefix="lsm"
      eventNoun="LSM hook"
      pathPlaceholder="e.g. /etc/shadow  (or type a custom path…)"
    />
  );
}
