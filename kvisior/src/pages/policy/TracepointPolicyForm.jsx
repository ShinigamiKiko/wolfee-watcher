import { HookPolicyForm } from './HookPolicyForm';
import { TRACEPOINTS, TRACEPOINT_GROUPS } from '../tracepoints/tracepointsCatalog';

export function TracepointPolicyForm(props) {
  return (
    <HookPolicyForm
      {...props}
      catalog={TRACEPOINTS}
      groups={TRACEPOINT_GROUPS}
      detType="Tracepoint"
      idPrefix="tp"
      eventNoun="Tracepoint"
      pathPlaceholder="e.g. /usr/bin  (or type a custom path…)"
    />
  );
}
