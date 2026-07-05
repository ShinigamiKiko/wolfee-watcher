import { PolicyBuilder } from '../policybuilder/PolicyBuilder';
import { SYSCALL_EVENTS } from './syscallsCatalog';

export function Syscalls() {
  return (
    <PolicyBuilder
      title="Syscalls"
      catalog={SYSCALL_EVENTS}
      storageKey="kvisior.policy.syscalls"
    />
  );
}
