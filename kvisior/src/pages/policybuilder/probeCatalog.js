import { SYSCALL_GROUPS } from '../forensics/watchableSyscalls';
import { TRACEPOINTS } from '../tracepoints/tracepointsCatalog';
import { SYSCALL_EVENTS } from '../syscalls/syscallsCatalog';
import { LSM_HOOKS } from '../lsm/lsmCatalog';


const syscallNames = new Set(SYSCALL_GROUPS.flatMap(g => g.items.map(i => i.name)));

const builderSyscalls = {
  label: 'Process Lifecycle',
  items: SYSCALL_EVENTS
    .filter(s => !syscallNames.has(s.name))
    .map(s => ({ name: s.name, desc: s.desc })),
};

const tracepointGroup = {
  label: 'Kernel Tracepoints',
  items: TRACEPOINTS.map(t => ({ name: t.name, desc: t.desc })),
};

const lsmGroup = {
  label: 'Security Hooks (LSM)',
  items: LSM_HOOKS.map(h => ({ name: h.name, desc: h.desc })),
};

export const PROBE_GROUPS = [...SYSCALL_GROUPS, builderSyscalls, tracepointGroup, lsmGroup];

export const PROBE_NAMES = PROBE_GROUPS.flatMap(g => g.items.map(i => i.name));
