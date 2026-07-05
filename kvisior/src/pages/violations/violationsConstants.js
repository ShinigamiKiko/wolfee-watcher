export const OUTER_TABS = ['Syscalls', 'Tracepoints', 'LSM Hooks', 'Build', 'Deploy', 'Audit'];

export const RUNTIME_TABS = ['Syscalls', 'Tracepoints', 'LSM Hooks'];

export const KIND_COLOR = {
  ClusterRoleBinding: '#f59e0b',
  ClusterRole:        '#f59e0b',
  Role:               '#f59e0b',
  ServiceAccount:     '#a78bfa',
  Namespace:          '#60a5fa',
  NetworkPolicy:      '#60a5fa',
  Pod:                '#34d399',
  MutatingWebhook:    '#f87171',
};

export const ackKey = (v, tab) => {
  if (tab === 'Syscalls')    return `sc::${v.pod||''}::${v.syscall||''}::${v.namespace||''}`;
  if (tab === 'Tracepoints') return `tp::${v.pod||''}::${v.syscall||''}::${v.namespace||''}`;
  if (tab === 'LSM Hooks')   return `lsm::${v.pod||''}::${v.syscall||''}::${v.namespace||''}`;
  if (tab === 'Build')       return `bld::${v.image||''}`;
  if (tab === 'Deploy')      return `dep::${v.workload||''}::${v.ns||''}`;
  return `aud::${v.kind||''}::${v.name||''}::${v.ns||''}`;
};

const DAY_MS = 24 * 60 * 60 * 1000;
const dayBucket = (now = Date.now()) => {
  const tzShift = new Date(now).getTimezoneOffset() * 60 * 1000;
  return Math.floor((now - tzShift) / DAY_MS);
};

export const fpKey = (v, tab) => {
  if (tab === 'Syscalls')    return v._fp || '';
  if (tab === 'Tracepoints') return v._fp || '';
  if (tab === 'LSM Hooks')   return v._fp || '';
  if (tab === 'Audit')       return v._fp || '';
  if (tab === 'Build')    return `bld::${v._policyId||''}::${v.image||''}::${v._check||''}::${dayBucket()}`;
  if (tab === 'Deploy')   return `dep::${v._policyId||''}::${v.workload||''}::${v.ns||''}::${v.check||''}::${dayBucket()}`;
  return '';
};
