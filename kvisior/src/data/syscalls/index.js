export * from './list';

export function matchesRule(event, rule) {
  if (!event || !rule || rule.enabled === false) return false;

  const rawEv = event._raw || event;

  const syscall  = rawEv.syscall    || event.syscall    || '';
  const category = rawEv.category   || event.category   || '';
  const ns       = rawEv.namespace  || event.namespace  || '';
  const pod      = rawEv.pod        || event.pod        || '';

  const args         = rawEv.args || event.args || {};
  const argsPathname = (typeof args.pathname === 'string') ? args.pathname : '';
  const argsArgv     = Array.isArray(args.argv)
    ? args.argv.join(' ')
    : (typeof args.argv === 'string' ? args.argv : '');

  const process  = rawEv.process  || event.process  || argsPathname.split('/').pop() || '';
  const execpath = rawEv.execpath || event.execpath || argsPathname || '';
  const cmdline  = rawEv.cmdline  || event.cmdline  || argsArgv || '';

  if (rule.syscall && rule.syscall !== '*') {
    if (syscall !== rule.syscall) return false;
  }

  if (rule.category && rule.category !== '*' && rule.detType !== 'Binary') {
    if (category !== rule.category) return false;
  }

  if (rule.namespace && !ns.includes(rule.namespace)) return false;

  if (rule.podPattern) {
    const pat = rule.podPattern.replace(/\*/g, '');
    if (rule.podPattern.endsWith('*')) {
      if (!pod.startsWith(pat)) return false;
    } else if (rule.podPattern.startsWith('*')) {
      if (!pod.endsWith(pat)) return false;
    } else {
      if (!pod.includes(rule.podPattern)) return false;
    }
  }

  const EXEC_SYSCALLS = new Set(['execve', 'execveat', 'sched_process_exec']);
  if (rule.processFilter) {
    if (!EXEC_SYSCALLS.has(syscall)) return false;
    const pf   = rule.processFilter.toLowerCase();
    const proc = process.toLowerCase();
    const ep   = execpath.toLowerCase();
    const cmd0 = cmdline.toLowerCase().split(' ')[0];
    const matched =
      proc === pf             ||
      proc.endsWith('/' + pf) ||
      ep.includes('/' + pf)   ||
      ep === pf               ||
      cmd0 === pf             ||
      cmd0.endsWith('/' + pf);
    if (!matched) return false;
  }

  if (rule.pathFilter) {
    const isDup    = syscall === 'dup2'  || syscall === 'dup3';
    const isSocket = syscall === 'socket';
    const isProt   = syscall === 'mmap'  || syscall === 'mprotect';
    if (isDup) {
      const allowed = rule.pathFilter.split(',').map(v => v.trim());
      const newfd   = String(args.newfd ?? '');
      if (!allowed.includes(newfd)) return false;
    } else if (isSocket) {
      const allowed = rule.pathFilter.split(',').map(v => v.trim());
      const rawDomain = args.domain ?? '';
      const AF_MAP = { AF_UNSPEC:'0', AF_UNIX:'1', AF_INET:'2', AF_INET6:'10', AF_NETLINK:'16', AF_PACKET:'17' };
      const domain = AF_MAP[rawDomain] ?? String(rawDomain);
      if (!allowed.includes(domain)) return false;
    } else if (isProt) {
      const allowed = rule.pathFilter.split(',').map(v => v.trim());
      const prot    = String(args.prot ?? '');
      if (!allowed.includes(prot)) return false;
    } else {
      const pf  = rule.pathFilter.replace(/\*/g, '').toLowerCase();
      const cmd = cmdline.toLowerCase();
      const ep  = execpath.toLowerCase();
      const pn  = argsPathname.toLowerCase();
      if (!cmd.includes(pf) && !ep.includes(pf) && !pn.includes(pf) && !argsContain(args, pf)) return false;
    }
  }

  return true;
}

function argsContain(args, needle) {
  if (!needle || !args || typeof args !== 'object') return false;
  return Object.values(args).some(v => valueContains(v, needle));
}

function valueContains(v, needle) {
  if (typeof v === 'string') return v.toLowerCase().includes(needle);
  if (typeof v === 'number') return String(v).includes(needle);
  if (Array.isArray(v))      return v.some(x => valueContains(x, needle));
  if (v && typeof v === 'object') {
    const ip   = v.sin_addr || v.sin6_addr || '';
    const port = v.sin_port != null ? String(v.sin_port) : '';
    if ((ip || port) && `${ip}:${port}`.toLowerCase().includes(needle)) return true;
    return Object.values(v).some(x => valueContains(x, needle));
  }
  return false;
}

export function saveRuntimeRules(rules) {
  return fetch('/api/policies', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policies: rules }),
    credentials: 'same-origin',
  })
    .then(r => {
      if (!r.ok) throw new Error(`backend responded ${r.status}`);
      window.dispatchEvent(new CustomEvent('sw-rules-changed'));
      return true;
    })
    .catch(err => {
      window.dispatchEvent(new CustomEvent('sw-rules-save-failed', { detail: { error: String(err) } }));
      return false;
    });
}

export async function fetchRulesFromAPI() {
  try {
    const r = await fetch('/api/policies', { credentials: 'same-origin' });
    if (!r.ok) return null;
    const data = await r.json();
    if (!Array.isArray(data.policies)) return null;
    return data.policies
      .filter(rule => !rule.origin && !rule.id?.startsWith('sys-'))
      .map(rule => ({ ...rule, category: '*' }));
  } catch {
    return null;
  }
}

export async function reconcileRules() {
  const rules = await fetchRulesFromAPI();
  if (rules !== null) {
    window.dispatchEvent(new CustomEvent('sw-rules-changed'));
  }
  return rules ?? [];
}

