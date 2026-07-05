import { PROBE_GROUPS } from './probeCatalog';

export const GROUP_RISK = {
  'Container Escape':           'critical',
  'Process & Memory':          'high',
  'Process Lifecycle':         'high',
  'Privilege':                 'high',
  'Async I/O (io_uring)':      'high',
  'Redirection & Modules':     'high',
  'Security Hooks (LSM)':      'high',
  'Network':                   'medium',
  'Filesystem':                'low',
  'Other':                     'low',
};

export const RISK_COLOR = {
  critical: '#fc8181',
  high:     '#fbbf24',
  medium:   '#a5b4fc',
  low:      '#34d399',
};

const CATALOG = (() => {
  const m = new Map();
  for (const g of PROBE_GROUPS) {
    for (const it of g.items) m.set(it.name, { group: g.label, desc: it.desc });
  }
  return m;
})();

export const CATALOG_NAMES = [...CATALOG.keys()];

export function catalogEntry(name) {
  return CATALOG.get(name) || { group: 'Other', desc: 'eBPF probe emitted by Tracee (not in the curated catalogue).' };
}

const ACTIVE_WINDOW_MS = 60 * 60 * 1000;
const SPARK_BUCKETS = 30;

export function aggregateProbes(events, { includeCatalog = true, now = Date.now() } = {}) {
  const bucketMs    = ACTIVE_WINDOW_MS / SPARK_BUCKETS;
  const windowStart = now - ACTIVE_WINDOW_MS;
  const map = new Map();

  const ensure = (name) => {
    let a = map.get(name);
    if (!a) {
      const meta = catalogEntry(name);
      a = {
        name,
        group:      meta.group,
        desc:       meta.desc,
        risk:       GROUP_RISK[meta.group] || 'low',
        count:      0,
        windowCount: 0,
        lastSeen:   0,
        firstSeen:  0,
        namespaces: new Map(),
        pods:       new Map(),
        nodes:      new Set(),
        buckets:    new Array(SPARK_BUCKETS).fill(0),
        recent:     [],
      };
      map.set(name, a);
    }
    return a;
  };

  if (includeCatalog) for (const n of CATALOG_NAMES) ensure(n);

  for (const e of events) {
    const name = e.syscall || e.name || 'unknown';
    const a = ensure(name);
    a.count++;

    const t = new Date(e.ts).getTime();
    if (!Number.isNaN(t)) {
      if (t > a.lastSeen) a.lastSeen = t;
      if (a.firstSeen === 0 || t < a.firstSeen) a.firstSeen = t;
      if (t >= windowStart) {
        a.windowCount++;
        let idx = Math.floor((t - windowStart) / bucketMs);
        if (idx < 0) idx = 0;
        if (idx >= SPARK_BUCKETS) idx = SPARK_BUCKETS - 1;
        a.buckets[idx]++;
      }
    }

    if (e.namespace) a.namespaces.set(e.namespace, (a.namespaces.get(e.namespace) || 0) + 1);
    if (e.pod)       a.pods.set(e.pod, (a.pods.get(e.pod) || 0) + 1);
    if (e.node)      a.nodes.add(e.node);
    if (a.recent.length < 200) a.recent.push(e);
  }

  const out = [];
  for (const a of map.values()) {
    a.recent.sort((x, y) => new Date(y.ts) - new Date(x.ts));
    a.recent    = a.recent.slice(0, 50);
    a.spark     = a.buckets.map(v => ({ value: v }));
    a.nsCount   = a.namespaces.size;
    a.podCount  = a.pods.size;
    a.nodeCount = a.nodes.size;
    a.active    = a.windowCount > 0;
    out.push(a);
  }
  return out;
}

export function fmtNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

export function riskColor(r) {
  return RISK_COLOR[r] || 'var(--accent)';
}
