function _yaml(obj, depth) {
  const pad = '  '.repeat(depth);
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean' || typeof obj === 'number') return String(obj);
  if (typeof obj === 'string') {
    if (!obj) return '""';
    if (obj.length > 100) return '<...>';
    if (obj.includes('\n')) return '|\n' + obj.split('\n').map(l => pad + '  ' + l).join('\n');
    if (/[:#{}[\],&*?|<>=!%@`]/.test(obj)) return JSON.stringify(obj);
    return obj;
  }
  if (Array.isArray(obj)) {
    if (!obj.length) return '[]';
    return obj.map(v => {
      const s = _yaml(v, depth + 1);
      return '\n' + pad + '- ' + (s.startsWith('\n') ? s.trimStart() : s);
    }).join('');
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj);
    if (!keys.length) return '{}';
    return keys.map(k => {
      const v = obj[k];
      const s = _yaml(v, depth + 1);
      if ((typeof v === 'object' && v !== null && Object.keys(v).length) || (Array.isArray(v) && v.length))
        return '\n' + pad + k + ':' + s;
      return '\n' + pad + k + ': ' + s;
    }).join('');
  }
  return String(obj);
}

function truncateLong(obj) {
  if (typeof obj === 'string') {
    if (obj.length > 100 && obj.indexOf(' ') === -1 && obj.indexOf('\n') === -1)
      return obj.slice(0, 80) + '… [' + obj.length + ' chars]';
    return obj;
  }
  if (Array.isArray(obj)) return obj.map(truncateLong);
  if (obj && typeof obj === 'object') {
    const res = {};
    Object.keys(obj).forEach(k => { res[k] = truncateLong(obj[k]); });
    return res;
  }
  return obj;
}

export function toYaml(raw) {
  let obj = Object.fromEntries(Object.entries(raw).filter(([k]) => !k.startsWith('_')));
  if (obj.metadata) {
    const m = { ...obj.metadata };
    delete m.managedFields; delete m.resourceVersion; delete m.uid; delete m.generation;
    if (m.annotations) {
      const a = { ...m.annotations };
      delete a['kubectl.kubernetes.io/last-applied-configuration'];
      m.annotations = Object.keys(a).length ? a : undefined;
    }
    obj.metadata = m;
  }
  obj = truncateLong(obj);
  const ordered = {};
  if (obj.apiVersion) ordered.apiVersion = obj.apiVersion;
  if (obj.kind)       ordered.kind       = obj.kind;
  Object.keys(obj).forEach(k => { if (k !== 'apiVersion' && k !== 'kind') ordered[k] = obj[k]; });
  const s = _yaml(ordered, 0);
  return s.startsWith('\n') ? s.slice(1) : s;
}
