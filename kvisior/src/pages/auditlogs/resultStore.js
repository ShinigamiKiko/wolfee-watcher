const KEY = 'kvisior.audit.investigation';
const SIZE_KEY = 'kvisior.audit.investigation.pageSize';
const VERSION = 1;

export const PAGE_SIZES = [50, 100];

export function loadResults(cluster) {
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) || 'null');
    if (!saved || saved.v !== VERSION || saved.cluster !== cluster) return null;
    return saved;
  } catch {
    return null;
  }
}

export function saveResults(cluster, state) {
  try {
    localStorage.setItem(KEY, JSON.stringify({ v: VERSION, cluster, ...state }));
  } catch {
    try { localStorage.removeItem(KEY); } catch {}
  }
}

export function clearResults() {
  try { localStorage.removeItem(KEY); } catch {}
}

export function loadPageSize() {
  try {
    const n = Number(localStorage.getItem(SIZE_KEY));
    return PAGE_SIZES.includes(n) ? n : PAGE_SIZES[0];
  } catch {
    return PAGE_SIZES[0];
  }
}

export function savePageSize(n) {
  try { localStorage.setItem(SIZE_KEY, String(n)); } catch {}
}
