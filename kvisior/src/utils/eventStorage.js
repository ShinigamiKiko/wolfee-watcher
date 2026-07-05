
export function loadStored(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw != null ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

export function saveStored(key, val) {
  try {
    localStorage.setItem(key, JSON.stringify(val));
    return val;
  } catch {
    if (Array.isArray(val) && val.length > 1) {
      try {
        const half = val.slice(0, val.length >> 1);
        localStorage.setItem(key, JSON.stringify(half));
        return half;
      } catch {}
    }
    return val;
  }
}

export function clearStored(...keys) {
  keys.forEach(k => { try { localStorage.removeItem(k); } catch {} });
}
