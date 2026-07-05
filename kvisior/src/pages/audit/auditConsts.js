export const STATUS_COLOR = { PASS:'var(--accent-3)', FAIL:'var(--danger)', WARN:'var(--warning)', INFO:'var(--text-muted)' };
export const SEV = {
  critical: { color:'#f87171', bg:'rgba(248,113,113,0.1)',  border:'rgba(248,113,113,0.25)' },
  high:     { color:'#fb923c', bg:'rgba(251,146,60,0.1)',   border:'rgba(251,146,60,0.25)' },
  medium:   { color:'#fbbf24', bg:'rgba(251,191,36,0.1)',   border:'rgba(251,191,36,0.25)' },
  low:      { color:'#94a3b8', bg:'rgba(148,163,184,0.08)', border:'rgba(148,163,184,0.2)' },
};
export const sev = s => SEV[s] || SEV.low;
export const SEV_ORDER = { critical:0, high:1, medium:2, low:3 };
export const fmt = d => d ? `${d.toLocaleDateString()} ${d.toLocaleTimeString()}` : '';
