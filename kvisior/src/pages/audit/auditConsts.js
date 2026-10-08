export const STATUS_COLOR = { PASS:'var(--ok-text)', FAIL:'var(--danger-text)', WARN:'var(--warning-text)', INFO:'var(--text-dim)' };
export const SEV = {
  critical: { color:'var(--danger-text)',    bg:'var(--danger-tint)',         border:'rgba(239,68,68,0.3)' },
  high:     { color:'var(--warning-text)',   bg:'var(--warning-tint-strong)', border:'rgba(245,158,11,0.35)' },
  medium:   { color:'var(--info)',           bg:'var(--info-tint)',           border:'rgba(99,102,241,0.35)' },
  low:      { color:'var(--text-secondary)', bg:'rgba(255,255,255,0.06)',     border:'var(--border-strong)' },
};
export const sev = s => SEV[s] || SEV.low;
export const SEV_ORDER = { critical:0, high:1, medium:2, low:3 };
export const fmt = d => d ? `${d.toLocaleDateString()} ${d.toLocaleTimeString()}` : '';
