import { SevBadge } from '../../components/ui';

export function DeployDetail({ v, onClose }) {
  if (!v) return null;

  const kv = (k, val) => (
    <div className="dp-kv" key={k}>
      <span>{k}</span>
      <span style={{ textAlign: 'right', maxWidth: '60%', wordBreak: 'break-all' }}>{val ?? '—'}</span>
    </div>
  );

  return (
    <div className="detail-panel open">
      <div className="detail-panel-inner">
        <div className="dp-header">
          <div style={{ minWidth: 0 }}>
            <div className="dp-title" style={{ fontSize: 13 }}>{v.policy}</div>
            <div className="dp-meta">{v.workload} · {v.ns}</div>
          </div>
          <button className="dp-close" onClick={onClose}>✕</button>
        </div>

        <div style={{ marginBottom: 14 }}><SevBadge sev={v.sev} /></div>

        <div style={{ padding: '10px 12px', background: 'rgba(239,68,68,.06)',
          border: '1px solid rgba(239,68,68,.15)', borderRadius: 8, marginBottom: 16,
          fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          {v.detail}
        </div>

        <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.09em', textTransform: 'uppercase',
          color: 'var(--text-muted)', marginBottom: 8, borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
          Workload Details
        </div>

        {kv('Workload',  v.workload)}
        {kv('Kind',      v.kind)}
        {kv('Namespace', v.ns)}
        {kv('Policy',    v.policy)}
        {kv('Check',     v.check)}
        {kv('Action',    v.action || 'alert')}
      </div>
    </div>
  );
}
