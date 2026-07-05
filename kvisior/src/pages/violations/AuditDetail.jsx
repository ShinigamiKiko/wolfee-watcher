import { SevBadge } from '../../components/ui';

const KIND_ICON = {
  exec:        '🖥️',
  attach:      '🔌',
  portforward: '🔗',
  create:      '➕',
  update:      '✏️',
  delete:      '🗑️',
  unknown:     '❓',
};

const KIND_COLOR = {
  exec:        'rgba(239,68,68,.12)',
  attach:      'rgba(239,68,68,.12)',
  portforward: 'rgba(245,158,11,.10)',
  create:      'rgba(59,130,246,.08)',
  update:      'rgba(245,158,11,.08)',
  delete:      'rgba(239,68,68,.10)',
};

export function AuditDetail({ v, onClose }) {
  if (!v) return null;

  const kv = (label, val) => val ? (
    <div className="dp-kv" key={label}>
      <span>{label}</span>
      <span style={{ textAlign: 'right', maxWidth: '60%', wordBreak: 'break-all' }}>{val}</span>
    </div>
  ) : null;

  const ts = v.timestamp ? new Date(v.timestamp).toLocaleString() : '—';
  const icon  = KIND_ICON[v.kind]  || KIND_ICON.unknown;
  const bgCol = KIND_COLOR[v.kind] || 'rgba(100,100,100,.06)';

  return (
    <div className="detail-panel open">
      <div className="detail-panel-inner">
        <div className="dp-header">
          <div style={{ minWidth: 0 }}>
            <div className="dp-title" style={{ fontSize: 13 }}>
              {icon} {v.policy}
            </div>
            <div className="dp-meta">{v.kind} · {v.resource} · {v.ns}</div>
          </div>
          <button className="dp-close" onClick={onClose}>✕</button>
        </div>

        {}
        <div style={{ marginBottom: 14, display: 'flex', gap: 8, alignItems: 'center' }}>
          <SevBadge sev={v.sev} />
          <span style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-elevated)',
            padding: '2px 8px', borderRadius: 6, border: '1px solid var(--border)', fontFamily: 'monospace' }}>
            {v.kind}
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-elevated)',
            padding: '2px 8px', borderRadius: 6, border: '1px solid var(--border)', fontFamily: 'monospace' }}>
            {v.check}
          </span>
        </div>

        {}
        <div style={{ padding: '10px 12px', background: bgCol,
          border: `1px solid ${bgCol.replace('.', ',.3').replace('rgba(', 'rgba(')}`,
          borderRadius: 8, marginBottom: 14, fontSize: 12,
          color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          <strong>{v.user || 'unknown'}</strong>
          {v.groups?.length ? <span style={{ color: 'var(--text-muted)' }}> [{v.groups.join(', ')}]</span> : null}
          {' performed '}
          <strong>{v.kind}</strong>
          {v.resource ? <> on <strong>{v.resource}</strong></> : null}
          {v.name ? <> · <code style={{ fontSize: 11 }}>{v.name}</code></> : null}
          {v.ns ? <> in <strong>{v.ns}</strong></> : null}
        </div>

        {}
        {(v.commands?.length || v.container) && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.09em', textTransform: 'uppercase',
              color: 'var(--text-muted)', marginBottom: 6, borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
              Exec Details
            </div>
            {kv('Container', v.container)}
            {v.commands?.length ? kv('Command', v.commands.join(' ')) : null}
          </div>
        )}

        {}
        {v.ports?.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.09em', textTransform: 'uppercase',
              color: 'var(--text-muted)', marginBottom: 6, borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
              Port Forward
            </div>
            {kv('Ports', v.ports.join(', '))}
          </div>
        )}

        {}
        <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.09em', textTransform: 'uppercase',
          color: 'var(--text-muted)', marginBottom: 8, borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
          Event Details
        </div>
        {kv('Time',      ts)}
        {kv('User',      v.user)}
        {kv('Groups',    v.groups?.join(', '))}
        {kv('Source IPs', v.sourceIPs?.join(', '))}
        {kv('Resource',  v.resource)}
        {kv('Name',      v.name)}
        {kv('Namespace', v.ns)}
        {kv('Policy',    v.policy)}
        {kv('Action',    v.action || 'alert')}
      </div>
    </div>
  );
}
