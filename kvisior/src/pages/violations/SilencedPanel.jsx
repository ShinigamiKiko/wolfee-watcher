import { ackKey } from './violationsConstants';

export function SilencedPanel({ silenced, doUnsilent, syscallViolations, tracepointViolations = [], lsmViolations = [], buildViolations, deployViolations, auditViolations }) {
  const parseKey = key => {
    if (key.startsWith('sc::'))  { const [,pod,syscall,ns] = key.split('::'); return { tab:'Syscalls',    parts:[pod,syscall,ns] }; }
    if (key.startsWith('tp::'))  { const [,pod,ev,ns]      = key.split('::'); return { tab:'Tracepoints', parts:[pod,ev,ns] }; }
    if (key.startsWith('lsm::')) { const [,pod,ev,ns]      = key.split('::'); return { tab:'LSM Hooks',   parts:[pod,ev,ns] }; }
    if (key.startsWith('bld::')) { const [,image]          = key.split('::'); return { tab:'Build',       parts:[image] }; }
    if (key.startsWith('dep::')) { const [,workload,ns]    = key.split('::'); return { tab:'Deploy',      parts:[workload,ns] }; }
    const [,kind,name,ns]        = key.split('::');                           return { tab:'Audit',       parts:[kind,name,ns] };
  };
  const tabColor = { Syscalls:'var(--accent)', Tracepoints:'#38bdf8', 'LSM Hooks':'#f472b6', Build:'#a78bfa', Deploy:'#34d399', Audit:'#f59e0b' };
  const colLabel = {
    Syscalls:    ['Pod','Syscall','Namespace'],
    Tracepoints: ['Pod','Tracepoint','Namespace'],
    'LSM Hooks': ['Pod','Hook','Namespace'],
    Build:       ['Image'],
    Deploy:      ['Workload','Namespace'],
    Audit:       ['Kind','Name','Namespace'],
  };

  const allViols = [
    ...syscallViolations.map(v    => ({ ...v, _tab:'Syscalls' })),
    ...tracepointViolations.map(v => ({ ...v, _tab:'Tracepoints' })),
    ...lsmViolations.map(v        => ({ ...v, _tab:'LSM Hooks' })),
    ...buildViolations.map(v      => ({ ...v, _tab:'Build' })),
    ...deployViolations.map(v     => ({ ...v, _tab:'Deploy' })),
    ...auditViolations.map(v      => ({ ...v, _tab:'Audit' })),
  ];
  const countByKey = {};
  for (const v of allViols) {
    const k = ackKey(v, v._tab);
    const entry = silenced.get(k);
    if (entry?.type === 'silent') countByKey[k] = (countByKey[k] || 0) + 1;
  }

  const now = Date.now();
  const msToLabel = exp => {
    if (!exp) return null;
    const diff = exp - now;
    if (diff <= 0) return 'expired';
    const d = Math.floor(diff / 86400000);
    const h = Math.floor((diff % 86400000) / 3600000);
    return d > 0 ? `${d}d ${h}h` : `${h}h`;
  };

  const entries = [...silenced.entries()].map(([key, { type, expiresAt }]) => {
    const { tab, parts } = parseKey(key);
    return { key, kind: type === 'fp' ? 'FP' : 'Silent', tab, parts, expiresAt };
  });
  return (
    <div className="card" style={{ marginRight: 24 }}>
      <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 13, fontWeight: 600 }}>Silenced</span>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>— hidden until manually removed</span>
      </div>
      {entries.length === 0 ? (
        <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>No silenced violations</div>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Tab</th><th>Type</th><th>Parameters</th><th>Suppressed</th><th>Expires</th><th></th></tr></thead>
            <tbody>
              {entries.map(({ key, kind, tab, parts, expiresAt }) => {
                const color   = tabColor[tab];
                const labels  = colLabel[tab];
                const expLabel = msToLabel(expiresAt);
                const badge = {
                  Silent:    { bg:'rgba(251,191,36,.12)', fg:'var(--warning)',    bd:'rgba(251,191,36,.3)'  },
                  FP:        { bg:'rgba(100,116,139,.15)', fg:'var(--text-muted)', bd:'rgba(100,116,139,.3)' },
                  ACK:       { bg:'rgba(56,189,248,.12)',  fg:'#38bdf8',           bd:'rgba(56,189,248,.3)'  },
                  DISMISSED: { bg:'rgba(248,113,113,.12)', fg:'var(--danger)',     bd:'rgba(248,113,113,.3)' },
                }[kind] || { bg:'rgba(100,116,139,.15)', fg:'var(--text-muted)', bd:'rgba(100,116,139,.3)' };
                return (
                  <tr key={key}>
                    <td>
                      <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                        background: `${color}22`, color, border: `1px solid ${color}44`, fontFamily: 'monospace' }}>
                        {tab}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                        background: badge.bg, color: badge.fg, border: `1px solid ${badge.bd}` }}>
                        {kind}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11 }}>
                      {parts.map((p, i) => p ? (
                        <span key={i} style={{ marginRight: 10 }}>
                          <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>{labels[i]}: </span>
                          <span style={{ color: 'var(--text-secondary)' }}>{p}</span>
                        </span>
                      ) : null)}
                    </td>
                    <td>
                      {kind === 'Silent' && (countByKey[key] || 0) > 0 && (
                        <span style={{ fontSize: 11, padding: '1px 8px', borderRadius: 10,
                          background: 'rgba(251,191,36,.12)', color: 'var(--warning)',
                          border: '1px solid rgba(251,191,36,.2)', fontWeight: 600 }}>
                          {countByKey[key]}
                        </span>
                      )}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono,monospace', whiteSpace: 'nowrap' }}>
                      {expiresAt ? (expLabel || '—') : '∞'}
                    </td>
                    <td>
                      <button onClick={() => doUnsilent(key)}
                        style={{ fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
                          border: '1px solid rgba(251,191,36,.35)', cursor: 'pointer',
                          background: 'transparent', color: 'var(--warning)' }}
                        onMouseEnter={e => e.currentTarget.style.background = 'rgba(251,191,36,.1)'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                        Unsilent
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
