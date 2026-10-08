import { ackKey } from './violationsConstants';
import { DataWindow } from '../../components/DataWindow';
import { Pager } from '../../components/Pager';
import { usePaged } from '../../hooks/usePaged';
import { Badge, Tag } from '../../components/kit';

const TAB_TONE = { Syscalls: 'accent', Tracepoints: 'accent', 'LSM Hooks': 'violet', Build: 'violet', Deploy: 'ok', Audit: 'warning' };
const KIND_TONE = { Silent: 'warning', ACK: 'accent', DISMISSED: 'danger' };

export function SilencedPanel({ silenced, doUnsilent, syscallViolations, tracepointViolations = [], lsmViolations = [], buildViolations, deployViolations, auditViolations }) {
  const parseKey = key => {
    if (key.startsWith('sc::'))  { const [,pod,syscall,ns] = key.split('::'); return { tab:'Syscalls',    parts:[pod,syscall,ns] }; }
    if (key.startsWith('tp::'))  { const [,pod,ev,ns]      = key.split('::'); return { tab:'Tracepoints', parts:[pod,ev,ns] }; }
    if (key.startsWith('lsm::')) { const [,pod,ev,ns]      = key.split('::'); return { tab:'LSM Hooks',   parts:[pod,ev,ns] }; }
    if (key.startsWith('bld::')) { const [,image]          = key.split('::'); return { tab:'Build',       parts:[image] }; }
    if (key.startsWith('dep::')) { const [,workload,ns]    = key.split('::'); return { tab:'Deploy',      parts:[workload,ns] }; }
    const [,kind,name,ns]        = key.split('::');                           return { tab:'Audit',       parts:[kind,name,ns] };
  };
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
  const { pageItems: pageEntries, pager } = usePaged(entries, 'violations.silenced');
  return (
    <>
      <div className="section-head">
        <div className="section-title">Silenced <span className="card-sub">hidden until manually removed</span></div>
      </div>
      <DataWindow label="Silenced violations" deps={[entries.length === 0]} footer={<Pager {...pager} noun="entries" />}>
        {entries.length === 0 ? (
          <div className="empty-state empty-state--compact">No silenced violations</div>
        ) : (
          <table className="data-table data-table--static">
            <thead><tr><th>Tab</th><th>Type</th><th>Parameters</th><th>Suppressed</th><th>Expires</th><th aria-label="Actions" /></tr></thead>
            <tbody>
              {pageEntries.map(({ key, kind, tab, parts, expiresAt }) => (
                <tr key={key}>
                  <td><Badge tone={TAB_TONE[tab]}>{tab}</Badge></td>
                  <td><Tag tone={KIND_TONE[kind]}>{kind}</Tag></td>
                  <td className="mono t-xs">
                    <span className="row row--wrap row--loose">
                      {parts.map((part, i) => part ? (
                        <span key={i}><span className="t-muted">{colLabel[tab][i]}: </span>{part}</span>
                      ) : null)}
                    </span>
                  </td>
                  <td>{kind === 'Silent' && (countByKey[key] || 0) > 0 && <Tag tone="warning" mono>{countByKey[key]}</Tag>}</td>
                  <td className="mono t-xs t-muted">{expiresAt ? (msToLabel(expiresAt) || '—') : '∞'}</td>
                  <td className="row-actions-cell">
                    <button type="button" className="btn btn-xs btn-ghost btn-tone-warning" onClick={() => doUnsilent(key)}>Unsilent</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </DataWindow>
    </>
  );
}
