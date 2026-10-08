import { KIND_META, GROUP_ORDER, GROUP_META } from './alertsConstants';
import { Icon } from '../../components/Icon';

function RowActions({ ev, onAck, onFp, onDelete }) {
  const stop = (fn) => (e) => { e.stopPropagation(); fn(ev); };
  return (
    <div className="al-row-actions" onClick={e => e.stopPropagation()}>
      <button className="al-row-act al-row-act--ack" title="ACK · suppress future events with the same pattern" onClick={stop(onAck)}>ACK</button>
      <button className="al-row-act al-row-act--fp"  title="False positive — move to FP"               onClick={stop(onFp)}>FP</button>
      <button className="al-row-act al-row-act--x"   title="Move to Silent (kept for 1 day, then deleted)" onClick={stop(onDelete)}><Icon name="x" /></button>
    </div>
  );
}

function BucketsPanel({ buckets, silentEvents = [], tab, setTab, onClose, onRestore, onRestoreEvent }) {
  const fmtTs = (ts) => ts ? new Date(ts).toLocaleString() : '—';

  const ackList = Object.values(buckets.ack).sort((a,b) => new Date(b.lastTs || b.createdAt || 0) - new Date(a.lastTs || a.createdAt || 0));
  const fpList  = Object.values(buckets.fp).sort((a,b)  => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

  const tabs = [
    { id: 'events', label: `Silent (${silentEvents.length})`, hint: 'Events hidden with the dismiss button — kept for 1 day, then deleted' },
    { id: 'ack',    label: `ACK (${ackList.length})`,         hint: 'Permanent suppression by pattern (ACK)' },
    { id: 'fp',     label: `FP (${fpList.length})`,           hint: 'Marked as false positive' },
  ];

  return (
    <div className="al-detail al-buckets">
      <div className="al-detail-head">
        <span className="al-detail-kind">Silent</span>
        <button className="al-detail-close" onClick={onClose}><Icon name="x" /></button>
      </div>

      <div className="al-buckets-tabs">
        {tabs.map(t => (
          <button
            key={t.id}
            className={`al-buckets-tab${tab === t.id ? ' al-buckets-tab--active' : ''}`}
            onClick={() => setTab(t.id)}
            title={t.hint}
          >{t.label}</button>
        ))}
      </div>

      <div className="al-detail-body">
        {tab === 'events' && (
          <>
            {silentEvents.length === 0 && <div className="al-bucket-empty">No hidden events</div>}
            {silentEvents.map(ev => (
              <div key={ev.id} className="al-bucket-item">
                <div className="al-bucket-item-main">
                  <div className="al-bucket-summary">{ev.src_pod || ev.src_deployment || ev.kind}</div>
                  <div className="al-bucket-sub mono t-2xs">
                    {ev.kind}{ev.syscall ? ` · ${ev.syscall}` : ''}{ev.dst_ip ? ` → ${ev.dst_ip}${ev.dst_port ? ':'+ev.dst_port : ''}` : ''}
                  </div>
                  <div className="al-bucket-sub">{fmtTs(ev.ts)}</div>
                </div>
                <button className="al-bucket-restore" title="Restore to active" onClick={() => onRestoreEvent(ev)}><Icon name="undo" /></button>
              </div>
            ))}
          </>
        )}

        {tab === 'ack' && (
          <>
            {ackList.length === 0 && <div className="al-bucket-empty">No ACK patterns</div>}
            {ackList.map(it => (
              <div key={it.pattern} className="al-bucket-item">
                <div className="al-bucket-item-main">
                  <div className="al-bucket-summary">{it.summary}</div>
                  <div className="al-bucket-sub">
                    <span className="mono t-2xs">{it.pattern}</span>
                  </div>
                  <div className="al-bucket-sub">
                    {it.count > 0 ? `${it.count}× since open · last ${fmtTs(it.lastTs)}` : `since ${fmtTs(it.createdAt)}`}
                  </div>
                </div>
                <button className="al-bucket-restore" title="Remove suppression" onClick={() => onRestore('ack', it.pattern)}><Icon name="undo" /></button>
              </div>
            ))}
          </>
        )}

        {tab === 'fp' && (
          <>
            {fpList.length === 0 && <div className="al-bucket-empty">No false positives</div>}
            {fpList.map(it => (
              <div key={it.id} className="al-bucket-item">
                <div className="al-bucket-item-main">
                  <div className="al-bucket-summary">{it.summary}</div>
                  <div className="al-bucket-sub">{fmtTs(it.createdAt)}</div>
                </div>
                <button className="al-bucket-restore" title="Remove from false positives" onClick={() => onRestore('fp', it.id)}><Icon name="undo" /></button>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, val, mono }) {
  if (!val && val !== 0) return null;
  return (
    <div className="al-detail-row">
      <span className="al-detail-lbl">{label}</span>
      <span className={`al-detail-val${mono?' al-detail-val--mono':''}`}>{val}</span>
    </div>
  );
}

const REF_COLOR = { warning: 'var(--warning)', danger: 'var(--danger)', info: 'var(--accent)' };

function KindReference({ onClose }) {
  return (
    <div className="al-detail al-kindref">
      <div className="al-detail-head">
        <span className="al-detail-kind">What lands in Anomaly</span>
        <button className="al-detail-close" onClick={onClose}><Icon name="x" /></button>
      </div>

      <div className="al-detail-body al-legend">
        {GROUP_ORDER.map(g => {
          const meta  = GROUP_META[g];
          const kinds = Object.entries(KIND_META).filter(([, m]) => m.group === g);
          if (!meta || kinds.length === 0) return null;
          return (
            <div key={g}>
              <div className="section-label mb-4">{meta.label}</div>
              <div className="t-xs t-muted mb-8">{meta.desc}</div>
              <div className="stack">
                {kinds.map(([k, m]) => (
                  <div key={k} className="row row--top">
                    <span className="al-legend-icon" style={{ '--tone': REF_COLOR[m.color] || 'var(--text-muted)' }}><Icon name={m.icon} /></span>
                    <div className="grow">
                      <div className="row row--wrap t-sm t-strong t-primary">
                        {m.label}
                        <code className="mono t-2xs t-muted">{k}</code>
                      </div>
                      <div className="t-xs t-secondary mt-4">{m.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export { RowActions, BucketsPanel, DetailRow, KindReference };
