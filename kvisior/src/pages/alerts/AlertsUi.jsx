import { KIND_META, GROUP_ORDER, GROUP_META } from './alertsConstants';

function RowActions({ ev, onAck, onFp, onDelete }) {
  const stop = (fn) => (e) => { e.stopPropagation(); fn(ev); };
  return (
    <div className="al-row-actions" onClick={e => e.stopPropagation()}>
      <button className="al-row-act al-row-act--ack" title="ACK · подавить будущие события того же паттерна" onClick={stop(onAck)}>ACK</button>
      <button className="al-row-act al-row-act--fp"  title="False positive — переместить в FP"               onClick={stop(onFp)}>FP</button>
      <button className="al-row-act al-row-act--x"   title="Переместить в Silent (хранится 1 день, затем удаляется)" onClick={stop(onDelete)}>✕</button>
    </div>
  );
}

function BucketsPanel({ buckets, silentEvents = [], tab, setTab, onClose, onRestore, onRestoreEvent }) {
  const fmtTs = (ts) => ts ? new Date(ts).toLocaleString() : '—';

  const ackList = Object.values(buckets.ack).sort((a,b) => new Date(b.lastTs || b.createdAt || 0) - new Date(a.lastTs || a.createdAt || 0));
  const fpList  = Object.values(buckets.fp).sort((a,b)  => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

  const tabs = [
    { id: 'events', label: `Silent (${silentEvents.length})`, hint: 'События, скрытые кнопкой ✕ — хранятся 1 день, затем удаляются из БД' },
    { id: 'ack',    label: `ACK (${ackList.length})`,         hint: 'Постоянное подавление по паттерну (ACK)' },
    { id: 'fp',     label: `FP (${fpList.length})`,           hint: 'Помеченные как false positive' },
  ];

  return (
    <div className="al-detail al-buckets">
      <div className="al-detail-head">
        <span className="al-detail-kind">Silent</span>
        <button className="al-detail-close" onClick={onClose}>✕</button>
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
            {silentEvents.length === 0 && <div className="al-bucket-empty">Нет скрытых событий</div>}
            {silentEvents.map(ev => (
              <div key={ev.id} className="al-bucket-item">
                <div className="al-bucket-item-main">
                  <div className="al-bucket-summary">{ev.src_pod || ev.src_deployment || ev.kind}</div>
                  <div className="al-bucket-sub" style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 10 }}>
                    {ev.kind}{ev.syscall ? ` · ${ev.syscall}` : ''}{ev.dst_ip ? ` → ${ev.dst_ip}${ev.dst_port ? ':'+ev.dst_port : ''}` : ''}
                  </div>
                  <div className="al-bucket-sub">{fmtTs(ev.ts)}</div>
                </div>
                <button className="al-bucket-restore" title="Вернуть в активные" onClick={() => onRestoreEvent(ev)}>↺</button>
              </div>
            ))}
          </>
        )}

        {tab === 'ack' && (
          <>
            {ackList.length === 0 && <div className="al-bucket-empty">Нет ACK-паттернов</div>}
            {ackList.map(it => (
              <div key={it.pattern} className="al-bucket-item">
                <div className="al-bucket-item-main">
                  <div className="al-bucket-summary">{it.summary}</div>
                  <div className="al-bucket-sub">
                    <span style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 10 }}>{it.pattern}</span>
                  </div>
                  <div className="al-bucket-sub">
                    {it.count > 0 ? `${it.count}× since open · last ${fmtTs(it.lastTs)}` : `since ${fmtTs(it.createdAt)}`}
                  </div>
                </div>
                <button className="al-bucket-restore" title="Снять подавление" onClick={() => onRestore('ack', it.pattern)}>↺</button>
              </div>
            ))}
          </>
        )}

        {tab === 'fp' && (
          <>
            {fpList.length === 0 && <div className="al-bucket-empty">Нет FP</div>}
            {fpList.map(it => (
              <div key={it.id} className="al-bucket-item">
                <div className="al-bucket-item-main">
                  <div className="al-bucket-summary">{it.summary}</div>
                  <div className="al-bucket-sub">{fmtTs(it.createdAt)}</div>
                </div>
                <button className="al-bucket-restore" title="Убрать из FP" onClick={() => onRestore('fp', it.id)}>↺</button>
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
        <button className="al-detail-close" onClick={onClose}>✕</button>
      </div>

      <div className="al-detail-body" style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
        {GROUP_ORDER.map(g => {
          const meta  = GROUP_META[g];
          const kinds = Object.entries(KIND_META).filter(([, m]) => m.group === g);
          if (!meta || kinds.length === 0) return null;
          return (
            <div key={g}>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
                {meta.label}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', margin: '3px 0 10px', lineHeight: 1.5 }}>
                {meta.desc}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {kinds.map(([k, m]) => (
                  <div key={k} style={{ display: 'flex', gap: 9, alignItems: 'flex-start' }}>
                    <span style={{
                      flexShrink: 0, width: 18, height: 18, borderRadius: 4,
                      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 11, marginTop: 1,
                      color: REF_COLOR[m.color] || 'var(--text-muted)',
                      background: `color-mix(in srgb, ${REF_COLOR[m.color] || 'var(--text-muted)'} 14%, transparent)`,
                      border: `1px solid color-mix(in srgb, ${REF_COLOR[m.color] || 'var(--text-muted)'} 35%, transparent)`,
                    }}>{m.icon}</span>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        {m.label}
                        <code style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 10, color: 'var(--text-muted)', fontWeight: 400 }}>{k}</code>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5, marginTop: 2 }}>{m.desc}</div>
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
