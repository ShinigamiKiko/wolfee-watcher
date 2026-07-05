import { kindMeta } from './alertsUtils';
import { RowActions } from './AlertsUi';
import { fmtDateOnly, fmtClock } from '../../utils/format';

export function AlertsList({ visible, status, groupFilter, selected, setSelected, ackEvent, fpEvent, deleteEvent }) {
  return (
  <div className="al-list">
    {visible.length === 0 && (
      <div className="al-empty">
        {status === 'connecting'
          ? 'Connecting to anomaly stream…'
          : groupFilter === 'images'
            ? 'No digest changes in the last hour'
            : 'No alerts match the current filter'}
      </div>
    )}
    {visible.map(ev => {
      const m = kindMeta(ev.kind);

      if (ev._isDigest) {
        return (
          <div
            key={ev.id}
            className={`al-row al-row--danger${selected?.id===ev.id?' al-row--sel':''}`}
            onClick={() => setSelected(s => s?.id===ev.id ? null : ev)}
          >
            <span className="al-time">{fmtDateOnly(ev.ts)}<br/>{fmtClock(ev.ts)}</span>
            <span className="al-kind-icon" style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, fontWeight: 700 }}>D</span>
            <div className="al-row-main">
              <span className="al-event-desc">
                <span className="al-pod">{ev.src_pod}</span>
              </span>
            </div>
            <RowActions ev={ev} onAck={ackEvent} onFp={fpEvent} onDelete={deleteEvent} />
          </div>
        );
      }

      if (ev._isHoneypot || ev.kind === 'honeypot_probe') {
        const trap = ev.honeypotName || ev.src_pod || '—';
        const svc  = (ev.server || '').replace('_server', '');
        const src  = ev.src_ip ? `${ev.src_ip}${ev.src_port ? ':'+ev.src_port : ''}` : '—';
        const tgtIP = (ev.dst_ip && ev.dst_ip !== '0.0.0.0') ? ev.dst_ip : '';
        const tgt  = tgtIP
          ? `${tgtIP}${ev.dst_port ? ':'+ev.dst_port : ''}`
          : (ev.dst_port ? `${trap}:${ev.dst_port}` : trap);
        return (
          <div
            key={ev.id}
            className={`al-row al-row--${m.color}${selected?.id===ev.id?' al-row--sel':''}`}
            onClick={() => setSelected(s => s?.id===ev.id ? null : ev)}
          >
            <span className="al-time">{fmtDateOnly(ev.ts)}<br/>{fmtClock(ev.ts)}</span>
            <span className="al-kind-icon">{m.icon}</span>
            <div className="al-row-main">
              <span className="al-event-desc">
                <span className="al-pod">{src}</span>
                <span className="al-arrow"> → </span>
                <span className="al-dest">{tgt}</span>
              </span>
              <span className="al-kind-label">
                {m.label} · {trap}{svc ? ` (${svc})` : ''}
              </span>
            </div>
            <RowActions ev={ev} onAck={ackEvent} onFp={fpEvent} onDelete={deleteEvent} />
          </div>
        );
      }

      const pod  = ev.src_pod  || `${ev.src_deployment}`;
      const dest = ev.dst_ip ? `${ev.dst_ip}${ev.dst_port ? ':'+ev.dst_port : ''}` : '—';
      return (
        <div
          key={ev.id}
          className={`al-row al-row--${m.color}${selected?.id===ev.id?' al-row--sel':''}`}
          onClick={() => setSelected(s => s?.id===ev.id ? null : ev)}
        >
          <span className="al-time">{fmtDateOnly(ev.ts)}<br/>{fmtClock(ev.ts)}</span>
          <span className="al-kind-icon">{m.icon}</span>
          <div className="al-row-main">
            <span className="al-event-desc">
              <span className="al-pod">{pod}</span>
              <span className="al-arrow"> → </span>
              <span className="al-dest">{dest}</span>
              {ev.protocol && <span className="al-proto">{ev.protocol}</span>}
            </span>
            <span className="al-kind-label">{ev.syscall ? `${ev.syscall} · ${m.label}` : m.label}</span>
          </div>
          <RowActions ev={ev} onAck={ackEvent} onFp={fpEvent} onDelete={deleteEvent} />
        </div>
      );
    })}
  </div>
  );
}
