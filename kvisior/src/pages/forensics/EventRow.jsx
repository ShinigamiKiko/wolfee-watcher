import { useState } from 'react';
import { fmtTs, fmtDateOnly } from '../../utils/format';
import { eventKind, KIND_LABEL } from './forensicsHelpers';

export function EventRow({ ev, getSev }) {
  const [open, setOpen] = useState(false);
  const kind = eventKind(ev.syscall);
  const sev = ev._anomaly
    ? 'anomaly'
    : getSev(ev.syscall, ev.execpath, ev.process);
  const { time, ms } = fmtTs(ev.ts);
  const args = ev.args || {};
  const argStr = Object.entries(args).map(([k, v]) => `${k}=${v}`).join(' ');

  return (
    <>
      <div className={`fns-erow fns-erow--${sev}`} onClick={() => setOpen(o => !o)}>
        <div className="fns-cell fns-cell--ts">
          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{fmtDateOnly(ev.ts)}</div>
          <div>{time}<span className="fns-ms">{ms}</span></div>
        </div>
        <div className="fns-cell fns-cell--sev">
          <span className={`fns-sev fns-sev--${sev}`}>{sev}</span>
          {kind !== 'syscall' && <span className={`fns-kind fns-kind--${kind}`}>{KIND_LABEL[kind]}</span>}
        </div>
        <div className="fns-cell"><span className="fns-stag">{ev.syscall}</span></div>
        <div className="fns-cell fns-cell--cmd">
          {ev.execpath && <span className="fns-bin">{ev.execpath.split('/').pop()}</span>}
          {ev.cmdline  && <span className="fns-arg"> {ev.cmdline}</span>}
          {!ev.cmdline && argStr && <span className="fns-arg">{argStr}</span>}
        </div>
        <div className="fns-cell fns-cell--proc">{ev.process}</div>
        <div className="fns-cell fns-cell--cid" title={ev.containerId || ev.container || ''}>
          {ev.containerId
            ? <span>{ev.containerId.slice(0, 8)}</span>
            : <span style={{color:'var(--text-muted)'}}>—</span>
          }
        </div>
        <div className="fns-cell fns-cell--pid">{ev.pid}</div>
      </div>
      {open && (
        <div className="fns-erow-detail">
          <div className="fns-detail-grid">
            <div className="fns-dfield"><span className="fns-dkey">Event type</span><span className={`fns-dval${kind === 'lsm' ? ' fns-dval--purple' : ''}`}>{KIND_LABEL[kind]}</span></div>
            <div className="fns-dfield"><span className="fns-dkey">Process</span><span className="fns-dval fns-dval--purple">{ev.process}</span></div>
            <div className="fns-dfield"><span className="fns-dkey">PID</span><span className="fns-dval">{ev.pid}</span></div>
            <div className="fns-dfield"><span className="fns-dkey">UID</span><span className={`fns-dval${ev.uid === 0 ? ' fns-dval--red' : ''}`}>{ev.uid === 0 ? '0 (root)' : ev.uid}</span></div>
            <div className="fns-dfield"><span className="fns-dkey">Node</span><span className="fns-dval">{ev.node}</span></div>
            {ev.execpath && <div className="fns-dfield"><span className="fns-dkey">Execpath</span><span className="fns-dval">{ev.execpath}</span></div>}
            {ev.container && <div className="fns-dfield"><span className="fns-dkey">Container</span><span className="fns-dval fns-dval--purple">{ev.container}</span></div>}
            {ev.image && <div className="fns-dfield"><span className="fns-dkey">Image</span><span className="fns-dval">{ev.image}</span></div>}
            <div className="fns-dfield"><span className="fns-dkey">Timestamp</span><span className="fns-dval">{ev.ts}</span></div>
            {Object.entries(args).map(([k, v]) => (
              <div key={k} className="fns-dfield">
                <span className="fns-dkey">{k}</span>
                <span className={`fns-dval${k === 'domain' && (v === 'AF_NETLINK' || v === '16') ? ' fns-dval--red' : ''}`}>{String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
