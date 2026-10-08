import { Icon } from '../../components/Icon';
export function EvDetail({ ev }) {
  if (!ev) return (
    <div className="rn-ev-detail-empty">
      <Icon name="hexagon" size={24} className="t-muted" />
      <span>Click an event to inspect</span>
    </div>
  );
  const isBlocked  = ev.kind==='blocked'||ev.kind==='policy_blocked'||ev.action==='deny';
  const typeTone   = isBlocked ? 't-danger' : 't-warning';
  const isInternal = ip => ip?.startsWith('10.')||ip?.startsWith('172.')||ip?.startsWith('192.168.');
  return (
    <div className="rn-ev-detail">
      <div className={`rn-ev-detail-hdr ${isBlocked ? 'is-blocked' : 'is-anomaly'}`}>
        <div className="rn-ev-detail-title">{ev.src_namespace} / {ev.src_deployment||ev.src_pod}</div>
        <div className="rn-ev-detail-sub">{ev.syscall ? `${ev.syscall} · ${ev.kind?.replace(/_/g,' ')}` : ev.kind?.replace(/_/g,' ')} · {new Date(ev.ts||ev.timestamp||Date.now()).toLocaleTimeString()}</div>
      </div>
      <div className="rn-ev-detail-sec">
        <div className="rn-ev-detail-sec-title">Source <span className="rn-ev-ns-badge">{ev.src_namespace}</span></div>
        <div className="rn-kv"><span>Deployment</span><span>{ev.src_deployment||'—'}</span></div>
        <div className="rn-kv"><span>Pod</span><span>{ev.src_pod||'—'}</span></div>
        <div className="rn-kv"><span>Namespace</span><span>{ev.src_namespace||'—'}</span></div>
        <div className="rn-kv"><span>Label</span><span className="t-accent">app={ev.src_deployment||ev.src_pod||'—'}</span></div>
        <div className="rn-kv"><span>Pod IP</span><span>{ev.src_ip||'—'}</span></div>
      </div>
      <div className="rn-ev-detail-sec">
        <div className="rn-ev-detail-sec-title">
          Destination <span className="rn-ev-ns-badge rn-ev-ns-badge--dst">{isInternal(ev.dst_ip)?'internal':'external'}</span>
        </div>
        <div className="rn-kv"><span>IP</span><span className={typeTone}>{ev.dst_ip||'—'}</span></div>
        <div className="rn-kv"><span>Port / Proto</span><span className="t-violet">{ev.dst_port?`${ev.dst_port} / TCP`:'—'}</span></div>
        <div className="rn-kv"><span>Service</span><span>{ev.dst_name||ev.dst_service||'—'}</span></div>
      </div>
      <div className="rn-ev-detail-sec">
        <div className="rn-ev-detail-sec-title">Status</div>
        <div className="rn-kv">
          <span>Type</span>
          <span className={`rn-ev-pill ${isBlocked?'rn-ev-pill--blocked':'rn-ev-pill--anomaly'}`}>{isBlocked?<><Icon name="ban" /> blocked</>:<><Icon name="zap" /> anomaly</>}</span>
        </div>
      </div>
    </div>
  );
}

