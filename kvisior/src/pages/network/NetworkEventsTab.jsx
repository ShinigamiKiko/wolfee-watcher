import { useState, useEffect, useRef } from 'react';

import { EvDetail }  from './NetworkEvDetail';
import { PolPicker } from './NetworkPolPicker';

export function NetworkEventsTab({ anomalies }) {
  const [selectedEv,   setSelectedEv]   = useState(null);
  const [pickerEv,     setPickerEv]     = useState(null);
  const [pickerAnchor, setPickerAnchor] = useState(null);

  const NETWORK_KINDS = new Set([
    'port_scan','suspicious_port','unauthorized_flow',
    'policy_blocked','raw_socket','suspicious_bind','connect',
  ]);
  const networkOnly = anomalies.filter(e => NETWORK_KINDS.has(e.kind) || e.dst_ip);
  const anomalyCount = networkOnly.filter(e=>e.kind!=='policy_blocked').length;
  const blockedCount = networkOnly.filter(e=>e.kind==='policy_blocked').length;
  const filtered = networkOnly;

  return (
    <div className="rn-ev-layout">
      <div className="rn-ev-list">

        <div className="rn-ev-hdr">
          <span>Time</span><span>Source</span><span>Destination</span><span>Port</span><span>Type</span><span>Action</span>
        </div>
        {filtered.length===0&&<div style={{padding:40,textAlign:'center',color:'var(--text-muted)',fontSize:12}}>No events</div>}
        {filtered.map((ev,i)=>{
          const isBlocked = ev.kind==='blocked'||ev.kind==='policy_blocked'||ev.action==='deny';
          return (
            <div key={i} className={`rn-ev-row${selectedEv===ev?' selected':''}${isBlocked?' blocked':''}`} onClick={()=>setSelectedEv(ev)}>
              <span className="rn-mono rn-muted">{new Date(ev.ts||ev.timestamp||Date.now()).toLocaleTimeString()}</span>
              <span className="rn-mono">{ev.src_namespace}/<b>{ev.src_deployment||ev.src_pod}</b></span>
              <span className={`rn-mono ${isBlocked?'rn-danger':'rn-warn'}`}>{ev.dst_ip}</span>
              <span className="rn-mono rn-muted">{ev.dst_port||'—'}</span>
              <span><span className={`rn-ev-pill ${isBlocked?'rn-ev-pill--blocked':'rn-ev-pill--anomaly'}`}>{ev.syscall || (isBlocked ? 'blocked' : ev.kind?.replace(/_/g,' '))}</span></span>
              <span>
                <button className={`rn-create-btn ${isBlocked?'rn-create-btn--red':'rn-create-btn--yellow'}`}
                  onClick={e=>{e.stopPropagation();setPickerEv(ev);setPickerAnchor(e.currentTarget);}}>
                  + Create Policy ▾
                </button>
              </span>
            </div>
          );
        })}
      </div>
      <EvDetail ev={selectedEv}/>
      {pickerEv&&<PolPicker ev={pickerEv} anchor={pickerAnchor} onClose={()=>{setPickerEv(null);setPickerAnchor(null);}}/>}
    </div>
  );
}
