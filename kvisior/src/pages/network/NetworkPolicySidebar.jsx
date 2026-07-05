import { useState } from 'react';
import { toYaml, cleanObj } from './networkPolicyUtils';

function CollapsiblePolicy({ pol }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="net-sb-section np-collapsible">
      <button className="np-collapsible-hdr" onClick={()=>setOpen(o=>!o)}>
        <span className="net-sb-section-title" style={{marginBottom:0}}>{pol.name}</span>
        <span className="np-collapsible-chevron">{open?'▾':'▸'}</span>
      </button>
      {open && (
        <div className="np-collapsible-body">
          <div className="net-kv"><span>Selector</span><code className="np-inline-code">{pol.selLabel}</code></div>
          <div className="net-kv"><span>Types</span><span>{pol.policyTypes.join(', ')}</span></div>
          {pol.ingress.length>0&&<>
            <div className="np-sb-rule-hdr">Ingress</div>
            {pol.ingress.map((r,i)=>(
              <div key={i} className="np-rule-item">
                <span className={`net-badge net-badge--${r.effect==='allow'?'success':'danger'}`}>{r.effect}</span>
                <span className="np-rule-peers">from: {r.peers.join(', ')}</span>
                {r.ports.length>0&&<span className="net-port-pill">{r.ports.join(' ')}</span>}
              </div>
            ))}
          </>}
          {pol.egress.length>0&&<>
            <div className="np-sb-rule-hdr">Egress</div>
            {pol.egress.map((r,i)=>(
              <div key={i} className="np-rule-item">
                <span className={`net-badge net-badge--${r.effect==='allow'?'success':'danger'}`}>{r.effect}</span>
                <span className="np-rule-peers">to: {r.peers.join(', ')}</span>
                {r.ports.length>0&&<span className="net-port-pill">{r.ports.join(' ')}</span>}
              </div>
            ))}
          </>}
          <div className="np-sb-rule-hdr" style={{marginTop:10}}>YAML</div>
          <pre className="net-yaml">{toYaml(cleanObj(pol.raw)).trimStart()}</pre>
        </div>
      )}
    </div>
  );
}

const KIND_LABEL = {
  policy_blocked:    { label:'Policy Blocked',    color:'var(--danger)',  icon:'⊗' },
  unauthorized_flow: { label:'Unauthorized Flow', color:'var(--warning)', icon:'⇝' },
  port_scan:         { label:'Port Scan',         color:'var(--danger)',  icon:'⟳' },
  suspicious_port:   { label:'Suspicious Port',   color:'var(--danger)',  icon:'⚑' },
};
const relTime = ts => {
  if (!ts) return '';
  const d = Math.floor((Date.now()-new Date(ts).getTime())/1000);
  return d<60?`${d}s ago`:d<3600?`${Math.floor(d/60)}m ago`:`${Math.floor(d/3600)}h ago`;
};

function EventsTab({ events }) {
  const [expanded, setExpanded] = useState(null);
  const n = v => (v!==undefined&&v!==null&&v!=='') ? v : 'none';
  if (!events.length) return (
    <div className="net-sb-section">
      <div className="np-muted" style={{fontSize:12,padding:'12px 0'}}>No anomaly events for this deployment</div>
    </div>
  );
  return (
    <div className="np-events-list">
      {events.map((ev,i)=>{
        const meta = KIND_LABEL[ev.kind]||{label:ev.kind||'unknown',color:'var(--text-muted)',icon:'•'};
        const isOpen = expanded===i;
        const endpoint = ev.dst_service
          ? `${ev.dst_service}${ev.dst_port?':'+ev.dst_port:''}${ev.dst_namespace?' ('+ev.dst_namespace+')':''}`
          : `${ev.dst_ip||'none'}${ev.dst_port?':'+ev.dst_port:''}`;
        return (
          <div key={i} className={`np-ev${isOpen?' np-ev--open':''}`} onClick={()=>setExpanded(isOpen?null:i)}>
            <div className="np-ev-header">
              <span className="np-ev-icon" style={{color:meta.color}}>{meta.icon}</span>
              <div className="np-ev-summary">
                <span className="np-ev-kind" style={{color:meta.color}}>{meta.label}</span>
                <span className="np-ev-endpoint">{endpoint}</span>
              </div>
              <span className="np-ev-time">{relTime(ev.ts)}</span>
              <span className="np-ev-chevron">{isOpen?'▾':'▸'}</span>
            </div>
            {isOpen&&(
              <div className="np-ev-detail">
                <div className="np-ev-section-hdr">Source</div>
                <div className="np-ev-grid">
                  <span>Pod</span><code>{n(ev.src_pod)}</code>
                  <span>Deployment</span><code>{n(ev.src_deployment)}</code>
                  <span>Namespace</span><code>{n(ev.src_namespace)}</code>
                  <span>Node</span><code>{n(ev.src_node)}</code>
                  <span>Process</span><code>{n(ev.src_process)}</code>
                </div>
                <div className="np-ev-divider"/>
                <div className="np-ev-section-hdr">Destination</div>
                <div className="np-ev-grid">
                  <span>IP</span><code>{n(ev.dst_ip)}</code>
                  <span>Port</span><code>{n(ev.dst_port)}</code>
                  <span>Protocol</span><code>{n(ev.protocol)}</code>
                  <span>Service</span><code>{n(ev.dst_service)}</code>
                  <span>Namespace</span><code>{n(ev.dst_namespace)}</code>
                </div>
                {ev.kind==='port_scan'&&ev.scanned_ports?.length>0&&<>
                  <div className="np-ev-divider"/>
                  <div className="np-ev-section-hdr">Scanned ports ({ev.port_count||ev.scanned_ports.length})</div>
                  <div className="np-ev-ports">{ev.scanned_ports.map(p=><span key={p} className="net-port-pill">{p}</span>)}</div>
                </>}
                <div className="np-ev-divider"/>
                <div className="np-ev-grid">
                  <span>Time</span><code>{ev.ts?new Date(ev.ts).toLocaleString():'none'}</code>
                  <span>Baseline</span><code>{n(ev.baseline_state)}</code>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function NodeSidebar({ node, connEdges, nodeEvents, onClose }) {
  const [tab, setTab] = useState('policy');
  const isPeer = node.kind==='peer';
  const referencedIn = isPeer ? [...new Map(connEdges.map(e=>[e.pol.name,e.pol])).values()] : [];
  const ingressEdges = connEdges.filter(e=>e.dir==='ingress'&&(isPeer?e.src===node.id:e.dst===node.id));
  const egressEdges  = connEdges.filter(e=>e.dir==='egress' &&(isPeer?e.dst===node.id:e.src===node.id));
  return (
    <>
      <div className="net-sb-header">
        <div>
          <div className="net-sb-title">{node.label}</div>
          <div className="net-sb-subtitle">{node.ns}{node.svcInfo?` · ${node.svcInfo.ip}`:''}</div>
        </div>
        <button className="net-sb-close" onClick={onClose}>✕</button>
      </div>
      <div className="np-sb-tabs">
        <button className={`np-sb-tab${tab==='policy'?' active':''}`} onClick={()=>setTab('policy')}>Policy</button>
        <button className={`np-sb-tab${tab==='events'?' active':''}`} onClick={()=>setTab('events')}>
          Events {nodeEvents.length>0&&<span className="np-sb-tab-badge">{nodeEvents.length}</span>}
        </button>
      </div>
      <div className="net-sb-body">
        {tab==='policy' && (
          isPeer
            ? <PeerPolicyTab node={node} ingressEdges={ingressEdges} egressEdges={egressEdges} referencedIn={referencedIn}/>
            : <PolicyTab node={node} ingressEdges={ingressEdges} egressEdges={egressEdges}/>
        )}
        {tab==='events' && <EventsTab events={nodeEvents}/>}
      </div>
    </>
  );
}

function PeerPolicyTab({ node, ingressEdges, egressEdges, referencedIn }) {
  return (
    <>
      <div className="net-sb-section">
        <div className="net-sb-section-title">Identity</div>
        <div className="net-kv"><span>Label</span><span>{node.label}</span></div>
        <div className="net-kv"><span>Namespace</span><span>{node.ns}</span></div>
        {node.svcInfo&&<>
          <div className="net-kv"><span>Service</span><span>{node.svcInfo.name}</span></div>
          <div className="net-kv"><span>ClusterIP</span><code className="np-inline-code">{node.svcInfo.ip}</code></div>
        </>}
      </div>
      {(ingressEdges.length>0||egressEdges.length>0)&&(
        <div className="net-sb-section">
          <div className="net-sb-section-title">Role in policies</div>
          {ingressEdges.map((e,i)=>(
            <div key={i} className="np-conn-row">
              <span className="np-conn-dir np-conn-dir--in">source</span>
              <span className="np-conn-peer">ingress → {e.pol.name}</span>
              {e.ports.length>0&&<span className="net-port-pill">{e.ports.join(' ')}</span>}
            </div>
          ))}
          {egressEdges.map((e,i)=>(
            <div key={i} className="np-conn-row">
              <span className="np-conn-dir np-conn-dir--out">target</span>
              <span className="np-conn-peer">egress ← {e.pol.name}</span>
              {e.ports.length>0&&<span className="net-port-pill">{e.ports.join(' ')}</span>}
            </div>
          ))}
        </div>
      )}
      {referencedIn.map(pol=><CollapsiblePolicy key={pol.name} pol={pol}/>)}
    </>
  );
}

function PolicyTab({ node, ingressEdges, egressEdges }) {
  return (
    <>
      <div className="net-sb-section">
        <div className="net-sb-section-title">Service</div>
        <div className="net-kv"><span>Namespace</span><span>{node.ns}</span></div>
        {node.svcInfo ? <>
          <div className="net-kv"><span>Name</span><span>{node.svcInfo.name}</span></div>
          <div className="net-kv"><span>ClusterIP</span><code className="np-inline-code">{node.svcInfo.ip}</code></div>
        </> : <div className="net-kv"><span>Service</span><span className="np-muted">not found</span></div>}
      </div>
      {(ingressEdges.length>0||egressEdges.length>0)&&(
        <div className="net-sb-section">
          <div className="net-sb-section-title">Connections</div>
          {ingressEdges.map((e,i)=>(
            <div key={i} className="np-conn-row">
              <span className="np-conn-dir np-conn-dir--in">← in</span>
              <span className="np-conn-peer">{node.label}</span>
              {e.ports.length>0&&<span className="net-port-pill">{e.ports.join(' ')}</span>}
            </div>
          ))}
          {egressEdges.map((e,i)=>(
            <div key={i} className="np-conn-row">
              <span className="np-conn-dir np-conn-dir--out">→ out</span>
              <span className="np-conn-peer">{e.pol.egress.flatMap(r=>r.peers).join(', ')}</span>
              {e.ports.length>0&&<span className="net-port-pill">{e.ports.join(' ')}</span>}
            </div>
          ))}
        </div>
      )}
      {node.policy&&<CollapsiblePolicy pol={node.policy}/>}
    </>
  );
}

export function EdgeSidebar({ edge, onClose }) {
  const srcLabel = edge.src.split(':').slice(2).join(':')||edge.src;
  const dstLabel = edge.dst.split(':').slice(2).join(':')||edge.dst;
  const color = edge.effect==='allow'?'var(--accent-3)':'var(--danger)';
  return (
    <>
      <div className="net-sb-header">
        <div>
          <div className="net-sb-title">{edge.pol.name}</div>
          <div className="net-sb-subtitle">{edge.dir} · <span style={{color}}>{edge.effect}</span></div>
        </div>
        <button className="net-sb-close" onClick={onClose}>✕</button>
      </div>
      <div className="net-sb-body">
        <div className="net-sb-section">
          <div className="np-flow-diagram">
            <div className="np-flow-box">{srcLabel}</div>
            <div className="np-flow-mid">
              {edge.ports.length>0&&<span className="np-flow-ports">{edge.ports.join(' ')}</span>}
              <span className="np-flow-arrow" style={{color}}>——›</span>
            </div>
            <div className="np-flow-box">{dstLabel}</div>
          </div>
        </div>
        <CollapsiblePolicy pol={edge.pol}/>
      </div>
    </>
  );
}

export function AllPoliciesPanel({ policies, onClose }) {
  const [search, setSearch] = useState('');
  const filtered = policies.filter(p => !search||p.name.includes(search)||p.namespace.includes(search));
  return (
    <div className="np-all-panel">
      <div className="net-sb-header">
        <div>
          <div className="net-sb-title">All Policies</div>
          <div className="net-sb-subtitle">{policies.length} policies in cluster</div>
        </div>
        <button className="net-sb-close" onClick={onClose}>✕</button>
      </div>
      <div className="np-all-search">
        <input className="np-search-input" placeholder="Filter by name or namespace…"
          value={search} onChange={e=>setSearch(e.target.value)}/>
      </div>
      <div className="net-sb-body">
        {filtered.length===0&&<div className="net-sb-section"><div className="np-muted">No policies match</div></div>}
        {filtered.map(pol=><CollapsiblePolicy key={pol.name} pol={pol}/>)}
      </div>
    </div>
  );
}
