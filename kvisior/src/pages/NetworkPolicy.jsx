import { useState, useEffect, useCallback, useRef } from 'react';
import { useSensor } from '../context/SensorContext';
import { normalizePolicies, buildGraph } from './network/networkPolicyUtils';
import { NodeSidebar, EdgeSidebar, AllPoliciesPanel } from './network/NetworkPolicySidebar';
import { NetworkEventsTab } from './network/NetworkEventsTab';
import { PolViewer } from './network/NetworkPolViewer';
import { CreatePolicyModal } from './network/CreatePolicyModal';
import '../styles/network.scss';

function Arrow({ src, dst, effect, ports, selected, onClick }) {
  if (!src||!dst) return null;
  const NR=45;
  const dx=dst.x-src.x, dy=dst.y-src.y;
  const len=Math.sqrt(dx*dx+dy*dy)||1;
  const ux=dx/len, uy=dy/len;
  const x1=src.x+ux*NR, y1=src.y+uy*NR;
  const x2=dst.x-ux*(NR+10), y2=dst.y-uy*(NR+10);
  const mx=(x1+x2)/2, my=(y1+y2)/2-8;
  const color = effect==='allow' ? 'var(--accent-3)' : 'var(--danger)';
  return (
    <g onClick={onClick} style={{cursor:'pointer'}}>
      <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="transparent" strokeWidth="18"/>
      <line x1={x1} y1={y1} x2={x2} y2={y2}
        stroke={color} strokeWidth={selected?2.5:1.5}
        opacity={selected?1:0.55}
        strokeDasharray={effect==='deny'?'6 3':'none'}
        markerEnd={`url(#np-arr-${effect})`}
      />
      {ports.length>0&&(
        <text x={mx} y={my} textAnchor="middle" fontSize="9"
          fill="var(--text-muted)" fontFamily="JetBrains Mono,monospace" style={{pointerEvents:'none'}}>
          {ports.join(' ')}
        </text>
      )}
    </g>
  );
}

function PolViewerPanel({ pol, onClose }) {
  const ref     = useRef(null);
  const dragRef = useRef(null);
  const [pos,  setPos]  = useState({ x: window.innerWidth - 520, y: 80 });
  const [size, setSize] = useState({ w: 480, h: 560 });

  const onDragStart = e => {
    if (e.target.closest('button,input,pre,select')) return;
    dragRef.current = { sx: e.clientX - pos.x, sy: e.clientY - pos.y, type: 'drag' };
    e.preventDefault();
  };
  const onResizeStart = e => {
    e.preventDefault();
    dragRef.current = { sx: e.clientX, sy: e.clientY, ow: size.w, oh: size.h, type: 'resize' };
  };
  useEffect(() => {
    const mv = e => {
      if (!dragRef.current) return;
      if (dragRef.current.type === 'drag')
        setPos({ x: e.clientX - dragRef.current.sx, y: e.clientY - dragRef.current.sy });
      else
        setSize({ w: Math.max(360, dragRef.current.ow + e.clientX - dragRef.current.sx), h: Math.max(300, dragRef.current.oh + e.clientY - dragRef.current.sy) });
    };
    const up = () => { dragRef.current = null; };
    document.addEventListener('mousemove', mv);
    document.addEventListener('mouseup', up);
    return () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); };
  }, []);

  return (
    <div ref={ref} style={{
      position: 'absolute', left: pos.x, top: pos.y,
      width: size.w, height: size.h,
      background: '#131620',
      border: '1px solid rgba(99,179,237,.25)',
      borderRadius: 10,
      boxShadow: '0 16px 48px rgba(0,0,0,.6)',
      display: 'flex', flexDirection: 'column',
      zIndex: 500, overflow: 'hidden',
    }}>
      {}
      <div onMouseDown={onDragStart} style={{
        padding: '10px 14px', cursor: 'move', userSelect: 'none',
        borderBottom: '1px solid rgba(255,255,255,.07)',
        background: '#1a1e2a',
        display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0,
      }}>
        <span style={{fontSize:12,fontWeight:600,fontFamily:'monospace',flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
          {pol.metadata?.name}
        </span>
        <span style={{fontSize:10,color:'var(--text-muted)'}}>drag to move · corner to resize</span>
        <button onClick={onClose} style={{
          width:20,height:20,border:'none',background:'transparent',
          color:'var(--text-muted)',cursor:'pointer',fontSize:14,lineHeight:1,
          display:'flex',alignItems:'center',justifyContent:'center',borderRadius:4,
          flexShrink:0,
        }} onMouseEnter={e=>e.currentTarget.style.color='#e2e8f0'}
           onMouseLeave={e=>e.currentTarget.style.color='var(--text-muted)'}>✕</button>
      </div>

      {}
      <div style={{flex:1,overflowY:'auto',display:'flex',flexDirection:'column',minHeight:0}}>
        <PolViewer pol={pol}/>
      </div>

      {}
      <div onMouseDown={onResizeStart} style={{
        position:'absolute',bottom:0,right:0,width:16,height:16,
        cursor:'se-resize',display:'flex',alignItems:'flex-end',justifyContent:'flex-end',
        padding:3,opacity:.4,
      }} onMouseEnter={e=>e.currentTarget.style.opacity=1}
         onMouseLeave={e=>e.currentTarget.style.opacity=.4}>
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M9 1L1 9M9 5L5 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      </div>
    </div>
  );
}

function NsDropdown({ nsFilter, setNsFilter, namespaces }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const h = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  return (
    <div ref={ref} style={{ position: 'relative', flexShrink: 0 }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '4px 12px', borderRadius: 6,
          border: open ? '1px solid rgba(99,179,237,.4)' : '1px solid var(--border)',
          background: open ? 'rgba(99,179,237,.08)' : 'var(--bg-elevated, #1e2330)',
          color: nsFilter !== 'all' ? 'var(--accent)' : 'var(--text-muted)',
          fontSize: 11, fontWeight: 500, cursor: 'pointer', whiteSpace: 'nowrap',
        }}>
        <span>{nsFilter === 'all' ? 'All namespaces' : nsFilter}</span>
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
          style={{ transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .15s' }}>
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: 'calc(100% + 6px)', left: 0, zIndex: 9999,
          background: '#1a1e2a',
          border: '1px solid rgba(99,179,237,.25)',
          borderRadius: 8, boxShadow: '0 8px 32px rgba(0,0,0,.7)',
          minWidth: 200, padding: 4, maxHeight: 300, overflowY: 'auto',
        }}>
          {['all', ...namespaces].map(ns => (
            <button key={ns}
              onClick={() => { setNsFilter(ns); setOpen(false); }}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                width: '100%', padding: '8px 12px', fontSize: 12, cursor: 'pointer',
                border: 'none', borderRadius: 5, textAlign: 'left',
                background: nsFilter === ns ? 'rgba(99,179,237,.15)' : 'transparent',
                color: nsFilter === ns ? '#63b3ed' : '#94a3b8',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,.06)'; e.currentTarget.style.color = '#e2e8f0'; }}
              onMouseLeave={e => { e.currentTarget.style.background = nsFilter === ns ? 'rgba(99,179,237,.15)' : 'transparent'; e.currentTarget.style.color = nsFilter === ns ? '#63b3ed' : '#94a3b8'; }}>
              {ns === 'all' ? 'All namespaces' : ns}
              {nsFilter === ns && <span style={{ fontSize: 11, color: '#63b3ed' }}>✓</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function NetworkRuntime() {
  const { snapshot } = useSensor();
  const networkPolicies = snapshot?.network_policies || [];

  const [tab,              setTab]              = useState('graph');
  const [policies,         setPolicies]         = useState([]);
  const [anomalies,        setAnomalies]        = useState([]);
  const [graph,            setGraph]            = useState({ nodes:[], edges:[], byId:{} });
  const [selected,         setSelected]         = useState(null);
  const [nsFilter,         setNsFilter]         = useState('all');
  const [namespaces,       setNamespaces]       = useState([]);
  const [loading,          setLoading]          = useState(true);
  const [error,            setError]            = useState(null);
  const [showAllPolicies,  setShowAllPolicies]  = useState(false);
  const [showCreatePolicy, setShowCreatePolicy] = useState(false);
  const [selectedPol,      setSelectedPol]      = useState(null);
  const [pan,              setPan]              = useState({ x:60, y:40 });
  const [scale,            setScale]            = useState(1);
  const dragRef  = useRef(null);
  const nodesRef = useRef({});

  const syncNodePos = (id, x, y) => {
    nodesRef.current[id] = { x, y };
    setGraph(g => ({ ...g, nodes:g.nodes.map(n=>n.id===id?{...n,x,y}:n), byId:{...g.byId,[id]:{...g.byId[id],x,y}} }));
  };

  useEffect(() => {
    if (!snapshot) return;
    const pols = normalizePolicies(snapshot.network_policies || []);
    const allNs = [...new Set([
      ...pols.map(p => p.namespace),
      ...(snapshot.deployments || []).map(d => d.metadata?.namespace),
      ...(snapshot.network_policies || []).map(p => p.metadata?.namespace),
    ].filter(Boolean))].sort();
    setNamespaces(allNs);
    setPolicies(pols);
    setGraph(buildGraph(pols, snapshot.services || []));
    setLoading(false);
  }, [snapshot]);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch('/anomaly/api/anomalies?limit=200', { credentials: 'same-origin' }).catch(() => null);
      const anom = res?.ok ? await res.json() : { events: [] };
      setAnomalies(anom.events || []);
    } catch(e) { setError(e.message); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const onBgDown = e => {
    if (e.target.closest('.np-node')) return;
    dragRef.current = { type:'pan', sx:e.clientX, sy:e.clientY, ox:pan.x, oy:pan.y };
  };
  const onMove = e => {
    if (!dragRef.current) return;
    if (dragRef.current.type==='pan')
      setPan({ x:dragRef.current.ox+(e.clientX-dragRef.current.sx), y:dragRef.current.oy+(e.clientY-dragRef.current.sy) });
    else if (dragRef.current.type==='node') {
      const {id,ox,oy,sx,sy} = dragRef.current;
      syncNodePos(id, ox+(e.clientX-sx)/scale, oy+(e.clientY-sy)/scale);
    }
  };
  const onUp    = () => { dragRef.current=null; };
  const onWheel = e => { e.preventDefault(); setScale(s=>Math.max(0.15,Math.min(3,s*(e.deltaY>0?0.9:1.1)))); };

  const onNodeMouseDown = (e,node) => { e.stopPropagation(); dragRef.current={type:'node',id:node.id,sx:e.clientX,sy:e.clientY,ox:node.x,oy:node.y}; };
  const onNodeMouseUp   = (e,node) => {
    if (!dragRef.current) return;
    const d = Math.hypot(e.clientX-dragRef.current.sx, e.clientY-dragRef.current.sy);
    dragRef.current=null;
    if (d<4) setSelected({ _type:'node', node, connEdges:graph.edges.filter(e=>e.src===node.id||e.dst===node.id), nodeEvents:anomalies.filter(ev=>ev.src_deployment===node.label||ev.src_deployment===node.policy?.name) });
  };

  const visNodes    = nsFilter==='all' ? graph.nodes : graph.nodes.filter(n=>n.ns===nsFilter);
  const visIds      = new Set(visNodes.map(n=>n.id));
  const visEdges    = graph.edges.filter(e=>visIds.has(e.src)&&visIds.has(e.dst));
  const alertedDeps = new Set(anomalies.map(ev=>ev.src_deployment).filter(Boolean));

  const anomalyCount = anomalies.filter(e=>e.kind!=='blocked').length;
  const blockedCount = anomalies.filter(e=>e.kind==='blocked').length;

  return (
    <div className="net-page">
      <div className="net-topbar">
        <span className="net-page-title">Network Runtime</span>
        <div className="rn-main-tabs">
          {[
            { id:'graph',  label:'Graph' },
            { id:'events', label:'Events', cY:anomalyCount, cR:blockedCount },
            { id:'netpol', label:'Network Policies', c:networkPolicies.length },
          ].map(t=>(
            <button key={t.id} className={`rn-main-tab${tab===t.id?' active':''}`} onClick={()=>setTab(t.id)}>
              {t.label}
              {t.cY>0&&<span className="rn-tab-count rn-tab-count--yellow">{t.cY}</span>}
              {t.cR>0&&<span className="rn-tab-count rn-tab-count--red">{t.cR}</span>}
              {t.c>0 &&<span className="rn-tab-count">{t.c}</span>}
            </button>
          ))}
        </div>
        {tab==='graph'&&<>
          <span className="net-badge net-badge--info">{policies.length} {policies.length===1?'policy':'policies'}</span>
          <div className="net-topbar-sep"/>
          <NsDropdown nsFilter={nsFilter} setNsFilter={setNsFilter} namespaces={namespaces}/>
          <div style={{flex:1}}/>
          <button className="np-create-btn" onClick={()=>setShowCreatePolicy(true)}>+ Create Policy</button>
          <div className="net-topbar-sep"/>
          <button className="net-icon-btn" onClick={()=>setScale(s=>Math.min(3,s*1.2))}>+</button>
          <button className="net-icon-btn" onClick={()=>setScale(s=>Math.max(0.15,s*0.83))}>−</button>
          <button className="net-icon-btn" onClick={()=>{setPan({x:60,y:40});setScale(1);}}>⊡</button>
          <button className="net-icon-btn" onClick={load}>↺</button>
        </>}
      </div>

      {tab==='graph'&&<>
        <div className="net-body">
          <div className="net-stage-wrap"
            onMouseDown={onBgDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp} onWheel={onWheel}
            style={{cursor:dragRef.current?'grabbing':'grab'}}>
            {loading&&<div className="net-overlay">Loading…</div>}
            {error  &&<div className="net-overlay net-overlay--error">⚠ {error}</div>}
            {!loading&&!error&&policies.length===0&&(
              <div className="net-overlay">
                <div className="net-empty-icon">⬡</div>
                <div className="net-empty-title">No NetworkPolicy resources found</div>
                <div className="net-empty-sub">Policies created in the cluster will appear here</div>
              </div>
            )}
            <div className="net-stage" style={{transform:`translate(${pan.x}px,${pan.y}px) scale(${scale})`}}>
              <svg className="net-svg">
                <defs>
                  <marker id="np-arr-allow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="var(--accent-3)"/></marker>
                  <marker id="np-arr-deny"  markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="var(--danger)"/></marker>
                </defs>
                {visEdges.map(edge=>(
                  <Arrow key={edge.id} src={graph.byId[edge.src]} dst={graph.byId[edge.dst]}
                    effect={edge.effect} ports={edge.ports}
                    selected={selected?._type==='edge'&&selected.edge.id===edge.id}
                    onClick={e=>{e.stopPropagation();setSelected({_type:'edge',edge});}}
                  />
                ))}
              </svg>
              {visNodes.map(node=>(
                <div key={node.id}
                  className={`np-node${selected?._type==='node'&&selected.node.id===node.id?' np-node--selected':''}${alertedDeps.has(node.label)?' np-node--alert':''}`}
                  style={{left:node.x,top:node.y,cursor:dragRef.current?.id===node.id?'grabbing':'pointer'}}
                  onMouseDown={e=>onNodeMouseDown(e,node)} onMouseUp={e=>onNodeMouseUp(e,node)}>
                  <div className="np-node-name">{node.label}</div>
                  <div className="np-node-sub">{node.svcInfo?node.svcInfo.ip:node.ns}</div>
                  {alertedDeps.has(node.label)&&<div className="np-node-alert-dot"/>}
                </div>
              ))}
            </div>
          </div>
          {showAllPolicies&&<AllPoliciesPanel policies={policies} onClose={()=>setShowAllPolicies(false)}/>}
          {!showAllPolicies&&selected&&(
            <div className="net-sidebar">
              {selected._type==='node'&&<NodeSidebar node={selected.node} connEdges={selected.connEdges} nodeEvents={selected.nodeEvents} onClose={()=>setSelected(null)}/>}
              {selected._type==='edge'&&<EdgeSidebar edge={selected.edge} onClose={()=>setSelected(null)}/>}
            </div>
          )}
        </div>
        <div className="net-legend">
          <span><span style={{color:'var(--accent-3)'}}>——›</span> allow</span>
          <span><span style={{color:'var(--danger)'}}>--›</span> deny</span>
          <span style={{color:'var(--text-muted)',fontSize:10}}>click deployment node for details</span>
        </div>
        {showCreatePolicy&&<CreatePolicyModal namespaces={namespaces} onClose={()=>setShowCreatePolicy(false)} onApplied={()=>{setShowCreatePolicy(false);setTimeout(load,800);}}/>}
      </>}

      {tab==='events'&&<NetworkEventsTab anomalies={anomalies}/>}

      {tab==='netpol'&&(
        <div style={{flex:1,overflow:'hidden',position:'relative',display:'flex'}}>
          {}
          <div style={{width:300,flexShrink:0,borderRight:'1px solid var(--border)',overflowY:'auto',display:'flex',flexDirection:'column'}}>
            <div className="rn-netpol-list-hdr">
              <span>Policies</span>
              <span className="rn-badge-ok">{networkPolicies.length} active</span>
            </div>
            {networkPolicies.length===0&&<div style={{padding:24,textAlign:'center',color:'var(--text-muted)',fontSize:12}}>No network policies found</div>}
            {networkPolicies.map((pol,i)=>{
              const meta=pol.metadata||{}, types=pol.spec?.policyTypes||[];
              return (
                <div key={i}
                  className={`rn-netpol-row${selectedPol===pol?' active':''}`}
                  onClick={()=>setSelectedPol(selectedPol===pol?null:pol)}>
                  <div className="rn-netpol-name">{meta.name}</div>
                  <div className="rn-netpol-tags">
                    {types.map(t=><span key={t} className={`rn-pol-tag rn-pol-tag--${t.toLowerCase()}`}>{t}</span>)}
                    {meta.labels?.['managed-by']==='wolf-vision'&&<span className="rn-pol-tag rn-pol-tag--gen">wolf-vision</span>}
                  </div>
                </div>
              );
            })}
          </div>

          {}
          <div style={{flex:1,position:'relative'}}>
            {selectedPol&&(
              <PolViewerPanel pol={selectedPol} onClose={()=>setSelectedPol(null)}/>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
