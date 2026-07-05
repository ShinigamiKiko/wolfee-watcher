import { useState, useEffect, useCallback, useRef } from 'react';
import { useSensor } from '../../context/SensorContext';
import { normalizePolicies, buildGraph } from './networkPolicyUtils';
import { NodeSidebar, EdgeSidebar, AllPoliciesPanel } from './NetworkPolicySidebar';
import { NetworkEventsTab } from './NetworkEventsTab';
import { PolViewer } from './NetworkPolViewer';
import { CreatePolicyModal } from './CreatePolicyModal';
import '../../styles/network.scss';

import { Arrow }           from './NetworkArrow';
import { PolViewerPanel }  from './NetworkPolViewerPanel';
import { NsDropdown }      from './NetworkNsDropdown';

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

  const lastAppliedAtRef = useRef(0);

  const applySnapshot = useCallback((snap) => {
    if (!snap) return;
    const ts = Date.parse(snap.collected_at || '') || 0;
    if (ts && ts < lastAppliedAtRef.current) return;
    lastAppliedAtRef.current = ts || lastAppliedAtRef.current;
    const pols = normalizePolicies(snap.network_policies || []);
    const allNs = [...new Set([
      ...pols.map(p => p.namespace),
      ...(snap.deployments || []).map(d => d.metadata?.namespace),
      ...(snap.network_policies || []).map(p => p.metadata?.namespace),
    ].filter(Boolean))].sort();
    setNamespaces(allNs);
    setPolicies(pols);
    setGraph(buildGraph(pols, snap.services || []));
    setLoading(false);
  }, []);

  useEffect(() => { applySnapshot(snapshot); }, [snapshot, applySnapshot]);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 5_000);
    return () => clearTimeout(t);
  }, []);

  const refreshSnapshot = useCallback(async () => {
    const tryOnce = async () => {
      const r = await fetch('/sensor/api/snapshot', { credentials: 'same-origin' });
      if (r.status === 503) return { retry: true };
      if (!r.ok) {
        setError(`refresh failed: HTTP ${r.status}`);
        return { retry: false };
      }
      const snap = await r.json();
      applySnapshot(snap);
      setError(null);
      return { retry: false };
    };
    try {
      const first = await tryOnce();
      if (first.retry) {
        setTimeout(() => { tryOnce().catch(() => {}); }, 1500);
      }
    } catch (e) {
      setError(e.message || String(e));
    }
  }, [applySnapshot]);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch('/anomaly/api/anomalies?limit=200', { credentials: 'same-origin' }).catch(() => null);
      const anom = res?.ok ? await res.json() : { events: [] };
      setAnomalies(anom.events || []);
    } catch(e) { setError(e.message); }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    let lastID = '0';
    const poll = async () => {
      try {
        const res = await fetch(`/anomaly/api/anomalies?since=${lastID}&limit=100`, { credentials: 'same-origin' });
        if (!res.ok) return;
        const data = await res.json();
        const evs = data.events || [];
        if (evs.length > 0) {
          lastID = evs[evs.length - 1].id || lastID;
          setAnomalies(prev => {
            const ids = new Set(prev.map(x => x.id));
            const fresh = evs.filter(e => e.id && !ids.has(e.id));
            if (!fresh.length) return prev;
            return [...fresh, ...prev].slice(0, 500);
          });
        }
      } catch {}
    };
    poll();
    const t = setInterval(poll, 8_000);
    return () => clearInterval(t);
  }, []);

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
        {showCreatePolicy&&<CreatePolicyModal namespaces={namespaces} onClose={()=>setShowCreatePolicy(false)} onApplied={()=>{setShowCreatePolicy(false);setTimeout(()=>{load();refreshSnapshot();},800);}}/>}
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
