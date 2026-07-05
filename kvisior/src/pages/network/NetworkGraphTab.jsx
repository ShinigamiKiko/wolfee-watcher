import { useRef } from 'react';

function Edge({ src, dst, port, kind }) {
  if (!src || !dst) return null;
  const NR = 30;
  const dx = dst.x - src.x, dy = dst.y - src.y;
  const len = Math.sqrt(dx*dx + dy*dy) || 1;
  const ux = dx/len, uy = dy/len;
  const x1 = src.x + ux*NR,       y1 = src.y + uy*NR;
  const x2 = dst.x - ux*(NR+8),   y2 = dst.y - uy*(NR+8);
  const mx = (x1+x2)/2,           my = (y1+y2)/2;
  const color = kind === 'INTERNET' ? 'var(--danger)' : 'var(--accent-2)';
  return (
    <g className="rn-edge">
      <line x1={x1} y1={y1} x2={x2} y2={y2}
        stroke={color} strokeWidth={1.5} opacity={0.45}
        markerEnd={`url(#arr-${kind==='INTERNET'?'danger':'normal'})`}
      />
      {port && <text x={mx} y={my-5} className="rn-edge-port" fill="var(--text-muted)">:{port}</text>}
    </g>
  );
}

function NetworkGraphTab({
  nodes, edges, loading,
  pan, setPan, scale, setScale,
  nsFilter, nsOpen, setNsOpen, namespaces, setNsFilter,
  selected, setSelected,
  dragRef, nodesRef,
  reload,
}) {
  const nsDropRef = useRef(null);

  const visNodes  = nsFilter==='all' ? nodes : nodes.filter(n => n.ns===nsFilter || n.external);
  const visIds    = new Set(visNodes.map(n => n.id));
  const visEdges  = edges.filter(e => visIds.has(e.src) && visIds.has(e.dst));
  const nodesById = Object.fromEntries(nodes.map(n => [n.id, n]));

  const onBgDown = e => {
    if (e.target.closest('.rn-node')) return;
    dragRef.current = { pan: true, sx: e.clientX, sy: e.clientY, ox: pan.x, oy: pan.y };
  };
  const onMove = e => {
    if (!dragRef.current) return;
    if (dragRef.current.pan) {
      setPan({ x: dragRef.current.ox+(e.clientX-dragRef.current.sx), y: dragRef.current.oy+(e.clientY-dragRef.current.sy) });
    } else {
      const { id, sx, sy, ox, oy } = dragRef.current;
      const nx = ox+(e.clientX-sx)/scale, ny = oy+(e.clientY-sy)/scale;
      nodesRef.current[id] = { ...nodesRef.current[id], x: nx, y: ny };
    }
  };
  const onUp    = () => { dragRef.current = null; };
  const onWheel = e => { e.preventDefault(); setScale(s => Math.max(0.15, Math.min(3, s*(e.deltaY>0?0.9:1.1)))); };

  const onNodeDown = (e, node) => {
    e.stopPropagation();
    dragRef.current = { id: node.id, sx: e.clientX, sy: e.clientY, ox: node.x, oy: node.y, startX: e.clientX, startY: e.clientY };
  };
  const onNodeClick = (e, node) => {
    e.stopPropagation();
    const dx = e.clientX-(dragRef.current?.startX||e.clientX), dy = e.clientY-(dragRef.current?.startY||e.clientY);
    if (Math.sqrt(dx*dx+dy*dy) > 4) return;
    const nodeEdges = edges.filter(ed => ed.src===node.id || ed.dst===node.id);
    setSelected({ node, edges: nodeEdges });
  };

  return (
    <>
      {}
      <div className="net-body">
        <div className="net-stage-wrap"
          onMouseDown={onBgDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp} onWheel={onWheel}
          style={{ cursor: dragRef.current?.pan ? 'grabbing' : 'grab' }}
        >
          {loading && <div className="net-overlay">Loading topology…</div>}
          {!loading && nodes.length === 0 && (
            <div className="net-overlay">
              <div className="net-empty-icon">⬡</div>
              <div className="net-empty-title">No network flows observed yet</div>
            </div>
          )}
          <div className="net-stage" style={{ transform: `translate(${pan.x}px,${pan.y}px) scale(${scale})` }}>
            <svg className="net-svg">
              <defs>
                {['normal','danger'].map(t => (
                  <marker key={t} id={`arr-${t}`} markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L8,3 z" fill={t==='danger'?'var(--danger)':'var(--accent-2)'} opacity="0.75"/>
                  </marker>
                ))}
              </defs>
              {visEdges.map((e,i) => (
                <Edge key={i} src={nodesById[e.src]} dst={nodesById[e.dst]} port={e.port} kind={e.kind} />
              ))}
            </svg>
            {visNodes.map(node => (
              <div key={node.id}
                className={`rn-node${node.external?' rn-node--external':''}${selected?.node.id===node.id?' rn-node--selected':''}`}
                style={{ left: node.x, top: node.y }}
                onMouseDown={e => onNodeDown(e, node)}
                onClick={e => onNodeClick(e, node)}
              >
                <div className="rn-node-icon">{node.external?'⊕':node.label[0]?.toUpperCase()}</div>
                <div className="rn-node-label">{node.label.length>14?node.label.slice(0,13)+'…':node.label}</div>
                <div className="rn-node-ns">{node.ns}</div>
              </div>
            ))}
          </div>
        </div>

        {selected && (
          <div className="net-sidebar">
            <div className="net-sb-header">
              <span className="net-sb-title">{selected.node.label}</span>
              <button className="net-sb-close" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div className="net-sb-body">
              <div className="net-sb-section">
                <div className="net-sb-section-title">Identity</div>
                <div className="net-kv"><span>Namespace</span><span>{selected.node.ns}</span></div>
                <div className="net-kv"><span>Deployment</span><span>{selected.node.label}</span></div>
              </div>
              <div className="net-sb-section">
                <div className="net-sb-section-title">Flows ({selected.edges.length})</div>
                {selected.edges.slice(0, 20).map((e, i) => (
                  <div key={i} className="net-rule-row">
                    <span className="net-rule-dir">{e.src===selected.node.id?'→':'←'}</span>
                    <span style={{ fontFamily:'monospace', fontSize:11, flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {e.src===selected.node.id?e.dst:e.src}
                    </span>
                    {e.port && <span className="net-port-pill">:{e.port}</span>}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

export function NsDropdown({ nsFilter, setNsFilter, nsOpen, setNsOpen, namespaces, nsDropRef }) {
  return (
    <div className="rn-ns-dropdown" ref={nsDropRef}>
      <button className="rn-ns-btn" onClick={() => setNsOpen(o => !o)}>
        <span>{nsFilter === 'all' ? 'All namespaces' : nsFilter}</span>
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
          style={{ transform: nsOpen ? 'rotate(180deg)' : 'none', transition: 'transform .15s' }}>
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </button>
      {nsOpen && (
        <div className="rn-ns-menu">
          {['all', ...namespaces].map(ns => (
            <button key={ns}
              className={`rn-ns-item${nsFilter===ns?' active':''}`}
              onClick={() => { setNsFilter(ns); setNsOpen(false); }}>
              {ns === 'all' ? 'All namespaces' : ns}
              {nsFilter === ns && <span style={{ marginLeft: 'auto' }}>✓</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
