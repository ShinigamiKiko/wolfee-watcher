import { useState, useRef, useEffect } from 'react';

export function PolPicker({ ev, anchor, onClose }) {
  const [useIp,      setUseIp]      = useState(true);
  const [useLabel,   setUseLabel]   = useState(false);
  const [addIngress, setAddIngress] = useState(true);
  const [yamlOpen,   setYamlOpen]   = useState(true);
  const ref     = useRef(null);
  const dragRef = useRef(null);

  const pod  = ev?.src_deployment||ev?.src_pod||'pod';
  const ns   = ev?.src_namespace||'default';
  const ip   = ev?.dst_ip||'0.0.0.0';
  const port = ev?.dst_port||'80';
  const name = `restrict-${pod}-egress-${port}`;

  useEffect(() => {
    const h = e => { if (ref.current&&!ref.current.contains(e.target)) onClose(); };
    setTimeout(() => document.addEventListener('mousedown', h), 50);
    return () => document.removeEventListener('mousedown', h);
  }, [onClose]);

  const [pos, setPos] = useState(() => {
    const r = anchor?.getBoundingClientRect();
    return r ? { x:Math.min(r.left,window.innerWidth-330), y:r.bottom+8 } : { x:200, y:200 };
  });

  const onDragStart = e => {
    if (e.target.closest('button,input')) return;
    dragRef.current = { sx:e.clientX-pos.x, sy:e.clientY-pos.y };
    e.preventDefault();
  };
  useEffect(() => {
    const mv = e => { if (dragRef.current) setPos({ x:e.clientX-dragRef.current.sx, y:e.clientY-dragRef.current.sy }); };
    const up = () => { dragRef.current=null; };
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up);
    return () => { document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up); };
  }, []);

  const onResizeStart = e => {
    e.preventDefault();
    const el=ref.current, sw=el.offsetWidth, sh=el.offsetHeight, sx=e.clientX, sy=e.clientY;
    const mv=e2=>{el.style.width=Math.max(280,sw+e2.clientX-sx)+'px';el.style.height=Math.max(200,sh+e2.clientY-sy)+'px';};
    const up=()=>{document.removeEventListener('mousemove',mv);document.removeEventListener('mouseup',up);};
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up);
  };

  let yaml = `apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: ${name}\n  namespace: ${ns}\n  labels:\n    managed-by: wolf-vision\nspec:\n  podSelector:\n    matchLabels:\n      app: ${pod}\n  policyTypes:\n    - Egress${addIngress?'\n    - Ingress':''}\n  egress:`;
  if (useIp)    yaml+=`\n    - to:\n        - ipBlock:\n            cidr: ${ip}/32\n      ports:\n        - protocol: TCP\n          port: ${port}`;
  if (useLabel) yaml+=`\n    - to:\n        - podSelector:\n            matchLabels:\n              app: ${ev?.dst_name||'target'}\n      ports:\n        - protocol: TCP\n          port: ${port}`;
  if (addIngress) yaml+=`\n  ingress:\n    - from:\n        - podSelector:\n            matchLabels:\n              app: ${pod}\n      ports:\n        - protocol: TCP\n          port: ${port}`;

  return (
    <div ref={ref} className="rn-picker" style={{left:pos.x,top:pos.y,display:'flex',flexDirection:'column'}}>
      <div className="rn-picker-title" onMouseDown={onDragStart}>
        <span>Create NetworkPolicy</span>
        <span className="rn-picker-hint">drag · corner to resize</span>
      </div>
      <label className="rn-check-row">
        <input type="checkbox" checked={useIp} onChange={e=>setUseIp(e.target.checked)}/>
        <div><div className="rn-check-label">By IP / CIDR</div><div className="rn-check-sub">{ip}/32</div></div>
      </label>
      <label className="rn-check-row">
        <input type="checkbox" checked={useLabel} onChange={e=>setUseLabel(e.target.checked)}/>
        <div><div className="rn-check-label">By Label selector</div><div className="rn-check-sub">app={ev?.dst_name||'target'}</div></div>
      </label>
      <div className="rn-picker-sep"/>
      <label className="rn-check-row">
        <input type="checkbox" checked={addIngress} onChange={e=>setAddIngress(e.target.checked)}/>
        <div><div className="rn-check-label">Also add Ingress rule</div><div className="rn-check-sub">On destination — allow inbound from source</div></div>
      </label>
      <div className="rn-picker-sep"/>
      <button className="rn-yaml-toggle-sm" onClick={()=>setYamlOpen(o=>!o)}>{yamlOpen?'▾':'▸'} YAML Preview</button>
      {yamlOpen&&<pre className="rn-picker-yaml" style={{flex:1,maxHeight:'none',minHeight:80,overflow:'auto'}}>{yaml}</pre>}
      <div className="rn-picker-actions" style={{flexShrink:0}}>
        <button className="rn-btn rn-btn--copy" onClick={()=>navigator.clipboard?.writeText(yaml)}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
          </svg>
          Copy YAML
        </button>
        <button className="rn-btn" onClick={onClose}>Close</button>
      </div>
      <div className="rn-picker-resize" onMouseDown={onResizeStart}>
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M9 1L1 9M9 5L5 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      </div>
    </div>
  );
}

