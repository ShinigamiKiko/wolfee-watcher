import { useState, useRef, useEffect } from 'react';
import { PolViewer } from './NetworkPolViewer';

export function PolViewerPanel({ pol, onClose }) {
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

