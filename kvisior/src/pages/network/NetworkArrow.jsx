export function Arrow({ src, dst, effect, ports, selected, onClick }) {
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

