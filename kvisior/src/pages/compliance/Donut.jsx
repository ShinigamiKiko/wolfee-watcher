import { scoreColor } from './complianceUtils';

function Donut({ value, size=72, stroke=7, color }) {
  const r = (size-stroke)/2, circ = 2*Math.PI*r;
  const dash = (Math.min(value,100)/100)*circ;
  const c = color||scoreColor(value);
  return (
    <svg width={size} height={size} style={{transform:'rotate(-90deg)',flexShrink:0}}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="var(--bg-elevated)" strokeWidth={stroke}/>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={c} strokeWidth={stroke}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        style={{transition:'stroke-dasharray 0.6s ease'}}/>
    </svg>
  );
}

export { Donut };
