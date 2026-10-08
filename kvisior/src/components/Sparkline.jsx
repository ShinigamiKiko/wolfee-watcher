import { useMemo } from 'react';

const uid = (() => { let n = 0; return () => `sl-${n++}`; })();

export function Sparkline({ points = [], color, height = 48, width = 200, fill = true, label, fluid }) {
  const id = useMemo(uid, []);
  const col = color || 'var(--accent)';

  const coords = useMemo(() => {
    if (!points.length) return null;
    const vals = points.map(p => p.value);
    const min = Math.min(...vals);
    const range = Math.max(...vals) - min || 1;
    const pad = 4;
    const h = height - pad * 2;
    const step = width / Math.max(points.length - 1, 1);
    const pts = points.map((p, i) => ({ x: i * step, y: pad + h - ((p.value - min) / range) * h }));
    return { pts, latest: vals[vals.length - 1] };
  }, [points, height, width]);

  const box = fluid
    ? { width: '100%', height, viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: 'none' }
    : { width, height };

  if (!coords) {
    return (
      <span className={`spark${fluid ? ' spark--fluid' : ''}`}>
        <svg {...box} aria-hidden="true">
          <line x1={0} y1={height / 2} x2={width} y2={height / 2} stroke="var(--border-strong)" strokeWidth={1} strokeDasharray="3 3" vectorEffect="non-scaling-stroke" />
        </svg>
        {label !== undefined && <span className="spark-label t-muted">{label}</span>}
      </span>
    );
  }

  const { pts, latest } = coords;
  const last = pts[pts.length - 1];
  const polyline = pts.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const areaPath = `M ${pts[0].x.toFixed(1)},${height} ${pts.map(p => `L ${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')} L ${last.x.toFixed(1)},${height} Z`;
  const text = label !== undefined ? label : (typeof latest === 'number' ? latest.toFixed(latest < 10 ? 1 : 0) : latest);

  return (
    <span className={`spark${fluid ? ' spark--fluid' : ''}`}>
      <svg {...box} aria-hidden="true">
        {fill && (
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={col} stopOpacity={0.25} />
              <stop offset="100%" stopColor={col} stopOpacity={0.02} />
            </linearGradient>
          </defs>
        )}
        {fill && <path d={areaPath} fill={`url(#${id})`} />}
        <polyline points={polyline} fill="none" stroke={col} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
        {!fluid && <circle cx={last.x} cy={last.y} r={3} fill={col} />}
      </svg>
      <span className="spark-label" style={{ color: col }}>{text}</span>
    </span>
  );
}
