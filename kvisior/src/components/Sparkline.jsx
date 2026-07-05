
import { useMemo } from 'react';

const uid = (() => { let n = 0; return () => `sl-${n++}`; })();

export function Sparkline({ points = [], color, height = 48, width = 200, fill = true, label, unit = '' }) {
  const id = useMemo(uid, []);
  const col = color || 'var(--accent)';

  const coords = useMemo(() => {
    if (!points.length) return null;
    const vals = points.map(p => p.value);
    const min  = Math.min(...vals);
    const max  = Math.max(...vals);
    const range = max - min || 1;
    const pad = 4;
    const h = height - pad * 2;
    const w = width;
    const step = w / Math.max(points.length - 1, 1);
    const pts = points.map((p, i) => ({
      x: i * step,
      y: pad + h - ((p.value - min) / range) * h,
    }));
    return { pts, min, max, latest: vals[vals.length - 1] };
  }, [points, height, width]);

  if (!coords || !coords.pts.length) {
    return (
      <svg width={width} height={height} style={{ display: 'block' }}>
        <line x1={0} y1={height / 2} x2={width} y2={height / 2}
          stroke="var(--border)" strokeWidth={1} strokeDasharray="3 3" />
      </svg>
    );
  }

  const { pts, latest } = coords;
  const polyline = pts.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const areaPath = [
    `M ${pts[0].x.toFixed(1)},${height}`,
    ...pts.map(p => `L ${p.x.toFixed(1)},${p.y.toFixed(1)}`),
    `L ${pts[pts.length - 1].x.toFixed(1)},${height}`,
    'Z',
  ].join(' ');

  return (
    <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <svg width={width} height={height} style={{ display: 'block', overflow: 'visible' }}>
        {fill && (
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"   stopColor={col} stopOpacity={0.25} />
              <stop offset="100%" stopColor={col} stopOpacity={0.02} />
            </linearGradient>
          </defs>
        )}
        {fill && <path d={areaPath} fill={`url(#${id})`} />}
        <polyline
          points={polyline}
          fill="none"
          stroke={col}
          strokeWidth={1.5}
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        {}
        <circle
          cx={pts[pts.length - 1].x}
          cy={pts[pts.length - 1].y}
          r={3}
          fill={col}
        />
      </svg>
      {label !== undefined && (
        <span style={{ fontSize: 13, fontFamily: 'JetBrains Mono, monospace', color: col, minWidth: 48 }}>
          {typeof latest === 'number' ? latest.toFixed(latest < 10 ? 1 : 0) : latest}{unit}
        </span>
      )}
    </div>
  );
}

export function MiniStat({ label, value, unit = '', points = [], color }) {
  const col = color || 'var(--accent)';
  return (
    <div style={{
      background: 'var(--bg-elevated)',
      border: '1px solid var(--border)',
      borderRadius: 10,
      padding: '12px 16px',
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
      minWidth: 180,
    }}>
      <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.07em', color: 'var(--text-muted)' }}>
        {label}
      </div>
      <div style={{ fontSize: 22, fontWeight: 300, fontFamily: 'JetBrains Mono, monospace', color: col }}>
        {value}{unit && <span style={{ fontSize: 12, marginLeft: 3 }}>{unit}</span>}
      </div>
      {points.length > 1 && (
        <Sparkline points={points} color={col} height={40} width={160} fill />
      )}
    </div>
  );
}

export function GrafanaChart({ title, series = [], height = 120, yUnit = '', yLabel = '' }) {
  const width = 600;
  const pad = { top: 8, right: 10, bottom: 24, left: yLabel ? 44 : 36 };
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;

  const allVals = series.flatMap(s => s.points.map(p => p.value));
  const globalMin = allVals.length ? Math.min(...allVals) : 0;
  const globalMax = allVals.length ? Math.max(...allVals) : 1;
  const range = globalMax - globalMin || 1;

  const toX = (i, total) => pad.left + (i / Math.max(total - 1, 1)) * innerW;
  const toY = (v) => pad.top + innerH - ((v - globalMin) / range) * innerH;

  const tickCount = 4;
  const ticks = Array.from({ length: tickCount + 1 }, (_, i) =>
    globalMin + (range / tickCount) * i
  );

  return (
    <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 10, padding: '12px 16px' }}>
      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8, fontWeight: 500 }}>{title}</div>
      <svg width="100%" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ display: 'block' }}>
        {}
        {ticks.map((t, i) => (
          <g key={i}>
            <line
              x1={pad.left} y1={toY(t)} x2={width - pad.right} y2={toY(t)}
              stroke="var(--border)" strokeWidth={0.5} strokeDasharray="2 4"
            />
            <text x={pad.left - 4} y={toY(t) + 4} textAnchor="end"
              fontSize={9} fill="var(--text-muted)">
              {t >= 1000 ? `${(t / 1000).toFixed(1)}k` : t.toFixed(t < 10 ? 1 : 0)}{yUnit}
            </text>
          </g>
        ))}
        {}
        {series.map((s, si) => {
          if (!s.points.length) return null;
          const pts = s.points.map((p, i) => ({ x: toX(i, s.points.length), y: toY(p.value) }));
          const poly = pts.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
          const area = [
            `M ${pts[0].x.toFixed(1)},${pad.top + innerH}`,
            ...pts.map(p => `L ${p.x.toFixed(1)},${p.y.toFixed(1)}`),
            `L ${pts[pts.length - 1].x.toFixed(1)},${pad.top + innerH}`,
            'Z',
          ].join(' ');
          const gradId = `gc-${si}-${title.replace(/\s/g, '')}`;
          return (
            <g key={si}>
              <defs>
                <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={s.color} stopOpacity={0.2} />
                  <stop offset="100%" stopColor={s.color} stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <path d={area} fill={`url(#${gradId})`} />
              <polyline points={poly} fill="none" stroke={s.color} strokeWidth={1.5}
                strokeLinejoin="round" strokeLinecap="round" />
            </g>
          );
        })}
        {}
        {yLabel && (
          <text transform={`rotate(-90,${pad.left - 28},${pad.top + innerH / 2})`}
            x={pad.left - 28} y={pad.top + innerH / 2}
            textAnchor="middle" fontSize={9} fill="var(--text-muted)">{yLabel}</text>
        )}
      </svg>
      {series.length > 1 && (
        <div style={{ display: 'flex', gap: 12, marginTop: 4 }}>
          {series.map((s, i) => (
            <span key={i} style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ display: 'inline-block', width: 12, height: 2, background: s.color, borderRadius: 1 }} />
              {s.label}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
