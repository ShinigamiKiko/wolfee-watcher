import { useRef, useState, useEffect, useCallback } from 'react';
import { SevBadge } from '../../components/ui';
import { sevColor, epssLabel } from '../../data/scanner';

const WIN_W = 480;
const WIN_H = 580;

const RISK_COLORS = {
  CRITICAL: 'var(--danger)',
  HIGH:     'var(--warning)',
  MEDIUM:   '#a78bfa',
  LOW:      'var(--accent-3)',
};

export function SbomDetail({ pkg, onClose }) {
  const [pos,  setPos]  = useState(null);
  const [size, setSize] = useState({ w: WIN_W, h: WIN_H });
  const dragging = useRef(null);
  const resizing = useRef(null);

  useEffect(() => {
    if (pkg) {
      setSize({ w: WIN_W, h: WIN_H });
      setPos({
        x: Math.max(0, window.innerWidth  - WIN_W - 32),
        y: Math.max(0, (window.innerHeight - WIN_H) / 2),
      });
    }
  }, [pkg?.name, pkg?.version]);

  const onDragStart = useCallback((e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    dragging.current = { sx: e.clientX, sy: e.clientY, ox: pos.x, oy: pos.y };

    const onMove = (ev) => {
      const { sx, sy, ox, oy } = dragging.current;
      setPos({
        x: Math.max(0, Math.min(window.innerWidth  - size.w, ox + ev.clientX - sx)),
        y: Math.max(0, Math.min(window.innerHeight - 40,     oy + ev.clientY - sy)),
      });
    };
    const onUp = () => {
      dragging.current = null;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup',   onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup',   onUp);
  }, [pos, size.w]);

  const onResizeStart = useCallback((e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    e.stopPropagation();
    resizing.current = { sx: e.clientX, sy: e.clientY, ow: size.w, oh: size.h };

    const onMove = (ev) => {
      const { sx, sy, ow, oh } = resizing.current;
      setSize({
        w: Math.max(340, ow + ev.clientX - sx),
        h: Math.max(300, oh + ev.clientY - sy),
      });
    };
    const onUp = () => {
      resizing.current = null;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup',   onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup',   onUp);
  }, [size]);

  if (!pkg || !pos) return null;

  const hasCrit = pkg.cves.some(c => (c.severity||'').toUpperCase() === 'CRITICAL');
  const hasHigh = pkg.cves.some(c => (c.severity||'').toUpperCase() === 'HIGH');
  const topSev  = hasCrit ? 'CRITICAL' : hasHigh ? 'HIGH' : pkg.cves.length > 0 ? 'MEDIUM' : null;

  return (
    <div
      style={{
        position:      'fixed',
        left:          pos.x,
        top:           pos.y,
        width:         size.w,
        height:        size.h,
        zIndex:        1000,
        display:       'flex',
        flexDirection: 'column',
        background:    'var(--bg-surface)',
        border:        '1px solid var(--border-active)',
        borderRadius:  10,
        boxShadow:     '0 12px 48px rgba(0,0,0,.6)',
        overflow:      'hidden',
        userSelect:    'none',
      }}
    >
      {}
      <div
        onMouseDown={onDragStart}
        style={{
          display:        'flex',
          alignItems:     'center',
          justifyContent: 'space-between',
          padding:        '8px 12px',
          background:     'var(--bg-elevated)',
          borderBottom:   '1px solid var(--border)',
          cursor:         'grab',
          flexShrink:     0,
          gap:            8,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
          {}
          <svg width="10" height="14" viewBox="0 0 10 14" style={{ flexShrink: 0, opacity: .4 }}>
            {[0,4,8].map(y => [0,5].map(x =>
              <circle key={`${x}${y}`} cx={x+2} cy={y+3} r="1.2" fill="var(--text-muted)"/>
            ))}
          </svg>
          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {pkg.name}
          </span>
          {topSev && <SevBadge sev={topSev} />}
        </div>
        <button
          onClick={onClose}
          onMouseDown={e => e.stopPropagation()}
          style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 6, padding: '3px 8px', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, flexShrink: 0 }}
        >✕</button>
      </div>

      {}
      <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px', userSelect: 'text' }}>

        {}
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14, fontFamily: 'JetBrains Mono,monospace' }}>
          {pkg.version} · {pkg.type}{pkg.license ? ` · ${pkg.license}` : ''}
        </div>

        {}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.08em', color: 'var(--text-muted)', marginBottom: 10, paddingBottom: 5, borderBottom: '1px solid var(--border)' }}>
            CVEs ({pkg.cves.length})
          </div>

          {pkg.cves.length === 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '8px 0' }}>No known vulnerabilities</div>
          )}

          {pkg.cves.map(c => {
            const epss     = c.epssScore > 0 ? epssLabel(c.epssScore) : null;
            const riskCol  = RISK_COLORS[c.riskLabel] || 'var(--text-muted)';
            return (
              <div key={c.id} style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 12px', marginBottom: 8 }}>

                {}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' }}>{c.id}</span>
                    {c.inKev && <span style={{ fontSize: 8, padding: '1px 4px', borderRadius: 2, background: 'rgba(239,68,68,.15)', color: 'var(--danger)', fontWeight: 700 }}>KEV</span>}
                    {c.pocs?.length > 0 && <span style={{ fontSize: 8, padding: '1px 4px', borderRadius: 2, background: 'rgba(245,158,11,.15)', color: 'var(--warning)', fontWeight: 700 }}>PoC</span>}
                  </div>
                  <SevBadge sev={(c.severity||'').toUpperCase()} />
                </div>

                {}
                {(c.title || c.description) && (
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 8 }}>
                    {c.title || (c.description?.length > 120 ? c.description.slice(0, 120) + '…' : c.description)}
                  </div>
                )}

                {}
                {c.riskScore > 0 && (
                  <div style={{ marginBottom: 8, padding: '7px 10px', background: 'var(--bg-surface)', borderRadius: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Risk Score</span>
                      <span style={{ fontSize: 11, fontWeight: 700, color: riskCol, fontFamily: 'JetBrains Mono,monospace' }}>{c.riskScore}/100 · {c.riskLabel}</span>
                    </div>
                    <div style={{ height: 4, background: 'rgba(255,255,255,.06)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${c.riskScore}%`, background: riskCol, borderRadius: 2 }}/>
                    </div>
                  </div>
                )}

                {}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 6 }}>
                  <div style={{ background: 'var(--bg-surface)', borderRadius: 5, padding: '5px 8px' }}>
                    <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '.04em' }}>CVSS v3</div>
                    <div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'JetBrains Mono,monospace', color: sevColor(c.severity) }}>
                      {c.cvssV3Score ? c.cvssV3Score.toFixed(1) : '—'}
                    </div>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', borderRadius: 5, padding: '5px 8px' }}>
                    <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '.04em' }}>EPSS</div>
                    <div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'JetBrains Mono,monospace', color: epss?.color || 'var(--text-secondary)' }}>
                      {c.epssScore ? (c.epssScore * 100).toFixed(2) + '%' : '—'}
                    </div>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', borderRadius: 5, padding: '5px 8px' }}>
                    <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '.04em' }}>Fix</div>
                    <div style={{ fontSize: 11, fontWeight: 600, color: c.hasFix ? 'var(--accent-3)' : 'var(--text-muted)' }}>
                      {c.hasFix ? (c.fixedIn || 'Available') : 'None'}
                    </div>
                  </div>
                </div>

                {}
                {c.hasFix && (
                  <div style={{ marginTop: 8, padding: '6px 10px', background: 'rgba(16,185,129,.08)', border: '1px solid rgba(16,185,129,.2)', borderRadius: 6, fontSize: 11, color: 'var(--accent-3)' }}>
                    ✓ Fix available — upgrade to <strong>{c.fixedIn}</strong>
                  </div>
                )}

                {}
                {c.pocs?.length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    {c.pocs.map((p, i) => (
                      <a key={i} href={p.url} target="_blank" rel="noreferrer"
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 7px', borderRadius: 4, background: 'rgba(245,158,11,.06)', border: '1px solid rgba(245,158,11,.15)', marginBottom: 3, textDecoration: 'none' }}>
                        <span style={{ fontSize: 10, color: 'var(--warning)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>💣 {p.name}</span>
                        {p.stars > 0 && <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 6, flexShrink: 0 }}>⭐{p.stars}</span>}
                      </a>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {}
        <div>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.08em', color: 'var(--text-muted)', marginBottom: 10, paddingBottom: 5, borderBottom: '1px solid var(--border)' }}>
            Lib uses — appears in {pkg.images.length} {pkg.images.length === 1 ? 'image' : 'images'}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, paddingBottom: 12 }}>
            {pkg.images.map(img => (
              <div key={img} style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)' }}>{img.split(':')[0]}</div>
                  <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-muted)', marginTop: 2 }}>{img}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

      {}
      <div
        onMouseDown={onResizeStart}
        style={{ position: 'absolute', right: 0, bottom: 0, width: 20, height: 20, cursor: 'se-resize', display: 'flex', alignItems: 'flex-end', justifyContent: 'flex-end', padding: 4, opacity: .35 }}
      >
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M9 1L1 9M9 5L5 9" stroke="var(--text-muted)" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      </div>
    </div>
  );
}
