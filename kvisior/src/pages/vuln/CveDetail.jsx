import { useRef, useState, useEffect, useCallback } from 'react';
import { SevBadge }  from '../../components/ui';
import { sevColor, epssLabel } from '../../data/scanner';
import { TabButton, FstecPanel, CvssVectorValue, SoftwareRow, hasShouldFields, linkifyURLs } from './CveDetailHelpers';

const VEX_LABEL = {
  fixed:               { icon: '✅', text: 'Fixed',               color: 'var(--accent-3)' },
  not_fixed:           { icon: '🔴', text: 'Not Fixed',            color: 'var(--danger)'   },
  wont_fix:            { icon: '⚠️', text: "Won't Fix",            color: 'var(--warning)'  },
  under_investigation: { icon: '🔍', text: 'Under Investigation',  color: '#a78bfa'         },
  unknown:             { icon: '❓', text: 'Unknown',              color: 'var(--text-muted)'},
};

const RISK_COLORS = {
  CRITICAL: 'var(--danger)',
  HIGH:     'var(--warning)',
  MEDIUM:   '#a78bfa',
  LOW:      'var(--accent-3)',
};

const WIN_W = 480;
const WIN_H = 560;

const FSTEC_SEV_COLOR = {
  critical: 'var(--danger)',
  high:     'var(--warning)',
  medium:   '#a78bfa',
  low:      'var(--accent-3)',
};

export function CveDetail({ item, onClose }) {
  const [pos,  setPos]  = useState(null);
  const [size, setSize] = useState({ w: WIN_W, h: WIN_H });
  const [tab,  setTab]  = useState('nvd');
  const [showMore, setShowMore] = useState(false);
  const dragging = useRef(null);
  const resizing = useRef(null);

  useEffect(() => {
    if (item) {
      setSize({ w: WIN_W, h: WIN_H });
      setPos({
        x: Math.max(0, window.innerWidth  - WIN_W - 32),
        y: Math.max(0, (window.innerHeight - WIN_H) / 2),
      });
      setTab('nvd');
      setShowMore(false);
    }
  }, [item?.id]);

  const onDragStart = useCallback((e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    dragging.current = { sx: e.clientX, sy: e.clientY, ox: pos.x, oy: pos.y };

    const onMove = (ev) => {
      const { sx, sy, ox, oy } = dragging.current;
      setPos(p => ({
        x: Math.max(0, Math.min(window.innerWidth  - size.w, ox + ev.clientX - sx)),
        y: Math.max(0, Math.min(window.innerHeight - 40,     oy + ev.clientY - sy)),
      }));
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
        w: Math.max(320, ow + ev.clientX - sx),
        h: Math.max(280, oh + ev.clientY - sy),
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

  if (!item || item._isScanResult || !pos) return null;

  const c    = item;
  const epss = c.epssScore > 0 ? epssLabel(c.epssScore) : null;
  const vex  = VEX_LABEL[c.vexStatus] || VEX_LABEL.unknown;
  const hasFstec   = !!(c.bduDetail || c.bduId);

  const kv = (label, val) => (
    <div key={label} style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', padding:'5px 0', borderBottom:'1px solid rgba(255,255,255,.04)', fontSize:12, gap:12 }}>
      <span style={{ color:'var(--text-muted)', flexShrink:0, minWidth:100 }}>{label}</span>
      <span style={{ color:'var(--text-secondary)', textAlign:'right', wordBreak:'break-all' }}>{val}</span>
    </div>
  );

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
        <div style={{ display:'flex', alignItems:'center', gap:8, minWidth:0 }}>
          {}
          <svg width="10" height="14" viewBox="0 0 10 14" style={{ flexShrink:0, opacity:.4 }}>
            {[0,4,8].map(y => [0,5].map(x =>
              <circle key={`${x}${y}`} cx={x+2} cy={y+3} r="1.2" fill="var(--text-muted)"/>
            ))}
          </svg>
          <span style={{ fontSize:12, fontFamily:'JetBrains Mono,monospace', color:'var(--text-primary)', fontWeight:600, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
            {c.id}
          </span>
          <SevBadge sev={c.severity?.toUpperCase()} />
        </div>
        <button
          onClick={onClose}
          onMouseDown={e => e.stopPropagation()}
          style={{ background:'none', border:'1px solid var(--border)', borderRadius:6, padding:'3px 8px', color:'var(--text-muted)', cursor:'pointer', fontSize:13, flexShrink:0 }}
        >✕</button>
      </div>

      {}
      <div
        onMouseDown={e => e.stopPropagation()}
        style={{
          display:      'flex',
          gap:          0,
          padding:      '0 12px',
          background:   'var(--bg-elevated)',
          borderBottom: '1px solid var(--border)',
          flexShrink:   0,
        }}
      >
        <TabButton active={tab === 'nvd'}   onClick={() => setTab('nvd')}>NVD</TabButton>
        <TabButton active={tab === 'fstec'} onClick={() => setTab('fstec')} disabled={!hasFstec}>
          ФСТЭК
        </TabButton>
      </div>

      {}
      {tab === 'nvd' && (
      <div style={{ flex:1, overflowY:'auto', padding:'14px 16px', userSelect:'text' }}>

        <div style={{ fontSize:12, color:'var(--text-muted)', marginBottom:12 }}>
          {c.pkgName} {c.pkgVersion}
        </div>

        {}
        <div style={{ display:'flex', gap:6, marginBottom:14, flexWrap:'wrap' }}>
          {c.cvssV3Score > 0 && (
            <span style={{ fontSize:11, padding:'2px 8px', borderRadius:4, background:'rgba(255,255,255,.06)', color:sevColor(c.severity), fontFamily:'JetBrains Mono,monospace', fontWeight:700 }}>
              CVSS {c.cvssV3Score.toFixed(1)}
            </span>
          )}
          {epss && (
            <span style={{ fontSize:11, padding:'2px 8px', borderRadius:4, background:'rgba(255,255,255,.06)', color:epss.color, fontFamily:'JetBrains Mono,monospace' }}>
              EPSS {epss.text}
            </span>
          )}
          {c.inKev && (
            <span style={{ fontSize:11, padding:'2px 8px', borderRadius:4, background:'rgba(239,68,68,.15)', color:'var(--danger)', fontWeight:700 }}>
              🔥 CISA KEV
            </span>
          )}
          {c.pocs?.length > 0 && (
            <span style={{ fontSize:11, padding:'2px 8px', borderRadius:4, background:'rgba(245,158,11,.12)', color:'var(--warning)' }}>
              💣 PoC ({c.pocs.length})
            </span>
          )}
        </div>

        {}
        {c.riskScore > 0 && (
          <div style={{ marginBottom:14, padding:'10px 12px', background:'var(--bg-elevated)', border:'1px solid var(--border)', borderRadius:8 }}>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
              <span style={{ fontSize:11, color:'var(--text-muted)' }}>Risk Score</span>
              <span style={{ fontSize:12, fontWeight:700, color:RISK_COLORS[c.riskLabel]||'var(--text-muted)', fontFamily:'JetBrains Mono,monospace' }}>
                {c.riskScore}/100 · {c.riskLabel}
              </span>
            </div>
            <div style={{ height:5, background:'rgba(255,255,255,.06)', borderRadius:3, overflow:'hidden' }}>
              <div style={{ height:'100%', width:`${c.riskScore}%`, background:RISK_COLORS[c.riskLabel]||'var(--accent)', borderRadius:3, transition:'width .3s' }}/>
            </div>
            <div style={{ fontSize:10, color:'var(--text-muted)', marginTop:4 }}>60% CVSS · 40% EPSS weighted score</div>
          </div>
        )}

        {c.title && (
          <div style={{ fontSize:12, color:'var(--text-secondary)', marginBottom:12, lineHeight:1.5 }}>{c.title}</div>
        )}

        {}
        <div style={{ marginBottom:12 }}>
          {kv('Package',    <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11 }}>{c.pkgName}</span>)}
          {kv('Installed',  <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11 }}>{c.pkgVersion}</span>)}
          {c.fixedIn   && kv('Fixed in',   <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11, color:'var(--accent-3)' }}>{c.fixedIn}</span>)}
          {c.pkgType   && kv('Type',        <span style={{ fontSize:11 }}>{c.pkgType}</span>)}
          {c.cwes?.length > 0 && kv('CWE', <span style={{ fontSize:11 }}>{c.cwes.join(', ')}</span>)}
          {c.publishedDate && kv('Published', c.publishedDate)}
          {c._imageName && kv('Image',      <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:11 }}>{c._imageName}:{c._imageTag||''}</span>)}
          {kv('VEX / Fix State',
            <span style={{ fontSize:11, color:vex.color }}>
              {vex.icon} {vex.text}
              {c.vexSource && <span style={{ color:'var(--text-muted)', marginLeft:4 }}>({c.vexSource})</span>}
            </span>
          )}
          {(c.cvssV3Vector || c.cvssV3Score > 0) && kv('CVSS v3 Vector',
            <CvssVectorValue vector={c.cvssV3Vector} score={c.cvssV3Score} />
          )}
          {(c.cvssV2Vector || c.cvssV2Score > 0) && kv('CVSS v2 Vector',
            <CvssVectorValue vector={c.cvssV2Vector} score={c.cvssV2Score} />
          )}
          {(c.cvssV4Vector || c.cvssV4Score > 0) && kv('CVSS v4 Vector',
            <CvssVectorValue vector={c.cvssV4Vector} score={c.cvssV4Score} />
          )}
          {c.epssScore > 0 && kv('EPSS',
            <span style={{ fontSize:11 }}>
              <span style={{ color:epss?.color, fontFamily:'JetBrains Mono,monospace', fontWeight:700 }}>
                {(c.epssScore*100).toFixed(3)}%
              </span>
              {c.epssPercentile > 0 && (
                <span style={{ color:'var(--text-muted)', marginLeft:6 }}>
                  ({Math.round(c.epssPercentile*100)}th percentile)
                </span>
              )}
            </span>
          )}
          {kv('CISA KEV',
            c.inKev
              ? <span style={{ color:'var(--danger)', fontSize:11, fontWeight:700 }}>🔥 Actively exploited</span>
              : <span style={{ color:'var(--text-muted)', fontSize:11 }}>Not listed</span>
          )}
        </div>

        {}
        {c.hasFix && (
          <div style={{ margin:'12px 0', padding:'8px 12px', background:'rgba(16,185,129,.08)', border:'1px solid rgba(16,185,129,.2)', borderRadius:8, fontSize:12, color:'var(--accent-3)' }}>
            ✓ Fix available — upgrade to <strong>{c.fixedIn}</strong>
          </div>
        )}

        {}
        {c.pocs?.length > 0 && (
          <div style={{ marginTop:14 }}>
            <div style={{ fontSize:11, textTransform:'uppercase', letterSpacing:'.07em', color:'var(--warning)', marginBottom:8, fontWeight:600 }}>
              💣 Public PoC Exploits ({c.pocs.length})
            </div>
            {c.pocs.map((p, i) => (
              <a key={i} href={p.url} target="_blank" rel="noreferrer"
                style={{ display:'flex', alignItems:'center', justifyContent:'space-between', padding:'5px 8px', borderRadius:5, background:'rgba(245,158,11,.06)', border:'1px solid rgba(245,158,11,.15)', marginBottom:4, textDecoration:'none' }}>
                <span style={{ fontSize:11, color:'var(--warning)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', flex:1 }}>{p.name}</span>
                {p.stars > 0 && <span style={{ fontSize:10, color:'var(--text-muted)', marginLeft:8, flexShrink:0 }}>⭐{p.stars}</span>}
              </a>
            ))}
          </div>
        )}

        {}
        {c.description && (
          <div style={{ marginTop:14 }}>
            <div style={{ fontSize:11, textTransform:'uppercase', letterSpacing:'.07em', color:'var(--text-muted)', marginBottom:6 }}>Description</div>
            <div style={{ fontSize:12, color:'var(--text-secondary)', lineHeight:1.6 }}>{c.description}</div>
          </div>
        )}

        {}
        {c.references?.length > 0 && (
          <div style={{ marginTop:14, paddingBottom:12 }}>
            <div style={{ fontSize:11, textTransform:'uppercase', letterSpacing:'.07em', color:'var(--text-muted)', marginBottom:6 }}>References</div>
            {c.references.slice(0, 6).map((ref, i) => (
              <a key={i} href={ref} target="_blank" rel="noreferrer"
                style={{ display:'block', fontSize:11, color:'var(--accent)', marginBottom:3, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                {ref}
              </a>
            ))}
          </div>
        )}
      </div>
      )}

      {tab === 'fstec' && (
        <FstecPanel item={c} kv={kv} showMore={showMore} setShowMore={setShowMore} />
      )}

      {}
      <div
        onMouseDown={onResizeStart}
        style={{ position:'absolute', right:0, bottom:0, width:20, height:20, cursor:'se-resize', display:'flex', alignItems:'flex-end', justifyContent:'flex-end', padding:4, opacity:.35 }}
      >
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M9 1L1 9M9 5L5 9" stroke="var(--text-muted)" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      </div>
    </div>
  );
}

