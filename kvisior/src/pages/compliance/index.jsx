import { useState, useEffect, useCallback, useRef } from 'react';
import { useSensor } from '../../context/SensorContext';
import { FSTEC } from './checksFSTEC';
import '../../styles/compliance.scss';
import { CIS }   from './complianceCIS';
import { NIST }  from './complianceNIST';
import { PCI }   from './compliancePCI';
import { HIPAA } from './complianceHIPAA';

const STANDARDS = [
  { id:'CIS',   label:'CIS Kubernetes 1.5', checks: CIS,   color:'var(--accent)' },
  { id:'NIST',  label:'NIST 800-190',       checks: NIST,  color:'var(--accent-2)' },
  { id:'PCI',   label:'PCI DSS',            checks: PCI,   color:'var(--warning)' },
  { id:'HIPAA', label:'HIPAA',              checks: HIPAA, color:'var(--accent-3)' },
  { id:'FSTEC', label:'ФСТЭК 118',          checks: FSTEC, color:'var(--danger)' },
];

function runStandard(std, data) {
  const results = std.checks.map(c => {
    try {
      const r = c.fn(data);
      return { ...c, ...r, score: Math.round(r.passing / r.total * 100) };
    } catch(e) {
      return { ...c, passing:0, total:1, score:0, entities:[], fix:'', err: e.message };
    }
  });
  const overall = results.length
    ? Math.round(results.reduce((s,r)=>s+r.score,0) / results.length)
    : 0;
  return { ...std, results, overall };
}

function scoreColor(n) { return n>=80?'var(--accent-3)':n>=50?'var(--warning)':'var(--danger)'; }

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

const REFRESH_MS = 10 * 60 * 1000;

export function Compliance() {
  const { snapshot } = useSensor();
  const [standards, setStandards] = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState(null);
  const [lastScan,  setLastScan]  = useState(null);
  const [nextIn,    setNextIn]    = useState(REFRESH_MS);
  const [activeStd, setActiveStd] = useState('CIS');
  const [expanded,  setExpanded]  = useState(null);
  const [catFilter, setCatFilter] = useState('all');
  const timerRef = useRef(null);
  const countRef = useRef(null);

  const scan = useCallback(async () => {
    if (!snapshot) return;
    setLoading(true); setError(null);
    try {
      const [scanRes, anomalyRes] = await Promise.all([
        fetch('/scanner/results', { credentials: 'same-origin' }).catch(()=>null),
        fetch('/anomaly/api/anomalies?limit=500', { credentials: 'same-origin', signal: AbortSignal.timeout(5000) }).catch(()=>null),
      ]);
      const data = {
        snap:    snapshot,
        scan:    scanRes?.ok    ? await scanRes.json()    : { results:[] },
        anomaly: anomalyRes?.ok ? await anomalyRes.json() : { events:[] },
      };
      setStandards(STANDARDS.map(std => runStandard(std, data)));
      setLastScan(new Date());
      setNextIn(REFRESH_MS);
    } catch(e) { setError(e.message); }
    setLoading(false);
  }, [snapshot]);

  useEffect(() => {
    scan();
    timerRef.current = setInterval(scan, REFRESH_MS);
    countRef.current = setInterval(() => setNextIn(n => Math.max(0, n-1000)), 1000);
    return () => { clearInterval(timerRef.current); clearInterval(countRef.current); };
  }, [scan]);

  const fmtCountdown = ms => {
    const s = Math.ceil(ms/1000);
    return `${Math.floor(s/60)}:${String(s%60).padStart(2,'0')}`;
  };

  const current  = standards.find(s => s.id === activeStd);
  const cats     = current ? ['all', ...new Set(current.results.map(r=>r.cat))] : ['all'];
  const visible  = current
    ? current.results.filter(r => catFilter==='all'||r.cat===catFilter)
        .slice().sort((a,b) => a.score-b.score)
    : [];

  return (
    <div className="co-page">
      <div className="co-header">
        <div>
          <span className="co-header-title">Compliance</span>
          <span className="co-header-sep">·</span>
          <span className="co-header-sub">CIS Kubernetes · NIST 800-190 · PCI DSS · HIPAA · ФСТЭК 118</span>
        </div>
        <div className="co-header-right">
          {lastScan && !loading && (
            <span className="co-next-scan">↺ in {fmtCountdown(nextIn)}</span>
          )}
          {lastScan && (
            <span className="co-last-scan">
              Last scan: {lastScan.toLocaleTimeString()}
            </span>
          )}
          <button className="co-btn" onClick={scan} disabled={loading}>
            {loading ? '…' : '↺'} Scan now
          </button>
        </div>
      </div>

      {error && <div className="co-banner">⚠ {error}</div>}
      {loading && <div className="co-splash"><div className="np-spinner"/><span>Running compliance scan…</span></div>}

      {!loading && !error && (
        <>
          {}
          <div className="co-standards-bar">
            {standards.map(std => (
              <div key={std.id}
                className={`co-std-card${activeStd===std.id?' co-std-card--active':''}`}
                style={{'--std-color': std.color}}
                onClick={()=>{ setActiveStd(std.id); setCatFilter('all'); setExpanded(null); }}>
                <div className="co-std-donut-wrap">
                  <Donut value={std.overall} size={60} stroke={6} color={std.color}/>
                  <span className="co-std-pct" style={{color:std.color}}>{std.overall}%</span>
                </div>
                <div>
                  <div className="co-std-name">{std.label}</div>
                  <div className="co-std-sub">{std.results.filter(r=>r.score===100).length}/{std.results.length} controls</div>
                </div>
              </div>
            ))}
          </div>

          {current && (
            <div className="co-main">
              {}
              <div className="co-cat-sidebar">
                <div className="co-cat-title">Categories</div>
                {cats.map(cat => {
                  const cr    = cat==='all' ? current.results : current.results.filter(r=>r.cat===cat);
                  const score = cr.length ? Math.round(cr.reduce((s,r)=>s+r.score,0)/cr.length) : 0;
                  return (
                    <div key={cat} className={`co-cat-item${catFilter===cat?' active':''}`}
                      onClick={()=>setCatFilter(cat)}>
                      <span className="co-cat-name">{cat}</span>
                      {cat!=='all'&&<span className="co-cat-score" style={{color:scoreColor(score)}}>{score}%</span>}
                    </div>
                  );
                })}
              </div>

              {}
              <div className="co-controls-wrap">
                <div className="co-controls-topbar">
                  <span className="co-controls-title">
                    {current.label}{catFilter!=='all'?` — ${catFilter}`:''}<span style={{color:'var(--text-muted)',fontWeight:400}}> ({visible.length})</span>
                  </span>
                  <div className="co-controls-legend">
                    <span className="co-leg-dot" style={{background:'var(--accent-3)'}}/>100%
                    <span className="co-leg-dot" style={{background:'var(--warning)',marginLeft:10}}/>partial
                    <span className="co-leg-dot" style={{background:'var(--danger)',marginLeft:10}}/>0%
                  </div>
                </div>

                <div className="co-controls">
                  {visible.map(r => (
                    <div key={r.id}
                      className={`co-ctrl${expanded===r.id?' co-ctrl--open':''}`}
                      onClick={()=>setExpanded(expanded===r.id?null:r.id)}>
                      <div className="co-ctrl-row">
                        <div className="co-ctrl-donut">
                          <Donut value={r.score} size={34} stroke={4}/>
                          <span className="co-ctrl-donut-pct" style={{color:scoreColor(r.score)}}>{r.score}%</span>
                        </div>
                        <div className="co-ctrl-body">
                          <span className="co-ctrl-title">{r.title}</span>
                          <span className="co-ctrl-sub">{r.passing}/{r.total} {r.total===1?'check':'entities'} passing</span>
                        </div>
                        <span className="co-ctrl-cat">{r.cat}</span>
                        <span className="co-ctrl-chev">{expanded===r.id?'▾':'▸'}</span>
                      </div>

                      {expanded===r.id&&(
                        <div className="co-ctrl-expand">
                          <div className="co-ctrl-expand-row">
                            <span>Score</span>
                            <code style={{color:scoreColor(r.score),fontWeight:700}}>{r.score}%</code>
                          </div>
                          <div className="co-ctrl-expand-row">
                            <span>Passing</span><code>{r.passing} / {r.total}</code>
                          </div>
                          {(r.total-r.passing)>0&&(
                            <div className="co-ctrl-expand-row co-ctrl-expand-row--top">
                              <span>Failing</span>
                              <div className="co-ctrl-entities" style={{maxHeight:120,overflowY:'auto'}}>
                                {r.entities?.length>0
                                  ? r.entities.map((e,i)=><span key={i} className="co-ctrl-entity">{e}</span>)
                                  : <span className="co-ctrl-entity co-ctrl-entity--more">{r.total-r.passing} entities</span>
                                }
                              </div>
                            </div>
                          )}
                          <div className="co-ctrl-expand-row co-ctrl-expand-row--top">
                            <span>Fix</span>
                            <span style={{fontSize:11,color:'var(--text-secondary)',lineHeight:1.4}}>{r.fix}</span>
                          </div>
                          {r.err&&<div className="co-ctrl-expand-row"><span>Error</span><code style={{color:'var(--danger)'}}>{r.err}</code></div>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
