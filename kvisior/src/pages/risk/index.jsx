import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScanner } from '../../context/ScannerContext';
import { useSensor }  from '../../context/SensorContext';
import { SevBadge }   from '../../components/ui';

const RISK_COLOR = s => s>=8?'var(--danger)':s>=6?'var(--warning)':s>=4?'#a78bfa':'var(--accent-3)';
const SEV_LABEL  = s => s>=8?'CRITICAL':s>=6?'HIGH':s>=4?'MEDIUM':'LOW';

const SYS_NS = new Set(['kube-system','kube-public','kube-node-lease',
  'metallb-system','calico-system','cert-manager','wolfee-watcher']);

function buildFactors(w, imageResults) {
  const factors = [];
  let score = 0;

  const allCVEs   = imageResults.flatMap(r => r.cves || []);
  const critCount = allCVEs.filter(c => c.severity === 'CRITICAL').length;
  const highCount = allCVEs.filter(c => c.severity === 'HIGH').length;
  const kevCount  = allCVEs.filter(c => c.inKEV).length;
  const maxCVSS   = allCVEs.reduce((m, c) => Math.max(m, c.cvss   || 0), 0);
  const maxEPSS   = allCVEs.reduce((m, c) => Math.max(m, c.epss   || 0), 0);
  const maxRisk   = allCVEs.reduce((m, c) => Math.max(m, c.riskScore || 0), 0);

  if (allCVEs.length > 0) {
    const s = Math.min(4.0, maxRisk * 0.4);
    score += s;
    factors.push({
      icon:'🐛', label:'Vulnerabilities',
      detail:`${allCVEs.length} CVEs · ${critCount} critical · ${highCount} high`,
      score:s, color: critCount>0?'var(--danger)':highCount>0?'var(--warning)':'var(--text-muted)',
    });
  }

  if (kevCount > 0) {
    const s = Math.min(2.0, kevCount * 0.8);
    score += s;
    factors.push({ icon:'💀', label:'Known Exploited (CISA KEV)',
      detail:`${kevCount} CVE${kevCount>1?'s':''} actively exploited in the wild`,
      score:s, color:'var(--danger)' });
  }

  if (maxEPSS >= 0.5) {
    const s = Math.min(0.8, maxEPSS * 0.8);
    score += s;
    factors.push({ icon:'🎯', label:'High Exploit Probability',
      detail:`EPSS ${(maxEPSS*100).toFixed(1)}% — likely to be exploited`,
      score:s, color:'var(--warning)' });
  }

  const containers = [
    ...(w.raw?.spec?.template?.spec?.containers||[]),
    ...(w.raw?.spec?.template?.spec?.initContainers||[]),
  ];
  const privC = containers.filter(c=>c.securityContext?.privileged===true);
  if (privC.length > 0) {
    score += 1.5;
    factors.push({ icon:'🔓', label:'Privileged Containers',
      detail:`${privC.length} container${privC.length>1?'s':''}: ${privC.map(c=>c.name).join(', ')}`,
      score:1.5, color:'var(--danger)' });
  }

  const spec = w.raw?.spec?.template?.spec||{};
  if (spec.hostNetwork) {
    score += 1.0;
    factors.push({ icon:'🌐', label:'Host Network Access', detail:'Pod uses host network namespace', score:1.0, color:'var(--warning)' });
  }
  if (spec.hostPID) {
    score += 0.8;
    factors.push({ icon:'👁', label:'Host PID Access', detail:'Pod can see all host processes', score:0.8, color:'var(--warning)' });
  }

  const noLimits = containers.filter(c=>!c.resources?.limits?.memory&&!c.resources?.limits?.cpu);
  if (noLimits.length > 0 && containers.length > 0) {
    score += 0.3;
    factors.push({ icon:'📈', label:'No Resource Limits',
      detail:`${noLimits.length}/${containers.length} containers without CPU/memory limits`,
      score:0.3, color:'var(--text-muted)' });
  }

  return { score: Math.min(9.9, score), factors, allCVEs,
    critCount, highCount, kevCount, maxCVSS, maxEPSS };
}

export function Risk() {
  const { results }                       = useScanner();
  const { workloads, sensorOnline }       = useSensor();
  const navigate                          = useNavigate();
  const [selected, setSelected]           = useState(null);
  const [search, setSearch]               = useState('');
  const [showSys, setShowSys]             = useState(false);

  const resultByImage = useMemo(() => {
    const m = {};
    results.forEach(r => {
      m[r.image] = r;
      m[r.name]  = r;
      if (r.image) m[r.image.split(':')[0]] = r;
    });
    return m;
  }, [results]);

  const riskRows = useMemo(() => {
    return workloads
      .filter(w => showSys || !SYS_NS.has(w.metadata?.namespace))
      .map(w => {
        const ns   = w.metadata?.namespace || '';
        const name = w.metadata?.name || '';
        const kind = w._kind || 'Deployment';
        const containers = [
          ...(w.spec?.template?.spec?.containers||[]),
          ...(w.spec?.template?.spec?.initContainers||[]),
        ];
        const images = [...new Set(
          containers.map(c=>c.image).filter(img=>img&&!img.startsWith('sha256:'))
        )];
        const imageResults = images
          .map(img => resultByImage[img] || resultByImage[img.split(':')[0]] || null)
          .filter(Boolean);

        const built = buildFactors({ name, ns, kind, raw: w }, imageResults);
        const age = w.metadata?.creationTimestamp
          ? Math.floor((Date.now()-new Date(w.metadata.creationTimestamp))/86400000)
          : null;
        return { name, ns, kind, images, ...built,
          age: age===null?'—':age<1?'today':age+'d' };
      })
      .sort((a,b) => b.score-a.score || b.critCount-a.critCount)
      .map((r,i) => ({ ...r, rank:i+1 }));
  }, [workloads, resultByImage, showSys]);

  const filtered = riskRows.filter(r => {
    if (!search) return true;
    const q = search.toLowerCase();
    return r.name.toLowerCase().includes(q) || r.ns.toLowerCase().includes(q);
  });

  const hasData = workloads.length > 0;

  return (
    <div className="page active flex-page" id="page-risk" style={{flexDirection:'column',padding:0}}>
      <div style={{padding:'20px 24px 0',flexShrink:0}}>
        <div className="page-header" style={{marginBottom:14}}>
          <div>
            <div className="page-title">Risk</div>
            <div className="page-subtitle">Workloads ranked by CVEs · KEV · CIS security posture</div>
          </div>
          <label style={{display:'flex',alignItems:'center',gap:6,fontSize:12,color:'var(--text-muted)',cursor:'pointer',userSelect:'none'}}>
            <input type="checkbox" checked={showSys} onChange={e=>setShowSys(e.target.checked)}
              style={{accentColor:'var(--accent)',cursor:'pointer'}}/>
            show system namespaces
          </label>
        </div>
        <div className="page-search" style={{marginBottom:14}}>
          <input type="text" placeholder="Search workloads…" value={search} onChange={e=>setSearch(e.target.value)}/>
        </div>
      </div>

      <div style={{display:'flex',flex:1,overflow:'hidden'}}>
        <div style={{flex:1,overflowY:'auto',padding:'0 0 24px 24px',minWidth:0}}>
          {!hasData && (
            <div style={{margin:'40px 24px 0 0',padding:32,background:'var(--bg-card)',borderRadius:12,
              border:'1px solid var(--border)',textAlign:'center',color:'var(--text-muted)',fontSize:13}}>
              Sensor offline — waiting for workload data.
            </div>
          )}
          {hasData && (
            <div className="card" style={{marginRight:selected?0:24}}>
              <div className="table-wrap">
                <table className="data-table">
                  <thead><tr>
                    <th style={{width:36}}>#</th>
                    <th>Workload</th>
                    <th>Namespace</th>
                    <th>Risk Score</th>
                    <th>CVEs</th>
                    <th>KEV</th>
                    <th>Age</th>
                  </tr></thead>
                  <tbody>
                    {filtered.length===0 && (
                      <tr><td colSpan={7} style={{textAlign:'center',color:'var(--text-muted)',padding:40}}>No workloads matching filter</td></tr>
                    )}
                    {filtered.map(r => {
                      const color = RISK_COLOR(r.score);
                      return (
                        <tr key={r.name+r.ns}
                          className={selected?.name===r.name&&selected?.ns===r.ns?'selected':''}
                          style={{cursor:'pointer'}}
                          onClick={()=>setSelected(selected?.name===r.name&&selected?.ns===r.ns?null:r)}>
                          <td><SevBadge sev={SEV_LABEL(r.score)}>#{r.rank}</SevBadge></td>
                          <td className="td-primary">
                            {r.name}
                            <span style={{marginLeft:6,fontSize:10,color:'var(--text-muted)',fontWeight:400}}>{r.kind}</span>
                          </td>
                          <td style={{fontSize:12,color:'var(--text-muted)'}}>{r.ns}</td>
                          <td>
                            <div style={{display:'flex',alignItems:'center',gap:8}}>
                              <span className="mono" style={{fontSize:13,color,fontWeight:700,minWidth:28}}>
                                {r.score>0?r.score.toFixed(1):'—'}
                              </span>
                              {r.score>0&&<div style={{flex:1,height:5,background:'var(--bg-elevated)',borderRadius:3,minWidth:60}}>
                                <div style={{width:`${r.score*10}%`,height:'100%',background:color,borderRadius:3}}/>
                              </div>}
                            </div>
                          </td>
                          <td>
                            {r.allCVEs.length>0
                              ?<span style={{fontSize:12}}>
                                {r.critCount>0&&<span style={{color:'var(--danger)',fontWeight:600}}>{r.critCount}C </span>}
                                {r.highCount>0&&<span style={{color:'var(--warning)',fontWeight:600}}>{r.highCount}H </span>}
                                <span style={{color:'var(--text-muted)'}}>{r.allCVEs.length}</span>
                              </span>
                              :<span style={{color:'var(--text-muted)',fontSize:12}}>—</span>}
                          </td>
                          <td>
                            {r.kevCount>0
                              ?<span style={{fontSize:11,padding:'1px 6px',borderRadius:3,
                                background:'rgba(239,68,68,.15)',color:'var(--danger)',fontWeight:600}}>⚠ {r.kevCount}</span>
                              :<span style={{color:'var(--text-muted)',fontSize:12}}>—</span>}
                          </td>
                          <td style={{color:'var(--text-muted)',fontSize:12}}>{r.age}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {}
        {selected && (
          <div className="detail-panel open">
            <div className="detail-panel-inner">
              <div className="dp-header">
                <div>
                  <div className="dp-title">{selected.name}</div>
                  <div className="dp-meta">{selected.kind} · {selected.ns}</div>
                </div>
                <button className="dp-close" onClick={()=>setSelected(null)}>✕</button>
              </div>

              {}
              {(() => {
                const c = RISK_COLOR(selected.score);
                const deg = selected.score * 36;
                return (
                  <div style={{display:'flex',alignItems:'center',gap:16,marginBottom:20,
                    padding:14,background:'var(--bg-elevated)',borderRadius:10}}>
                    <div style={{width:60,height:60,borderRadius:'50%',flexShrink:0,position:'relative',
                      background:`conic-gradient(${c} 0deg ${deg}deg, var(--bg-card) ${deg}deg 360deg)`,
                      display:'flex',alignItems:'center',justifyContent:'center'}}>
                      <div style={{position:'absolute',width:42,height:42,background:'var(--bg-elevated)',borderRadius:'50%'}}/>
                      <span style={{position:'relative',zIndex:1,fontFamily:'JetBrains Mono,monospace',
                        fontSize:15,fontWeight:700,color:c}}>
                        {selected.score>0?selected.score.toFixed(1):'0'}
                      </span>
                    </div>
                    <div>
                      <div style={{fontSize:12,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'.06em'}}>Risk Score</div>
                      <div style={{fontSize:14,fontWeight:700,color:c,marginTop:2}}>{SEV_LABEL(selected.score)}</div>
                      <div style={{fontSize:11,color:'var(--text-muted)',marginTop:2}}>
                        {selected.images.length} image{selected.images.length!==1?'s':''} · {selected.allCVEs.length} CVEs
                      </div>
                    </div>
                  </div>
                );
              })()}

              {}
              <div className="dp-section">Risk Factors</div>
              {selected.factors.length===0
                ?<div style={{padding:20,textAlign:'center',color:'var(--text-muted)',fontSize:12,
                  background:'var(--bg-card)',borderRadius:8,border:'1px solid var(--border)',marginBottom:16}}>
                  No risk factors detected
                </div>
                :<div style={{display:'flex',flexDirection:'column',gap:8,marginBottom:20}}>
                  {selected.factors.sort((a,b)=>b.score-a.score).map((f,i)=>(
                    <div key={i} style={{background:'var(--bg-card)',border:'1px solid var(--border)',
                      borderRadius:8,padding:'10px 12px',display:'flex',gap:10}}>
                      <span style={{fontSize:16,lineHeight:1,marginTop:1,flexShrink:0}}>{f.icon}</span>
                      <div style={{flex:1,minWidth:0}}>
                        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',gap:8}}>
                          <div style={{fontSize:12,fontWeight:600,color:f.color}}>{f.label}</div>
                          <span className="mono" style={{fontSize:11,color:'var(--text-muted)',flexShrink:0}}>+{f.score.toFixed(1)}</span>
                        </div>
                        <div style={{fontSize:11,color:'var(--text-muted)',marginTop:2}}>{f.detail}</div>
                      </div>
                    </div>
                  ))}
                </div>
              }

              {}
              {selected.allCVEs.length>0&&(
                <>
                  <div className="dp-section">Top CVEs</div>
                  <div style={{display:'flex',flexDirection:'column',gap:5,marginBottom:20}}>
                    {selected.allCVEs
                      .sort((a,b)=>(b.riskScore||0)-(a.riskScore||0))
                      .slice(0,6)
                      .map((c,i)=>(
                      <div key={i} style={{display:'flex',alignItems:'center',gap:8,
                        padding:'6px 10px',background:'var(--bg-card)',borderRadius:6,border:'1px solid var(--border)'}}>
                        <span className="mono" style={{fontSize:11,color:'var(--accent)',minWidth:120,flexShrink:0}}>{c.id}</span>
                        <SevBadge sev={c.severity}>{c.severity}</SevBadge>
                        <span className="mono" style={{fontSize:11,color:'var(--text-muted)',marginLeft:'auto',flexShrink:0}}>
                          {(c.cvss||0).toFixed(1)}
                        </span>
                        {c.inKEV&&<span style={{fontSize:10,padding:'1px 5px',borderRadius:3,
                          background:'rgba(239,68,68,.2)',color:'var(--danger)',fontWeight:700,flexShrink:0}}>KEV</span>}
                      </div>
                    ))}
                    {selected.allCVEs.length>6&&<div style={{fontSize:11,color:'var(--text-muted)',textAlign:'center',padding:4}}>
                      +{selected.allCVEs.length-6} more
                    </div>}
                  </div>
                </>
              )}

              {}
              {selected.images.length>0&&(
                <>
                  <div className="dp-section">Images</div>
                  <div style={{display:'flex',flexDirection:'column',gap:6}}>
                    {selected.images.map((img,i)=>(
                      <div key={i}
                        onClick={() => {
                          localStorage.setItem('wv_vuln_image', img);
                          navigate('/vulnmgmt');
                        }}
                        style={{
                          fontSize:11, fontFamily:'monospace',
                          padding:'6px 10px',
                          background:'rgba(99,179,237,.08)',
                          border:'1px solid rgba(99,179,237,.3)',
                          borderRadius:5,
                          color:'var(--accent)',
                          wordBreak:'break-all',
                          cursor:'pointer',
                          display:'flex', alignItems:'center', gap:8,
                          transition:'all .12s',
                        }}
                        onMouseEnter={e=>{e.currentTarget.style.background='rgba(99,179,237,.16)';e.currentTarget.style.borderColor='rgba(99,179,237,.5)';}}
                        onMouseLeave={e=>{e.currentTarget.style.background='rgba(99,179,237,.08)';e.currentTarget.style.borderColor='rgba(99,179,237,.3)';}}>
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{flexShrink:0}}>
                          <rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/>
                        </svg>
                        {img}
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{marginLeft:'auto',flexShrink:0,opacity:.6}}>
                          <path d="M5 12h14M12 5l7 7-7 7"/>
                        </svg>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
