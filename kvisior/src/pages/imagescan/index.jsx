import { useState, useMemo, useRef, useEffect } from 'react';
import { useScanner } from '../../context/ScannerContext';
import { SevBadge, StatusDot } from '../../components/ui';
import { useApp } from '../../context/AppContext';
import { epssLabel, sevColor, fmtDuration } from '../../data/scanner';
import { FilterDD }        from './FilterDD';
import { ImageDetailPanel } from './ImageDetailPanel';

const SCAN_TABS = [
  { id: 'results',    label: 'Scan Results' },
  { id: 'namespaces', label: 'Namespaces' },
  { id: 'unscanned',  label: 'Unscanned' },
  { id: 'policies',   label: 'Scan Policies' },
  { id: 'history',    label: 'Scan History' },
];

const MOCK_POLICIES = [
  { name: 'Block on Critical CVE',  scope: 'All registries',       action: 'Block deploy', ac: 'var(--danger)',  last: '2m ago', status: 'active' },
  { name: 'Warn on High CVE',       scope: 'production namespace', action: 'Alert only',   ac: 'var(--warning)', last: '8m ago', status: 'active' },
  { name: 'Block on OS EOL',        scope: 'prod-cluster',         action: 'Block deploy', ac: 'var(--danger)',  last: '1h ago', status: 'active' },
  { name: 'Require signed images',  scope: 'All clusters',         action: 'Block deploy', ac: 'var(--danger)',  last: 'Never',  status: 'warn'   },
];

const MOCK_HISTORY = [
  { started: 'Mar 06 · 09:14', images: 94, dur: '1m 12s', newC: '+8',  fixed: '-34', r: 'active' },
  { started: 'Mar 06 · 08:00', images: 94, dur: '58s',    newC: '+2',  fixed: '-12', r: 'active' },
  { started: 'Mar 05 · 23:00', images: 91, dur: '1m 04s', newC: '0',   fixed: '-7',  r: 'active' },
  { started: 'Mar 05 · 18:30', images: 91, dur: '—',      newC: '—',   fixed: '—',   r: 'error'  },
  { started: 'Mar 05 · 12:00', images: 89, dur: '1m 22s', newC: '+14', fixed: '-6',  r: 'active' },
];

export function ImageScan() {
  const { toast } = useApp();
  const { clusterImages, results, summary, scanning, progress, agentOnline, startScan } = useScanner();
  const [tab, setTab]       = useState('results');
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState('');
  const [sevChecked, setSevChecked] = useState(['Critical','High','Medium','Low']);
  const [regChecked, setRegChecked] = useState(['docker.io','gcr.io','quay.io','registry.k8s.io','sha256']);

  const filtered = useMemo(()=>{
    const q=search.toLowerCase();
    return results.filter(r=>!q||r.name?.toLowerCase().includes(q)||(r.namespaces||[]).some(n=>n.toLowerCase().includes(q)));
  },[results,search]);

  const unscanned = clusterImages.filter(img=>!results.find(r=>r.image===img.ref||r.name===img.name));

  const nsByNs = useMemo(()=>{
    const m={};
    results.forEach(r=>(r.namespaces||[]).forEach(ns=>{
      if(!m[ns]) m[ns]={ns,images:0,total:0,critical:0,high:0,pods:new Set()};
      m[ns].images++; m[ns].total+=r.summary?.total||0;
      m[ns].critical+=r.summary?.critical||0; m[ns].high+=r.summary?.high||0;
      (r.pods||[]).forEach(p=>m[ns].pods.add(p));
    }));
    return Object.values(m).sort((a,b)=>b.critical-a.critical);
  },[results]);

  const handleScanAll = async()=>{
    if(!agentOnline){toast('error','Scanner offline','scanner-agent unreachable');return;}
    try{await startScan([],true);setTab('history');toast('info','Scan started','Scanning all cluster images…');}
    catch(e){toast('error','Scan failed',e.message);}
  };
  const handleScanOne = async(ref)=>{
    if(!agentOnline){toast('error','Scanner offline','scanner-agent unreachable');return;}
    try{await startScan([ref]);toast('info','Scanning',ref);}
    catch(e){toast('error','Scan failed',e.message);}
  };

  const toggleSev=(s)=>setSevChecked(p=>p.includes(s)?p.filter(x=>x!==s):[...p,s]);
  const toggleReg=(s)=>setRegChecked(p=>p.includes(s)?p.filter(x=>x!==s):[...p,s]);

  const imgStatus=(r)=>{
    if(!r) return ['warn','Unscanned'];
    if((r.summary?.critical||0)>0) return ['error','Action needed'];
    if((r.summary?.high||0)>0)     return ['warn','Review'];
    return ['active','Clean'];
  };

  return (
    <div className="page active" id="page-imagescan">

      {}
      <div className="page-header">
        <div>
          <div className="page-title">Image Scan</div>
          <div className="page-subtitle">Scan results and vulnerability findings across container images</div>
        </div>
        <div style={{display:'flex',gap:8}}>
          <button className="btn btn-outline" onClick={()=>toast('info','Export','Preparing CSV…')}>📥 Export</button>
          <button className="btn btn-primary" onClick={handleScanAll} disabled={scanning||!agentOnline}
            style={{opacity:(scanning||!agentOnline)?0.6:1}}>
            {scanning?'⏳ Scanning…':'🔍 Scan Now'}
          </button>
        </div>
      </div>

      {}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Images Scanned</div>
          <div className="stat-value info">{results.length}</div>
          <div className="stat-delta"><StatusDot type={agentOnline?'active':'error'} label={agentOnline?'Agent online':'Agent offline'}/></div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Images with Critical</div>
          <div className="stat-value danger">{results.filter(r=>(r.summary?.critical||0)>0).length}</div>
          <div className="stat-delta up">require attention</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Fixable CVEs</div>
          <div className="stat-value success">{summary?.fixable||0}</div>
          <div className="stat-delta down">can be remediated</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Unscanned</div>
          <div className="stat-value warn">{unscanned.length}</div>
          <div className="stat-delta">{unscanned.length>0?'require attention':'all images scanned'}</div>
        </div>
      </div>

      {}
      <div className="tabs">
        {SCAN_TABS.map(t=>(
          <div key={t.id} className={`tab${tab===t.id?' active':''}`}
            onClick={()=>{setTab(t.id);setSelected(null);}}>{t.label}</div>
        ))}
      </div>

      {}
      {tab==='results' && <>
        <div className="page-search">
          <input type="text" placeholder="Search images…" value={search} onChange={e=>setSearch(e.target.value)}/>
          <FilterDD label="Severity" options={['Critical','High','Medium','Low']} checked={sevChecked} onChange={toggleSev}/>
          <FilterDD label="Registry" options={['docker.io','gcr.io','quay.io','registry.k8s.io','sha256']} checked={regChecked} onChange={toggleReg}/>
        </div>
        <div className="card">
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>Image</th><th>Tag</th><th>OS</th><th>CVEs</th><th>Critical</th><th>High</th><th>Deployment</th><th>Last Scanned</th><th>Status</th></tr>
              </thead>
              <tbody>
                {filtered.map((r,i)=>{
                  const [st,sl]=imgStatus(r);
                  return (
                    <tr key={i} style={{cursor:'pointer'}} className={selected===r?'selected':''}
                      onClick={()=>setSelected(selected===r?null:r)}>
                      <td className="td-primary mono" style={{fontSize:11}}>{r.name}</td>
                      <td className="mono" style={{fontSize:11}}>{r.tag}</td>
                      <td style={{fontSize:11}}>{r.os||'—'}</td>
                      <td>{r.summary?.total??0}</td>
                      <td>{(r.summary?.critical||0)>0?<span className="sev sev-critical">{r.summary.critical}</span>:'—'}</td>
                      <td>{(r.summary?.high||0)>0?<span className="sev sev-high">{r.summary.high}</span>:'—'}</td>
                      <td style={{color:'var(--accent)',fontSize:12}}>{(r.pods||[])[0]||'—'}</td>
                      <td style={{color:'var(--text-muted)',fontSize:11}}>{r.scannedAt?new Date(r.scannedAt).toLocaleTimeString():'—'}</td>
                      <td><StatusDot type={st} label={sl}/></td>
                    </tr>
                  );
                })}
                {filtered.length===0&&(
                  <tr><td colSpan={9} style={{textAlign:'center',color:'var(--text-muted)',padding:40}}>
                    {agentOnline?'No results yet — click "Scan Now"':'⚠ scanner-agent offline'}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </>}

      {}
      {tab==='namespaces' && (
        <div className="card">
          <div className="card-header"><div className="card-title">CVE Exposure by Namespace</div></div>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Namespace</th><th>Images</th><th>Total CVEs</th><th>Critical</th><th>High</th><th>Pods Affected</th><th>Risk</th></tr></thead>
              <tbody>
                {nsByNs.map((ns,i)=>{
                  const rsk=ns.critical>0?['error','High']:ns.high>0?['warn','Medium']:['active','Low'];
                  return(
                    <tr key={i} style={{cursor:'pointer'}}>
                      <td className="td-primary">{ns.ns}</td><td>{ns.images}</td><td>{ns.total}</td>
                      <td>{ns.critical>0?<span className="sev sev-critical">{ns.critical}</span>:'—'}</td>
                      <td>{ns.high>0?<span className="sev sev-high">{ns.high}</span>:'—'}</td>
                      <td style={{fontSize:11,color:'var(--text-muted)'}}>{[...ns.pods].slice(0,3).join(', ')}{ns.pods.size>3?'…':''}</td>
                      <td><StatusDot type={rsk[0]} label={rsk[1]}/></td>
                    </tr>
                  );
                })}
                {nsByNs.length===0&&<tr><td colSpan={7} style={{textAlign:'center',color:'var(--text-muted)',padding:40}}>No scan data</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {}
      {tab==='unscanned' && (
        <div className="card">
          <div className="card-header"><div className="card-title">Unscanned Images</div></div>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Image</th><th>Deployment</th><th>Namespace</th><th>Reason</th><th/></tr></thead>
              <tbody>
                {unscanned.map((img,i)=>(
                  <tr key={i}>
                    <td className="td-primary mono" style={{fontSize:11}}>{img.ref}</td>
                    <td>{(img.pods||[])[0]||'—'}</td>
                    <td>{(img.namespaces||[])[0]||'—'}</td>
                    <td><span style={{color:'var(--warning)',fontSize:12}}>Not yet scanned</span></td>
                    <td><button className="btn btn-primary" style={{fontSize:10,padding:'3px 10px'}} onClick={()=>handleScanOne(img.ref)}>🔬 Scan</button></td>
                  </tr>
                ))}
                {unscanned.length===0&&<tr><td colSpan={5} style={{textAlign:'center',color:'var(--accent-3)',padding:40}}>✓ All images scanned</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {}
      {tab==='policies' && (
        <div className="card">
          <div className="card-header"><div className="card-title">Image Scan Policies</div></div>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Policy</th><th>Scope</th><th>Action on Fail</th><th>Last Triggered</th><th>Status</th></tr></thead>
              <tbody>
                {MOCK_POLICIES.map((p,i)=>(
                  <tr key={i} style={{cursor:'pointer'}}>
                    <td className="td-primary">{p.name}</td>
                    <td>{p.scope}</td>
                    <td><span style={{color:p.ac,fontSize:12}}>{p.action}</span></td>
                    <td style={{color:'var(--text-muted)'}}>{p.last}</td>
                    <td><StatusDot type={p.status} label={p.status==='active'?'Active':'Disabled'}/></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {}
      {tab==='history' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Recent Scan Jobs {scanning&&<span style={{color:'var(--accent)',marginLeft:8,fontSize:12}}>● Running…</span>}</div>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Started</th><th>Images</th><th>Duration</th><th>New CVEs</th><th>Fixed</th><th>Result</th></tr></thead>
              <tbody>
                {scanning&&(
                  <tr>
                    <td style={{color:'var(--accent)'}}>Now</td>
                    <td>{clusterImages.length}</td>
                    <td style={{color:'var(--text-muted)'}}>running…</td>
                    <td>—</td><td>—</td>
                    <td><StatusDot type="warn" label="In progress"/></td>
                  </tr>
                )}
                {MOCK_HISTORY.map((h,i)=>(
                  <tr key={i}>
                    <td style={{color:'var(--text-muted)'}}>{h.started}</td>
                    <td>{h.images}</td>
                    <td style={{color:'var(--text-muted)'}}>{h.dur}</td>
                    <td style={{color:h.newC.startsWith('+')?'var(--danger)':'var(--text-muted)'}}>{h.newC}</td>
                    <td style={{color:h.fixed.startsWith('-')?'var(--accent-3)':'var(--text-muted)'}}>{h.fixed}</td>
                    <td><StatusDot type={h.r} label={h.r==='active'?'Completed':'Failed'}/></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {progress.length>0&&(
            <div style={{padding:'0 18px 18px'}}>
              <div style={{fontSize:11,fontWeight:600,letterSpacing:'.08em',textTransform:'uppercase',color:'var(--text-muted)',margin:'12px 0 8px'}}>Live Log</div>
              <div style={{fontFamily:'JetBrains Mono,monospace',fontSize:11,lineHeight:1.8,background:'var(--bg-elevated)',borderRadius:8,padding:16,maxHeight:280,overflowY:'auto'}}>
                {progress.map((line,i)=>(
                  <div key={i} style={{color:line.startsWith('✓')?'var(--accent-3)':line.startsWith('✗')||line.startsWith('Error')?'var(--danger)':'var(--text-secondary)'}}>{line}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {}
      {selected && <ImageDetailPanel img={selected} onClose={()=>setSelected(null)}/>}
    </div>
  );
}
