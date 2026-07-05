import { useState, useMemo, useRef, useEffect } from 'react';
import { useScanner } from '../../context/ScannerContext';
import { SevBadge, StatusDot } from '../../components/ui';
import { useApp } from '../../context/AppContext';
import { epssLabel, sevColor, fmtDuration } from '../../data/scanner';

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

function ImageDetailPanel({ img, onClose }) {
  if (!img) return null;
  const cves = [...(img.cves||[])].sort((a,b)=>(b.cvssV3Score||0)-(a.cvssV3Score||0)).slice(0,8);
  return (
    <div style={{position:'fixed',top:52,right:0,bottom:0,width:480,overflow:'hidden',
      transition:'width .3s ease',background:'var(--bg-surface)',borderLeft:'1px solid var(--border)',zIndex:200}}>
      <div style={{height:'100%',overflowY:'auto',padding:20,scrollbarWidth:'thin',scrollbarColor:'var(--bg-elevated) transparent'}}>
        <div style={{display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:16}}>
          <div>
            <div style={{fontSize:15,fontWeight:600,color:'var(--text-primary)',fontFamily:'JetBrains Mono,monospace',marginBottom:3,wordBreak:'break-all'}}>{img.name}</div>
            <div style={{fontSize:12,color:'var(--text-muted)'}}>{img.tag} · {img.os||'—'}</div>
          </div>
          <button onClick={onClose} style={{background:'none',border:'1px solid var(--border)',borderRadius:6,padding:'5px 9px',color:'var(--text-muted)',cursor:'pointer',fontSize:14,flexShrink:0,marginLeft:12}}>✕</button>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:8,marginBottom:16}}>
          {[[img.summary?.critical||0,'Critical','rgba(239,68,68,.3)','var(--danger)'],
            [img.summary?.high||0,'High','rgba(245,158,11,.3)','var(--warning)'],
            [img.summary?.total||0,'Total CVEs','rgba(0,200,255,.2)','var(--accent)']].map(([n,l,bc,fc])=>(
            <div key={l} style={{background:'var(--bg-card)',border:`1px solid ${bc}`,borderRadius:8,padding:10,textAlign:'center'}}>
              <div style={{fontSize:22,fontWeight:300,color:fc,fontFamily:'JetBrains Mono,monospace'}}>{n}</div>
              <div style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:'.07em',marginTop:2}}>{l}</div>
            </div>
          ))}
        </div>

        <div style={{background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:10,padding:14,marginBottom:14}}>
          <div style={{fontSize:10,textTransform:'uppercase',letterSpacing:'.08em',color:'var(--text-muted)',marginBottom:10}}>Image Info</div>
          {[['OS',img.os||'—'],['Scanned',img.scannedAt?new Date(img.scannedAt).toLocaleString():'—'],
            ['Duration',fmtDuration(img.durationMs)],['Pods',(img.pods||[]).join(', ')||'—'],
            ['Namespaces',(img.namespaces||[]).join(', ')||'—']].map(([k,v])=>(
            <div key={k} className="dp-kv"><span>{k}</span><span>{v}</span></div>
          ))}
        </div>

        <div style={{fontSize:11,fontWeight:600,textTransform:'uppercase',letterSpacing:'.08em',color:'var(--text-muted)',marginBottom:8}}>Top CVEs in this image</div>
        <div style={{background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:10,overflow:'hidden'}}>
          <table className="data-table">
            <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Component</th><th>Fix</th></tr></thead>
            <tbody>
              {cves.map((c,i)=>{
                const epss=epssLabel(c.epssScore);
                return (
                  <tr key={i}>
                    <td className="td-primary mono" style={{fontSize:10}}>
                      <a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer"
                        style={{color:'var(--accent)',textDecoration:'none'}}>{c.id}</a>
                    </td>
                    <td><SevBadge sev={c.severity}/></td>
                    <td className="mono" style={{fontWeight:600,color:sevColor(c.severity)}}>{c.cvssV3Score?c.cvssV3Score.toFixed(1):'—'}</td>
                    <td className="mono" style={{fontSize:11,color:epss.color}}>{c.epssScore?epss.text:'—'}</td>
                    <td style={{fontSize:11,color:'var(--text-muted)'}}>{c.pkgName}</td>
                    <td style={{fontSize:11,color:c.hasFix?'var(--accent-3)':'var(--danger)'}}>{c.fixedIn||'None'}</td>
                  </tr>
                );
              })}
              {cves.length===0&&<tr><td colSpan={6} style={{textAlign:'center',color:'var(--accent-3)',padding:16}}>✓ No CVEs found</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}


export { ImageDetailPanel };
