import { useState } from 'react';
import { fmt, SEV, sev, SEV_ORDER } from './auditConstants';

function HunterDetail({ run, onBack, onSelect }) {
  const [sevFilter, setSevFilter] = useState('all');
  const nodes   = Array.isArray(run.data?.nodes)           ? run.data.nodes           : [];
  const services= Array.isArray(run.data?.services)        ? run.data.services        : [];
  const vulns   = Array.isArray(run.data?.vulnerabilities) ? run.data.vulnerabilities : [];
  const totals  = run.data?.totals || {};

  const sorted  = [...vulns].sort((a,b)=>(SEV_ORDER[a?.severity]??4)-(SEV_ORDER[b?.severity]??4));
  const visible = sevFilter==='all' ? sorted : sorted.filter(v=>v?.severity===sevFilter);

  return (
    <div className="au-detail">
      <div className="au-detail__header">
        <button className="au-back" onClick={onBack}>← Back</button>
        <div className="au-detail__info">
          <span className="au-detail__name">{run.name}</span>
          <span className="au-detail__meta">kube-hunter · {fmt(run.startedAt)}</span>
        </div>
        <div className="au-detail__score" style={{color: totals.critical>0?sev('critical').color:totals.high>0?sev('high').color:'var(--accent-3)'}}>
          {vulns.length} findings
        </div>
      </div>

      {(nodes.length>0||services.length>0) && (
        <div className="au-discovery">
          {nodes.length>0 && (
            <div className="au-disc__group">
              <div className="au-disc__title">Nodes discovered</div>
              {nodes.map((n,i)=>(
                <div key={i} className="au-disc__row">
                  <span className="au-disc__type">{n.type||'node'}</span>
                  <span className="au-disc__loc">{n.location}</span>
                </div>
              ))}
            </div>
          )}
          {services.length>0 && (
            <div className="au-disc__group">
              <div className="au-disc__title">Services discovered</div>
              {services.map((s,i)=>(
                <div key={i} className="au-disc__row">
                  <span className="au-disc__type">{s.service}</span>
                  <span className="au-disc__loc">{s.location}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="au-summary-bar">
        <div className="au-score-block">
          <span className="au-score-n" style={{color: totals.critical>0?sev('critical').color:'var(--accent-3)'}}>{vulns.length}</span>
          <span className="au-score-label">findings</span>
        </div>
        <div className="au-pills">
          {[['critical',totals.critical||0],['high',totals.high||0],['medium',totals.medium||0],['low',totals.low||0]]
            .filter(([,n])=>n>0)
            .map(([s,n])=>(
              <button key={s} className={`au-pill${sevFilter===s?' active':''}`}
                style={{'--pc':sev(s).color}} onClick={()=>setSevFilter(f=>f===s?'all':s)}>
                <b>{n}</b> {s}
              </button>
            ))}
          {sevFilter!=='all' && <button className="au-pill-clear" onClick={()=>setSevFilter('all')}>✕</button>}
        </div>
      </div>

      {vulns.length===0 && <div className="au-empty">✓ No vulnerabilities found</div>}

      <div className="au-scroll-area">
        {visible.map((v,i)=>{
          const st = sev(v?.severity);
          return (
            <div key={(v?.id||'')+i} className="au-vuln-card"
              style={{borderLeftColor:st.border}}
              onClick={()=>onSelect(v,'hunter')}>
              <div className="au-vuln-card__top">
                <span className="au-vuln-card__sev" style={{color:st.color,background:st.bg,border:`1px solid ${st.border}`}}>
                  {(v?.severity||'N/A').toUpperCase()}
                </span>
                <span className="au-vuln-card__name">{v?.vulnerability}</span>
                <span className="au-row-arrow">›</span>
              </div>
              {v?.category && <div className="au-vuln-card__cat">{v.category}</div>}
              {v?.location  && <div className="au-vuln-card__loc">📍 {v.location}</div>}
              {v?.avd_remediation && (
                <div className="au-vuln-card__remedy">
                  <b>🔧 Fix:</b> {v.avd_remediation.slice(0,180)}{v.avd_remediation.length>180?'…':''}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}


export { HunterDetail };
