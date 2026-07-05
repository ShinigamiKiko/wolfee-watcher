import { useState } from 'react';
import { STATUS_COLOR, fmt } from './auditConstants';

function BenchDetail({ run, onBack, onSelect }) {
  const [filter, setFilter] = useState('all');
  const [openCtrl, setOpenCtrl] = useState(null);
  const controls = Array.isArray(run.data?.controls) ? run.data.controls : [];
  const totals   = run.data?.totals || {};
  const total    = (totals.pass||0)+(totals.fail||0)+(totals.warn||0)+(totals.info||0);
  const score    = total ? Math.round((totals.pass||0)/total*100) : 0;
  const sc       = score>=80?'var(--accent-3)':score>=50?'var(--warning)':'var(--danger)';

  return (
    <div className="au-detail">
      <div className="au-detail__header">
        <button className="au-back" onClick={onBack}>← Back</button>
        <div className="au-detail__info">
          <span className="au-detail__name">{run.name}</span>
          <span className="au-detail__meta">kube-bench · {fmt(run.startedAt)}</span>
        </div>
        <div className="au-detail__score" style={{color:sc}}>{score}% pass</div>
      </div>
      <div className="au-summary-bar">
        <div className="au-score-block">
          <span className="au-score-n" style={{color:sc}}>{score}%</span>
          <span className="au-score-label">pass rate</span>
        </div>
        <div className="au-pills">
          {[['PASS',totals.pass||0],['FAIL',totals.fail||0],['WARN',totals.warn||0],['INFO',totals.info||0]].map(([s,n])=>(
            <button key={s} className={`au-pill${filter===s?' active':''}`}
              style={{'--pc':STATUS_COLOR[s]}} onClick={()=>setFilter(f=>f===s?'all':s)}>
              <b>{n}</b> {s}
            </button>
          ))}
          {filter!=='all' && <button className="au-pill-clear" onClick={()=>setFilter('all')}>✕</button>}
        </div>
      </div>
      <div className="au-scroll-area">
        {controls.map(ctrl => {
          const tests  = (ctrl.tests||[]).filter(t=>filter==='all'||t.status===filter);
          if (filter!=='all' && !tests.length) return null;
          const isOpen = openCtrl===ctrl.id;
          return (
            <div key={ctrl.id} className="au-ctrl">
              <div className="au-ctrl__hdr" onClick={()=>setOpenCtrl(isOpen?null:ctrl.id)}>
                <span className="au-ctrl__id">{ctrl.id}</span>
                {ctrl.node_type && <span className="au-ctrl__node">{ctrl.node_type}</span>}
                <span className="au-ctrl__text">{ctrl.text}</span>
                <div className="au-ctrl__counts">
                  {ctrl.fail>0 && <span style={{color:'var(--danger)'}}>✕{ctrl.fail}</span>}
                  {ctrl.warn>0 && <span style={{color:'var(--warning)'}}>⚠{ctrl.warn}</span>}
                  {ctrl.pass>0 && <span style={{color:'var(--accent-3)'}}>✓{ctrl.pass}</span>}
                </div>
                <span className="au-chev">{isOpen?'▾':'▸'}</span>
              </div>
              {isOpen && (
                <div className="au-ctrl__body">
                  {(ctrl.tests||[]).filter(t=>filter==='all'||t.status===filter).map(t=>(
                    <div key={t.number} className="au-test" onClick={()=>onSelect(t,'bench')}>
                      <span className="au-test__icon" style={{color:STATUS_COLOR[t.status]||'var(--text-muted)'}}>
                        {t.status==='PASS'?'✓':t.status==='FAIL'?'✕':t.status==='WARN'?'⚠':'ℹ'}
                      </span>
                      <span className="au-test__num">{t.number}</span>
                      <span className="au-test__desc">{t.desc}</span>
                      {t.remediation && <span title="Has remediation" style={{opacity:.6}}>🔧</span>}
                      <span className="au-row-arrow">›</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}


export { BenchDetail };
