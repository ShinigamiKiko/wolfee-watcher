import { useState, useEffect, useRef, useCallback } from 'react';
import '../../styles/audit.scss';
import { AuditBoundary, STATUS_COLOR, fmt } from './auditConstants';
import { RunDialog } from './RunDialog';
import { RunList } from './RunList';
import { BenchDetail } from './BenchDetail';
import { HunterDetail } from './HunterDetail';
import { DetailModal, F } from './DetailModal';

export function Audit() {
  return <AuditBoundary><AuditInner/></AuditBoundary>;
}

function AuditInner() {
  const [tab,    setTab]    = useState('hunter');
  const [dialog, setDialog] = useState(null);
  const [detail, setDetail] = useState(null);
  const [modal,  setModal]  = useState(null);
  const [runs,   setRuns]   = useState({ bench: [], hunter: [] });
  const [busy,   setBusy]   = useState({ bench: false, hunter: false });
  const pollRef = useRef(null);
  const activeRunId = useRef({ bench: null, hunter: null });

  const pollStatus = useCallback(async () => {
    try {
      const r = await fetch('/audit/api/audit/current', { credentials: 'same-origin' });
      if (!r.ok) return;
      const d = await r.json();

      ['bench','hunter'].forEach(tool => {
        const td = tool==='bench' ? d.bench : d.hunter;
        if (!td || td.status==='idle') return;
        const rid = activeRunId.current[tool];
        if (!rid) return;

        setRuns(prev => {
          const list = [...prev[tool]];
          const idx  = list.findIndex(r => r.id===rid);
          if (idx < 0) return prev;
          list[idx] = { ...list[idx], status: td.status, data: td.parsed, error: td.error };
          return { ...prev, [tool]: list };
        });

        setDetail(prev => prev?.id===rid ? {...prev, status:td.status, data:td.parsed} : prev);

        if (td.status !== 'running') {
          setBusy(prev => ({...prev, [tool]: false}));
        }
      });

      if (d.bench?.status !== 'running' && d.hunter?.status !== 'running') {
        clearInterval(pollRef.current);
      }
    } catch {}
  }, []);

  useEffect(() => {
    fetch('/audit/api/audit/current', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (!d) return;
        ['bench', 'hunter'].forEach(tool => {
          const td = tool === 'bench' ? d.bench : d.hunter;
          if (!td || td.status === 'idle') return;
          const id  = `${tool}-restored`;
          const run = {
            id, name: `Last ${tool === 'bench' ? 'kube-bench' : 'kube-hunter'} run`,
            startedAt: td.started_at ? new Date(td.started_at) : new Date(),
            status: td.status, data: td.parsed, error: td.error,
          };
          setRuns(prev => ({ ...prev, [tool]: [run] }));
          if (td.status === 'running') {
            activeRunId.current[tool] = id;
            setBusy(prev => ({ ...prev, [tool]: true }));
          }
        });
        if (d.bench?.status === 'running' || d.hunter?.status === 'running') {
          pollRef.current = setInterval(pollStatus, 3000);
        }
      })
      .catch(() => {});
  }, [pollStatus]);

  useEffect(() => () => clearInterval(pollRef.current), []);

  const handleConfirm = async (tool, name) => {
    setDialog(null);
    const id  = `${tool}-${Date.now()}`;
    const run = { id, name, startedAt: new Date(), status: 'running', data: null };
    activeRunId.current[tool] = id;

    setRuns(prev => ({ ...prev, [tool]: [run, ...prev[tool]] }));
    setBusy(prev => ({...prev, [tool]: true}));

    const endpoint = tool==='bench' ? '/audit/api/audit/run/bench' : '/audit/api/audit/run/hunter';
    try {
      await fetch(endpoint, { method: 'POST', credentials: 'same-origin' });
      clearInterval(pollRef.current);
      pollRef.current = setInterval(pollStatus, 3000);
    } catch {
      setBusy(prev => ({...prev, [tool]: false}));
      setRuns(prev => {
        const list = [...prev[tool]];
        const idx  = list.findIndex(r => r.id===id);
        if (idx>=0) list[idx] = {...list[idx], status:'error', error:'Request failed'};
        return {...prev, [tool]: list};
      });
    }
  };

  const toolRuns = runs[tab];
  const isBusy   = busy[tab];
  const toolName = tab==='bench' ? 'kube-bench' : 'kube-hunter';

  return (
    <div className="au-page">
      {}
      <div className="au-header">
        <div className="au-header__left">
          {detail ? (
            <button className="au-back-btn" onClick={()=>setDetail(null)}>← Audits</button>
          ) : (
            <><span className="au-title">Audit</span><span className="au-sep">·</span><span className="au-sub">kube-bench · kube-hunter</span></>
          )}
        </div>
        {!detail && (
          <button className="au-run-btn" onClick={()=>setDialog(tab)} disabled={isBusy}>
            {isBusy ? '⏳ Running…' : `▶ Run ${toolName}`}
          </button>
        )}
      </div>

      {}
      {!detail && (
        <div className="au-tabs">
          {[['bench','kube-bench'],['hunter','kube-hunter']].map(([id,label])=>(
            <button key={id} className={`au-tab${tab===id?' active':''}`} onClick={()=>{ setTab(id); setDetail(null); }}>
              {label}
              {busy[id] && <span className="au-tab__running">● running</span>}
              {runs[id].length>0 && !busy[id] && (
                <span className="au-tab__count">{runs[id].length}</span>
              )}
            </button>
          ))}
        </div>
      )}

      {}
      <div className="au-body">
        {!detail && (
          <RunList
            runs={toolRuns}
            tool={toolName}
            busy={isBusy}
            onNew={()=>setDialog(tab)}
            onOpen={run => setDetail(run)}
          />
        )}
        {detail && tab==='bench' && (
          <BenchDetail run={detail} onBack={()=>setDetail(null)} onSelect={(item,type)=>setModal({item,type})}/>
        )}
        {detail && tab==='hunter' && (
          <HunterDetail run={detail} onBack={()=>setDetail(null)} onSelect={(item,type)=>setModal({item,type})}/>
        )}
      </div>

      {dialog && <RunDialog tool={dialog==='bench'?'kube-bench':'kube-hunter'} onConfirm={n=>handleConfirm(dialog,n)} onCancel={()=>setDialog(null)}/>}
      {modal  && <DetailModal item={modal.item} type={modal.type} onClose={()=>setModal(null)}/>}
    </div>
  );
}
