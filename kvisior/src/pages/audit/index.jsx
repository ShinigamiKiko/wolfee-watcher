import { apiFetch } from '../../data/cluster';
import { useState, useEffect, useRef, useCallback } from 'react';
import '../../styles/audit.scss';
import { AuditBoundary } from './auditConstants';
import { RunDialog } from './RunDialog';
import { RunList } from './RunList';
import { BenchDetail } from './BenchDetail';
import { HunterDetail } from './HunterDetail';
import { DetailModal } from './DetailModal';
import { Icon } from '../../components/Icon';
import { useReportDownload } from '../../reports/useReportDownload';

const TOOLS = ['bench', 'hunter'];
const HISTORY_LIMIT = 50;
const SAME_RUN_MS = 2000;

export function Audit() {
  return <AuditBoundary><AuditInner/></AuditBoundary>;
}

function toDate(v) {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d.getTime()) || d.getFullYear() < 2000 ? null : d;
}

function fromHistory(tool, rows) {
  const n = rows.length;
  return rows.map((row, i) => ({
    id: row.runId || `${tool}-${row.startedAt}`,
    name: i === 0 ? `Run #${n - i} · latest` : `Run #${n - i}`,
    startedAt: toDate(row.startedAt),
    doneAt: toDate(row.doneAt),
    status: row.status,
    data: row.parsed,
    error: row.error,
  }));
}

async function fetchHistory(tool) {
  const r = await apiFetch(`/audit/runs?tool=${tool}&limit=${HISTORY_LIMIT}`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`runs: HTTP ${r.status}`);
  const d = await r.json();
  return Array.isArray(d.runs) ? d.runs : [];
}

async function fetchCurrent() {
  const r = await apiFetch('/audit/api/audit/current', { credentials: 'same-origin' });
  return r.ok ? r.json() : null;
}

function sameRun(a, b) {
  return a?.startedAt && b?.startedAt && Math.abs(a.startedAt - b.startedAt) < SAME_RUN_MS;
}

function AuditInner() {
  const [tab,     setTab]     = useState('hunter');
  const [dialog,  setDialog]  = useState(null);
  const [detail,  setDetail]  = useState(null);
  const [modal,   setModal]   = useState(null);
  const [history, setHistory] = useState({ bench: [], hunter: [] });
  const [current, setCurrent] = useState({ bench: null, hunter: null });
  const [names,   setNames]   = useState({ bench: '', hunter: '' });
  const [historyOk, setHistoryOk] = useState(true);
  const pollRef = useRef(null);
  const { busy: downloading, download } = useReportDownload();

  const loadHistory = useCallback(async () => {
    try {
      const [bench, hunter] = await Promise.all(TOOLS.map(fetchHistory));
      setHistory({ bench: fromHistory('bench', bench), hunter: fromHistory('hunter', hunter) });
      setHistoryOk(true);
    } catch {
      setHistoryOk(false);
    }
  }, []);

  const loadCurrent = useCallback(async () => {
    let d = null;
    try { d = await fetchCurrent(); } catch {}
    const next = { bench: null, hunter: null };
    TOOLS.forEach(tool => {
      const td = d?.[tool];
      if (!td || !td.status || td.status === 'idle') return;
      next[tool] = {
        id: `${tool}-current`,
        startedAt: toDate(td.started_at) || new Date(),
        doneAt: toDate(td.done_at),
        status: td.status,
        data: td.parsed,
        error: td.error,
      };
    });
    setCurrent(next);
    return next;
  }, []);

  const stopPolling = () => { clearInterval(pollRef.current); pollRef.current = null; };

  const poll = useCallback(async () => {
    const next = await loadCurrent();
    const running = TOOLS.some(t => next[t]?.status === 'running');
    if (!running) {
      stopPolling();
      await loadHistory();
      setTimeout(loadHistory, 3000);
    }
  }, [loadCurrent, loadHistory]);

  const startPolling = useCallback(() => {
    stopPolling();
    pollRef.current = setInterval(poll, 3000);
  }, [poll]);

  useEffect(() => {
    loadHistory();
    loadCurrent().then(next => {
      if (TOOLS.some(t => next[t]?.status === 'running')) startPolling();
    });
    return stopPolling;
  }, [loadHistory, loadCurrent, startPolling]);

  const runsFor = tool => {
    const list = history[tool];
    const cur = current[tool];
    if (!cur) return list;
    if (cur.status === 'running') {
      return [{ ...cur, name: names[tool] || 'Run in progress' }, ...list];
    }
    if (list.some(r => sameRun(r, cur))) return list;
    const label = list.length ? 'Last run (not yet in history)' : 'Last run';
    return [{ ...cur, name: label }, ...list];
  };

  const handleConfirm = async (tool, name) => {
    setDialog(null);
    setNames(prev => ({ ...prev, [tool]: name }));
    setCurrent(prev => ({ ...prev, [tool]: { id: `${tool}-current`, startedAt: new Date(), status: 'running', data: null } }));
    const endpoint = tool === 'bench' ? '/audit/api/audit/run/bench' : '/audit/api/audit/run/hunter';
    try {
      const r = await apiFetch(endpoint, { method: 'POST', credentials: 'same-origin' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      startPolling();
    } catch (e) {
      setCurrent(prev => ({ ...prev, [tool]: { id: `${tool}-current`, startedAt: new Date(), status: 'error', error: e?.message || 'Request failed' } }));
    }
  };

  const downloadRun = run => download(run.id, async ctx => {
    const reports = await import('../../reports/auditReport');
    return tab === 'bench' ? reports.benchReport({ run, ...ctx }) : reports.hunterReport({ run, ...ctx });
  });

  const toolRuns = runsFor(tab);
  const isBusy   = current[tab]?.status === 'running';
  const toolName = tab === 'bench' ? 'kube-bench' : 'kube-hunter';

  return (
    <div className="au-page">
      <div className="au-header">
        <div className="au-header__left">
          {detail ? (
            <button className="au-back-btn" onClick={() => setDetail(null)}><Icon name="arrow-left" /> Audits</button>
          ) : (
            <span className="au-sub">
              kube-bench · kube-hunter
              {historyOk
                ? <span className="au-sub__note"> · runs are kept for 14 days</span>
                : <span className="au-sub__note t-warning"> · history unavailable, showing the last run only</span>}
            </span>
          )}
        </div>
        {!detail && (
          <button className="au-run-btn" onClick={() => setDialog(tab)} disabled={isBusy}>
            {isBusy ? <><Icon name="loader" /> Running…</> : <><Icon name="play" /> Run {toolName}</>}
          </button>
        )}
      </div>

      {!detail && (
        <div className="au-tabs">
          {[['bench', 'kube-bench'], ['hunter', 'kube-hunter']].map(([id, label]) => {
            const running = current[id]?.status === 'running';
            const count = runsFor(id).length;
            return (
              <button key={id} className={`au-tab${tab === id ? ' active' : ''}`} onClick={() => { setTab(id); setDetail(null); }}>
                {label}
                {running && <span className="au-tab__running">● running</span>}
                {count > 0 && !running && <span className="au-tab__count">{count}</span>}
              </button>
            );
          })}
        </div>
      )}

      <div className="au-body">
        {!detail && (
          <RunList
            runs={toolRuns}
            tool={toolName}
            busy={isBusy}
            onNew={() => setDialog(tab)}
            onOpen={run => setDetail(run)}
            onDownload={downloadRun}
            downloading={downloading}
          />
        )}
        {detail && tab === 'bench' && (
          <BenchDetail run={detail} onBack={() => setDetail(null)} onSelect={(item, type) => setModal({ item, type })}
            onDownload={downloadRun} downloading={downloading}/>
        )}
        {detail && tab === 'hunter' && (
          <HunterDetail run={detail} onBack={() => setDetail(null)} onSelect={(item, type) => setModal({ item, type })}
            onDownload={downloadRun} downloading={downloading}/>
        )}
      </div>

      {dialog && <RunDialog tool={dialog === 'bench' ? 'kube-bench' : 'kube-hunter'} onConfirm={n => handleConfirm(dialog, n)} onCancel={() => setDialog(null)}/>}
      {modal  && <DetailModal item={modal.item} type={modal.type} onClose={() => setModal(null)}/>}
    </div>
  );
}
