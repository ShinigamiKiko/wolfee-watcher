import { fmt } from './auditConstants';

function RunList({ runs, onOpen, onNew, tool, busy }) {
  return (
    <div className="au-run-list">
      {runs.length === 0 && (
        <div className="au-empty-state">
          <div className="au-empty-state__icon">🔍</div>
          <div className="au-empty-state__text">No audits yet</div>
          <div className="au-empty-state__sub">Click <b>▶ Run {tool}</b> to start</div>
        </div>
      )}
      {runs.map(run => {
        const vulnCount = run.data?.vulnerabilities?.length ?? 0;
        const ctrlFail  = run.data?.controls ? run.data.controls.reduce((s,c)=>s+(c.fail||0),0) : 0;
        const isBench   = tool === 'kube-bench';

        return (
          <div key={run.id} className={`au-run-card${run.status==='running'?' au-run-card--running':''}`}
            onClick={() => run.status !== 'running' && run.status !== 'error' && onOpen(run)}>
            <div className="au-run-card__left">
              <div className="au-run-card__icon">
                {run.status==='running' ? <div className="np-spinner"/> :
                 run.status==='error'   ? '✕' :
                 run.status==='done'    ? '✓' : '○'}
              </div>
            </div>
            <div className="au-run-card__body">
              <div className="au-run-card__name">{run.name}</div>
              <div className="au-run-card__meta">
                {tool} · {fmt(run.startedAt)}
              </div>
            </div>
            <div className="au-run-card__right">
              {run.status === 'running' && <span className="au-run-card__status au-run-card__status--running">● Running…</span>}
              {run.status === 'error'   && <span className="au-run-card__status au-run-card__status--error">✕ Failed</span>}
              {run.status === 'done' && isBench && ctrlFail > 0 && (
                <span className="au-run-card__badge au-run-card__badge--fail">{ctrlFail} failed</span>
              )}
              {run.status === 'done' && isBench && ctrlFail === 0 && (
                <span className="au-run-card__badge au-run-card__badge--pass">All pass</span>
              )}
              {run.status === 'done' && !isBench && vulnCount > 0 && (
                <span className="au-run-card__badge au-run-card__badge--vuln">{vulnCount} findings</span>
              )}
              {run.status === 'done' && !isBench && vulnCount === 0 && (
                <span className="au-run-card__badge au-run-card__badge--pass">No findings</span>
              )}
              {run.status === 'done' && <span className="au-run-card__arrow">›</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}


export { RunList };
