import { fmt } from './auditConstants';
import { Icon } from '../../components/Icon';
import { Pager } from '../../components/Pager';
import { usePaged } from '../../hooks/usePaged';

function duration(run) {
  if (!run.startedAt || !run.doneAt) return '';
  const sec = Math.round((run.doneAt - run.startedAt) / 1000);
  if (sec <= 0) return '';
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function RunList({ runs, onOpen, onNew, tool, busy, onDownload, downloading }) {
  const { pageItems, pager } = usePaged(runs, 'audit.runs', [tool]);
  return (
    <>
    <div className="au-run-list dw dw-fill" tabIndex={0} role="region" aria-label="Audit runs">
      {runs.length === 0 && (
        <div className="au-empty-state">
          <div className="au-empty-state__icon"><Icon name="search" /></div>
          <div className="au-empty-state__text">No audits yet</div>
          <div className="au-empty-state__sub">Click <b>Run {tool}</b> to start</div>
        </div>
      )}
      {pageItems.map(run => {
        const vulnCount = run.data?.vulnerabilities?.length ?? 0;
        const ctrlFail  = run.data?.controls ? run.data.controls.reduce((s,c)=>s+(c.fail||0),0) : 0;
        const isBench   = tool === 'kube-bench';

        return (
          <div key={run.id} className={`au-run-card${run.status==='running'?' au-run-card--running':''}`}
            onClick={() => run.status !== 'running' && run.status !== 'error' && onOpen(run)}>
            <div className="au-run-card__left">
              <div className="au-run-card__icon">
                {run.status==='running' ? <div className="np-spinner"/> :
                 run.status==='error'   ? <Icon name="x" /> :
                 run.status==='done'    ? <Icon name="check" /> : <Icon name="circle-dot" />}
              </div>
            </div>
            <div className="au-run-card__body">
              <div className="au-run-card__name">{run.name}</div>
              <div className="au-run-card__meta">
                {tool} · {fmt(run.startedAt)}{duration(run) && <> · {duration(run)}</>}
              </div>
            </div>
            <div className="au-run-card__right">
              {run.status === 'running' && <span className="au-run-card__status au-run-card__status--running">● Running…</span>}
              {run.status === 'error'   && <span className="au-run-card__status au-run-card__status--error" title={run.error || ''}><Icon name="x" /> Failed</span>}
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
              {run.status === 'done' && onDownload && (
                <button type="button" className="btn-icon btn-icon--sm au-run-card__download"
                  title="Download PDF report" aria-label={`Download PDF report for ${run.name}`}
                  disabled={!!downloading}
                  onClick={e => { e.stopPropagation(); onDownload(run); }}>
                  <Icon name={downloading === run.id ? 'loader' : 'download'} />
                </button>
              )}
              {run.status === 'done' && <span className="au-run-card__arrow">›</span>}
            </div>
          </div>
        );
      })}
    </div>
    <div className="dw-foot"><Pager {...pager} noun="runs" /></div>
    </>
  );
}


export { RunList };
