import { useBridge } from '../../context/BridgeContext';
import { Sparkline } from '../../components/Sparkline';
import { Stat, Metrics, Tag, EmptyRow, cx } from '../../components/kit';

function fmtCPU(milli) {
  if (!milli) return '0m';
  if (milli < 1000) return `${milli}m`;
  return `${(milli / 1000).toFixed(2)} cores`;
}

function fmtMem(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ki`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} Mi`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} Gi`;
}

function fmtAge(sec) {
  if (!sec) return '—';
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d${h ? ` ${h}h` : ''}`;
  if (h) return `${h}h${m ? ` ${m}m` : ''}`;
  if (m) return `${m}m`;
  return `${sec}s`;
}

const CPU_COLOR = 'var(--accent)';
const MEM_COLOR = 'var(--violet-text)';
const BAD_COLOR = 'var(--danger)';
const OK_COLOR  = 'var(--ok-text)';

const toPoints = list => (list || []).map((p, i) => ({ ts: i, value: p.y }));
const lastY = list => (list || []).length ? (list[list.length - 1]?.y ?? 0) : 0;

function ComponentRow({ comp, series }) {
  const s   = series[comp.id] || { cpu: [], mem: [], rst: [] };
  const ok  = comp.pods_total > 0 && comp.pods_ready === comp.pods_total;
  const deg = comp.pods_total > 0 && comp.pods_ready < comp.pods_total && comp.pods_ready > 0;
  const restarts = comp.restarts_total || 0;

  return (
    <div className="comp-row">
      <div className="comp-row-name">
        <div className="row row--tight t-md t-medium t-primary">
          {comp.label}
          <span className={`dot ${ok ? 'dot--ok' : deg ? 'dot--warning' : 'dot--danger'}`} />
        </div>
        <div className="mono t-xs t-muted mt-4">
          {comp.pods_ready}/{comp.pods_total} pods · {comp.kind} · {restarts} restarts
        </div>
        {comp.error && <div className="t-xs t-danger mt-4 break">err: {comp.error}</div>}
      </div>
      <div>
        <div className="metric-label">CPU</div>
        <Sparkline points={toPoints(s.cpu)} color={CPU_COLOR} height={44} width={160} label={fmtCPU(comp.cpu_milli)} />
      </div>
      <div>
        <div className="metric-label">Memory</div>
        <Sparkline points={toPoints(s.mem)} color={MEM_COLOR} height={44} width={160} label={fmtMem(comp.mem_bytes)} />
      </div>
      <div>
        <div className="metric-label">Restarts</div>
        <Sparkline points={toPoints(s.rst)} color={restarts > 0 ? BAD_COLOR : OK_COLOR} height={44} width={160} label={String(restarts)} />
      </div>
    </div>
  );
}

export function EvilStats() {
  const { k8sMetrics, k8sSeries } = useBridge();

  const components = k8sMetrics?.components || [];
  const nodes      = k8sMetrics?.nodes      || [];
  const pvcs       = k8sMetrics?.pvcs       || [];
  const overall    = k8sSeries?.__overall   || { cpu: [], mem: [], rst: [] };
  const pods       = components.flatMap(c => (c.pods || []).map(p => ({ ...p, component: c.label, key: `${c.id}/${p.name}` })));

  const restartTotal = components.reduce((a, c) => a + (c.restarts_total || 0), 0);
  const cpuTotal     = components.reduce((a, c) => a + (c.cpu_milli      || 0), 0);
  const memTotal     = components.reduce((a, c) => a + (c.mem_bytes      || 0), 0);

  const noMetrics = components.length > 0 &&
    components.every(c => (c.cpu_milli || 0) === 0 && !(c.pods || []).some(p => p.has_metrics));

  return (
    <>
      <div className="stats-grid stats-grid--3">
        <Stat label="Restarts Total" value={restartTotal} tone={restartTotal === 0 ? 'ok' : 'danger'} sub="cumulative since pod start" />
        <Stat label="CPU Used" value={fmtCPU(cpuTotal)} tone="accent" sub="all platform pods" />
        <Stat label="Memory Used" value={fmtMem(memTotal)} sub="all platform pods" />
      </div>

      <div className="card">
        <div className="card-header"><div className="card-title">Cluster Trend <span className="card-sub">10 min rolling</span></div></div>
        <Metrics cols={3} items={[
          { label: 'CPU total',      children: <Sparkline fluid points={toPoints(overall.cpu)} color={CPU_COLOR} height={72} width={300} label={fmtCPU(lastY(overall.cpu))} /> },
          { label: 'Memory total',   children: <Sparkline fluid points={toPoints(overall.mem)} color={MEM_COLOR} height={72} width={300} label={fmtMem(lastY(overall.mem))} /> },
          { label: 'Restarts total', children: <Sparkline fluid points={toPoints(overall.rst)} color={BAD_COLOR} height={72} width={300} label={String(lastY(overall.rst) | 0)} /> },
        ]} />
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Per-Component Metrics</div>
          {noMetrics && <span className="t-xs t-warning">metrics-server not reporting — install it for CPU/memory</span>}
        </div>
        {components.length === 0 && <div className="empty-state empty-state--compact">Loading component metrics…</div>}
        {components.map(c => <ComponentRow key={c.id} comp={c} series={k8sSeries || {}} />)}
      </div>

      {nodes.length > 0 && (
        <div className="card">
          <div className="card-header"><div className="card-title">Node Resource Usage</div></div>
          <div className="table-wrap">
            <table className="data-table data-table--static">
              <thead><tr><th>Node</th><th className="num">CPU</th><th className="num">Memory</th><th>Conditions</th></tr></thead>
              <tbody>
                {nodes.map((n, i) => {
                  const conditions = [
                    !n.ready && ['NotReady', 'danger'],
                    n.memory_pressure && ['MemPressure', 'danger'],
                    n.disk_pressure && ['DiskPressure', 'danger'],
                    n.pid_pressure && ['PIDPressure', 'warning'],
                  ].filter(Boolean);
                  return (
                    <tr key={i}>
                      <td className="mono t-xs"><span className="row row--tight"><span className={`dot ${n.ready ? 'dot--ok' : 'dot--danger'}`} />{n.name}</span></td>
                      <td className="mono num">{fmtCPU(n.cpu_milli)}</td>
                      <td className="mono num">{fmtMem(n.mem_bytes)}</td>
                      <td>
                        {conditions.length === 0
                          ? <span className="t-xs t-ok">OK</span>
                          : <span className="row row--tight">{conditions.map(([label, tone]) => <Tag key={label} tone={tone} mono>{label}</Tag>)}</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {pvcs.length > 0 && (
        <div className="card">
          <div className="card-header"><div className="card-title">PersistentVolumeClaims</div></div>
          <div className="table-wrap">
            <table className="data-table data-table--static">
              <thead><tr><th>Name</th><th>StorageClass</th><th className="num">Capacity</th><th>Phase</th></tr></thead>
              <tbody>
                {pvcs.map(pvc => (
                  <tr key={pvc.name}>
                    <td className="mono t-xs">{pvc.name}</td>
                    <td className="mono t-xs">{pvc.storage_class || '—'}</td>
                    <td className="mono num">{fmtMem(pvc.capacity_bytes)}</td>
                    <td className={pvc.phase === 'Bound' ? 't-ok' : pvc.phase === 'Pending' ? 't-warning' : 't-danger'}>{pvc.phase}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header"><div className="card-title">Pods</div></div>
        <div className="table-wrap">
          <table className="data-table data-table--static">
            <thead><tr>
              <th>Pod</th><th>Component</th><th>Phase</th><th>OOM</th>
              <th className="num">Restarts</th><th className="num">CPU</th><th className="num">Memory</th><th>Node</th><th className="num">Age</th>
            </tr></thead>
            <tbody>
              {pods.map(p => (
                <tr key={p.key}>
                  <td className="mono t-xs">{p.name}</td>
                  <td>{p.component}</td>
                  <td className={p.ready ? 't-ok' : 't-danger'}>{p.phase}{p.ready ? '' : ' / not ready'}</td>
                  <td>{p.oom_killed && <Tag tone="danger" mono>OOM</Tag>}</td>
                  <td className={cx('mono num', (p.restarts || 0) > 0 && 't-danger')}>{p.restarts || 0}</td>
                  <td className="mono num">
                    {p.has_metrics ? fmtCPU(p.cpu_milli) : '—'}
                    {p.cpu_request_milli ? <span className="t-muted"> / {fmtCPU(p.cpu_request_milli)}</span> : null}
                  </td>
                  <td className="mono num">
                    {p.has_metrics ? fmtMem(p.mem_bytes) : '—'}
                    {p.mem_request_bytes ? <span className="t-muted"> / {fmtMem(p.mem_request_bytes)}</span> : null}
                  </td>
                  <td className="mono t-xs">{p.node || '—'}</td>
                  <td className="num">{fmtAge(p.age_sec)}</td>
                </tr>
              ))}
              {pods.length === 0 && <EmptyRow cols={9}>No pod data</EmptyRow>}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
