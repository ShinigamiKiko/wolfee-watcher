import { useNavigate } from 'react-router-dom';
import { useBridge } from '../context/BridgeContext';
import { useScanner } from '../context/ScannerContext';
import { SevBadge } from '../components/ui';
import { PageHeader, Stat, Meter, EmptyRow } from '../components/kit';

function workloadName(pod) {
  if (!pod || pod === '—') return null;
  let m = pod.match(/^(.+?)-[a-z0-9]{6,10}-[a-z0-9]{5}$/);
  if (m) return m[1];
  m = pod.match(/^(.+?)-\d+$/);
  if (m) return m[1];
  m = pod.match(/^(.+?)-[a-z0-9]{5}$/);
  if (m) return m[1];
  return pod;
}

export function Dashboard() {
  const { violations, connected } = useBridge();
  const { summary, results } = useScanner();
  const navigate = useNavigate();

  // Overview severity metrics are image CVEs from Trivy, not runtime events.
  const critViol = summary?.critical ?? 0;
  const highViol = summary?.high ?? 0;
  const medViol  = summary?.medium ?? 0;
  const lowViol  = summary?.low ?? 0;
  const totalViol = summary?.total ?? (critViol + highViol + medViol + lowViol);
  const severityTotal = critViol + highViol + medViol + lowViol;
  const ringStops = (() => {
    if (!severityTotal) return 'var(--bg-elevated) 0 100%';
    let start = 0;
    return [
      [critViol, 'var(--danger)'],
      [highViol, 'var(--warning)'],
      [medViol, 'var(--info)'],
      [lowViol, 'var(--ok-text)'],
    ].map(([count, color]) => {
      const end = start + count / severityTotal * 100;
      const stop = `${color} ${start}% ${end}%`;
      start = end;
      return stop;
    }).join(', ');
  })();

  const wlCounts = {};
  violations.forEach(v => {
    const wl = workloadName(v.pod);
    if (!wl) return;
    const key = `${v.namespace || '—'}|${wl}`;
    wlCounts[key] = (wlCounts[key] || 0) + 1;
  });
  const topWorkloads = Object.entries(wlCounts).sort((a,b) => b[1]-a[1]).slice(0,5);
  const maxWl = topWorkloads[0]?.[1] || 1;

  const timeOf = v => (v.ts ? new Date(v.ts).getTime() : (v._detectedAt || 0));
  const recent = [...violations].sort((a, b) => timeOf(b) - timeOf(a)).slice(0, 5);

  const bars = [
    ['Critical', critViol, 'var(--danger)'],
    ['High',     highViol, 'var(--warning)'],
    ['Medium',   medViol,  'var(--info)'],
    ['Low',      lowViol,  'var(--ok-text)'],
  ];

  return (
    <div className="page active" id="page-dashboard">
      <PageHeader title="Dashboard" subtitle="Security overview across all clusters"
        actions={<span className="live-dot">{connected ? 'Live data' : 'Disconnected'}</span>} />

      <div className="stats-grid stats-grid--4">
        <Stat label="Critical CVEs" tone="danger" value={critViol} sub={`${totalViol} total CVEs`} />
        <Stat label="Image CVEs" tone="accent" value={totalViol} sub={`${critViol} critical · ${highViol} high`} />
        <Stat label="Images Scanned" tone="ok" value={results.length} sub="Trivy · EPSS enriched" />
        <Stat label="Runtime Violations" tone="warning" value={violations.length} sub="since the bridge connected" onClick={() => navigate('/violations')} />
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-header">
            <div className="card-title">Image CVEs by Severity</div>
            <div className="sev-legend">
              {bars.map(([label, , color]) => (
                <span key={label} className="sev-legend-item"><span className="sev-legend-dot" style={{ background: color }} />{label}</span>
              ))}
            </div>
          </div>
          <div className="card-body">
            <div className="row row--loose">
              <div className="chart-ring" style={{ background: `conic-gradient(${ringStops})` }} />
              <div className="grow stack">
                {bars.map(([label, count, color]) => (
                  <div key={label}>
                    <div className="row row--between t-sm mb-4">
                      <span className="t-primary">{label}</span>
                      <span className="mono">{count}</span>
                    </div>
                    <Meter value={count} max={totalViol || 1} color={color} showValue={false} label={`${label} CVEs`} />
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Recent Violations</div>
            <button type="button" className="btn btn-outline btn-sm" onClick={() => navigate('/violations')}>View all</button>
          </div>
          <div className="table-wrap">
            <table className="data-table data-table--static">
              <thead><tr><th>Syscall</th><th>Severity</th><th>Pod</th></tr></thead>
              <tbody>
                {recent.length === 0
                  ? <EmptyRow cols={3}>No violations yet</EmptyRow>
                  : recent.map((v, i) => (
                    <tr key={i}>
                      <td className="td-primary mono t-sm">{v.syscall || v.name || '—'}</td>
                      <td><SevBadge sev={String(v.sev || v.severity || '').toUpperCase()} /></td>
                      <td className="t-sm t-accent">{v.pod || '—'}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {topWorkloads.length > 0 && (
        <div className="card">
          <div className="card-header"><div className="card-title">Top Workloads · Violations</div></div>
          <div className="card-body stack">
            {topWorkloads.map(([key, count]) => {
              const [ns, wl] = key.split('|');
              return (
                <div key={key}>
                  <div className="row row--between t-sm mb-4">
                    <span className="mono t-primary">{wl}<span className="t-muted"> · {ns}</span></span>
                    <span className="mono">{count}</span>
                  </div>
                  <Meter value={count} max={maxWl} color="var(--danger)" showValue={false} label={`${wl} violations`} />
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
