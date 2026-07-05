import { useNavigate } from 'react-router-dom';
import { useBridge } from '../context/BridgeContext';
import { useScanner } from '../context/ScannerContext';
import { SevBadge } from '../components/ui';

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

  const critViol = violations.filter(v => v.severity === 'critical').length;
  const highViol = violations.filter(v => v.severity === 'high').length;
  const medViol  = violations.filter(v => v.severity === 'medium').length;
  const lowViol  = violations.filter(v => v.severity === 'low').length;
  const totalViol = violations.length;

  const wlCounts = {};
  violations.forEach(v => {
    const wl = workloadName(v.pod);
    if (!wl) return;
    const key = `${v.namespace || '—'}|${wl}`;
    wlCounts[key] = (wlCounts[key] || 0) + 1;
  });
  const topWorkloads = Object.entries(wlCounts).sort((a,b) => b[1]-a[1]).slice(0,5);
  const maxWl = topWorkloads[0]?.[1] || 1;

  const recent = [...violations].sort((a,b) => new Date(b.time||0)-new Date(a.time||0)).slice(0,5);

  return (
    <div className="page active" id="page-dashboard">
      <div className="page-header">
        <div>
          <div className="page-title">Dashboard</div>
          <div className="page-subtitle">Security overview across all clusters</div>
        </div>
        <div style={{display:'flex',gap:8,alignItems:'center'}}>
          <span className={`live-dot`}>{connected ? 'Live data' : 'Disconnected'}</span>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Critical Violations</div>
          <div className="stat-value danger">{critViol}</div>
          <div className="stat-delta up">{totalViol} total violations</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Violations</div>
          <div className="stat-value info">{totalViol}</div>
          <div className="stat-delta">{critViol} critical · {highViol} high</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Images Scanned</div>
          <div className="stat-value success">{results.length}</div>
          <div className="stat-delta">Grype · EPSS enriched</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Critical CVEs</div>
          <div className="stat-value danger">{summary?.critical ?? 0}</div>
          <div className="stat-delta">{summary?.total ?? 0} total CVEs</div>
        </div>
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-header">
            <div className="card-title">Violations by Severity</div>
            <div className="sev-legend">
              <span className="sev-legend-item"><span className="sev-legend-dot" style={{background:'var(--danger)'}}/>Critical</span>
              <span className="sev-legend-item"><span className="sev-legend-dot" style={{background:'var(--warning)'}}/>High</span>
              <span className="sev-legend-item"><span className="sev-legend-dot" style={{background:'#6366f1'}}/>Medium</span>
              <span className="sev-legend-item"><span className="sev-legend-dot" style={{background:'var(--accent-3)'}}/>Low</span>
            </div>
          </div>
          <div className="card-body">
            <div style={{display:'flex',alignItems:'center',gap:24}}>
              <div className="chart-ring" />
              <div style={{flex:1}}>
                {[
                  ['Critical', critViol, 'var(--danger)'],
                  ['High',     highViol, 'var(--warning)'],
                  ['Medium',   medViol,  '#6366f1'],
                  ['Low',      lowViol,  'var(--accent-3)'],
                ].map(([label,count,color],i) => (
                  <div className="compliance-item" key={label} style={i===3?{marginBottom:0}:{}}>
                    <div className="compliance-header">
                      <span className="compliance-name" style={{fontSize:12}}>{label}</span>
                      <span className="compliance-pct" style={{color}}>{count}</span>
                    </div>
                    <div className="compliance-bar">
                      <div className="compliance-fill" style={{width:`${totalViol?Math.round(count/totalViol*100):0}%`,background:color}} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Recent Violations</div>
            <button className="btn btn-outline" style={{padding:'5px 10px',fontSize:11}} onClick={() => navigate('/violations')}>View all</button>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Syscall</th><th>Severity</th><th>Pod</th></tr></thead>
              <tbody>
                {recent.length === 0
                  ? <tr><td colSpan={3} style={{textAlign:'center',color:'var(--text-muted)',padding:32}}>No violations yet</td></tr>
                  : recent.map((v,i) => (
                    <tr key={i}>
                      <td className="td-primary">{v.syscall || v.name || '—'}</td>
                      <td><SevBadge sev={v.severity?.toUpperCase()} /></td>
                      <td style={{color:'var(--accent)',fontSize:12}}>{v.pod || '—'}</td>
                    </tr>
                  ))
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {topWorkloads.length > 0 && (
        <div className="card">
          <div className="card-header"><div className="card-title">Top Workloads · Violations</div></div>
          <div className="card-body">
            {topWorkloads.map(([key, count]) => {
              const [ns, wl] = key.split('|');
              return (
                <div key={key} className="compliance-item">
                  <div className="compliance-header">
                    <span className="compliance-name" style={{fontFamily:'JetBrains Mono,monospace',fontSize:12}}>
                      {wl}<span style={{color:'var(--text-muted)'}}> · {ns}</span>
                    </span>
                    <span className="compliance-pct">{count}</span>
                  </div>
                  <div className="compliance-bar">
                    <div className="compliance-fill" style={{width:`${Math.round(count/maxWl*100)}%`,background:'var(--danger)'}} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
