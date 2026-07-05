import { useBridge } from '../../context/BridgeContext';
import { Sparkline } from '../../components/Sparkline';

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

const GREEN  = 'var(--accent-3,#3ecf8e)';
const ORANGE = 'var(--warn,#f5a623)';
const RED    = 'var(--danger,#e25c5c)';
const BLUE   = '#5b8dee';
const PURPLE = '#9b59b6';

function ComponentRow({ comp, series }) {
  const s   = series[comp.id] || { cpu: [], mem: [], rst: [] };
  const ok  = comp.pods_total > 0 && comp.pods_ready === comp.pods_total;
  const deg = comp.pods_total > 0 && comp.pods_ready < comp.pods_total && comp.pods_ready > 0;

  return (
    <div style={{
      borderTop: '1px solid var(--border)',
      padding: '14px 18px',
      display: 'grid',
      gridTemplateColumns: '1.4fr 1fr 1fr 1fr',
      gap: 18,
      alignItems: 'center',
    }}>
      <div>
        <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
          {comp.label}
          <span className={`status-dot status-${ok ? 'active' : deg ? 'warning' : 'error'}`} style={{ fontSize: 9 }} />
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono,monospace' }}>
          {comp.pods_ready}/{comp.pods_total} pods · {comp.kind} · {comp.restarts_total || 0} restarts
        </div>
        {comp.error && (
          <div style={{ fontSize: 11, color: RED, marginTop: 4 }}>err: {comp.error}</div>
        )}
      </div>
      <div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '.06em' }}>CPU</div>
        <Sparkline points={s.cpu.map((p, i) => ({ ts: i, value: p.y }))} color={BLUE} height={44} width={160} label={fmtCPU(comp.cpu_milli)} />
      </div>
      <div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '.06em' }}>MEMORY</div>
        <Sparkline points={s.mem.map((p, i) => ({ ts: i, value: p.y }))} color={PURPLE} height={44} width={160} label={fmtMem(comp.mem_bytes)} />
      </div>
      <div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '.06em' }}>RESTARTS</div>
        <Sparkline
          points={s.rst.map((p, i) => ({ ts: i, value: p.y }))}
          color={(comp.restarts_total || 0) > 0 ? RED : GREEN}
          height={44} width={160}
          label={String(comp.restarts_total || 0)}
        />
      </div>
    </div>
  );
}

export function EvilStats() {
  const { k8sMetrics, k8sSeries } = useBridge();

  const components   = k8sMetrics?.components || [];
  const nodes        = k8sMetrics?.nodes       || [];
  const pvcs         = k8sMetrics?.pvcs        || [];
  const overall      = k8sSeries?.__overall    || { cpu: [], mem: [], rst: [] };

  const restartTotal = components.reduce((a, c) => a + (c.restarts_total || 0), 0);
  const cpuTotal     = components.reduce((a, c) => a + (c.cpu_milli      || 0), 0);
  const memTotal     = components.reduce((a, c) => a + (c.mem_bytes      || 0), 0);

  const noMetrics = components.length > 0 &&
    components.every(c => (c.cpu_milli || 0) === 0 && !(c.pods || []).some(p => p.has_metrics));

  return (
    <>
      {}
      <div className="health-grid">
        <div className="health-widget">
          <div className="health-label">Restarts Total</div>
          <div className="health-value" style={{ color: restartTotal === 0 ? GREEN : RED }}>
            {restartTotal}
          </div>
          <div className="health-sub">cumulative since pod start</div>
        </div>
        <div className="health-widget">
          <div className="health-label">CPU Used</div>
          <div className="health-value" style={{ color: BLUE }}>{fmtCPU(cpuTotal)}</div>
          <div className="health-sub">all platform pods</div>
        </div>
        <div className="health-widget">
          <div className="health-label">Memory Used</div>
          <div className="health-value" style={{ color: PURPLE }}>{fmtMem(memTotal)}</div>
          <div className="health-sub">all platform pods</div>
        </div>
      </div>

      {}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header"><div className="card-title">Cluster Trend (10 min rolling)</div></div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 0 }}>
          {[
            { label: 'CPU TOTAL',     points: overall.cpu, color: BLUE,   fmt: fmtCPU },
            { label: 'MEMORY TOTAL',  points: overall.mem, color: PURPLE, fmt: fmtMem },
            { label: 'RESTARTS TOTAL',points: overall.rst, color: RED,    fmt: v => String(v | 0) },
          ].map(({ label, points, color, fmt }, i) => (
            <div key={label} style={{ padding: '14px 20px', borderRight: i < 2 ? '1px solid var(--border)' : 'none', borderTop: '1px solid var(--border)' }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 6, letterSpacing: '.06em' }}>{label}</div>
              <Sparkline
                points={(points || []).map((p, idx) => ({ ts: idx, value: p.y }))}
                color={color} height={72} width={300} fill
                label={fmt((points || []).length ? (points[points.length - 1]?.y ?? 0) : 0)}
              />
            </div>
          ))}
        </div>
      </div>

      {}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <div className="card-title">Per-Component Metrics</div>
          {noMetrics && (
            <div style={{ fontSize: 11, color: ORANGE }}>metrics-server not reporting — install it for CPU/memory</div>
          )}
        </div>
        {components.length === 0 && (
          <div style={{ padding: '24px 20px', color: 'var(--text-muted)', fontSize: 12 }}>Loading component metrics…</div>
        )}
        {components.map(c => (
          <ComponentRow key={c.id} comp={c} series={k8sSeries || {}} />
        ))}
      </div>

      {}
      {nodes.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header"><div className="card-title">Node Resource Usage</div></div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Node', 'CPU', 'Memory', 'Conditions'].map(h => (
                  <th key={h} style={{ padding: '6px 16px', textAlign: 'left', fontSize: 11, textTransform: 'uppercase', letterSpacing: '.05em', color: 'var(--text-muted)', fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {nodes.map((n, i) => {
                const conditions = [];
                if (!n.ready) conditions.push({ label: 'NotReady', color: RED });
                if (n.memory_pressure) conditions.push({ label: 'MemPressure', color: RED });
                if (n.disk_pressure) conditions.push({ label: 'DiskPressure', color: RED });
                if (n.pid_pressure) conditions.push({ label: 'PIDPressure', color: ORANGE });
                return (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 16px', fontFamily: 'JetBrains Mono,monospace', fontSize: 11 }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <span className={`status-dot status-${n.ready ? 'active' : 'error'}`} style={{ fontSize: 8 }} />
                        {n.name}
                      </span>
                    </td>
                    <td style={{ padding: '8px 16px', fontFamily: 'JetBrains Mono,monospace' }}>{fmtCPU(n.cpu_milli)}</td>
                    <td style={{ padding: '8px 16px', fontFamily: 'JetBrains Mono,monospace' }}>{fmtMem(n.mem_bytes)}</td>
                    <td style={{ padding: '8px 16px' }}>
                      {conditions.length === 0
                        ? <span style={{ color: GREEN, fontSize: 11 }}>OK</span>
                        : conditions.map(c => (
                            <span key={c.label} style={{ marginRight: 6, fontSize: 10, padding: '2px 6px', borderRadius: 4, background: c.color + '22', color: c.color, fontFamily: 'JetBrains Mono,monospace' }}>{c.label}</span>
                          ))
                      }
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {}
      {pvcs.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header"><div className="card-title">PersistentVolumeClaims</div></div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)', color: 'var(--text-muted)', fontSize: 11 }}>
                {['Name', 'StorageClass', 'Capacity', 'Phase'].map(h => (
                  <th key={h} style={{ padding: '10px 14px', textAlign: 'left' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pvcs.map(pvc => (
                <tr key={pvc.name} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '8px 14px', fontFamily: 'JetBrains Mono,monospace', fontSize: 11 }}>{pvc.name}</td>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono,monospace' }}>{pvc.storage_class || '—'}</td>
                  <td style={{ padding: '8px 14px', fontFamily: 'JetBrains Mono,monospace' }}>{fmtMem(pvc.capacity_bytes)}</td>
                  <td style={{ padding: '8px 14px' }}>
                    <span style={{ color: pvc.phase === 'Bound' ? GREEN : pvc.phase === 'Pending' ? ORANGE : RED }}>{pvc.phase}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {}
      <div className="card">
        <div className="card-header"><div className="card-title">Pods</div></div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)', color: 'var(--text-muted)', fontSize: 11, textAlign: 'left' }}>
                {['Pod', 'Component', 'Phase', 'OOM', 'Restarts', 'CPU', 'Memory', 'Node', 'Age'].map(h => (
                  <th key={h} style={{ padding: '10px 14px', textAlign: h === 'Restarts' || h === 'CPU' || h === 'Memory' || h === 'Age' ? 'right' : 'left' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {components.flatMap(c =>
                (c.pods || []).map(p => (
                  <tr key={`${c.id}/${p.name}`} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 14px', fontFamily: 'JetBrains Mono,monospace', fontSize: 11 }}>{p.name}</td>
                    <td style={{ padding: '8px 14px', color: 'var(--text-secondary)' }}>{c.label}</td>
                    <td style={{ padding: '8px 14px' }}>
                      <span style={{ color: p.ready ? GREEN : RED }}>{p.phase}{p.ready ? '' : ' / not ready'}</span>
                    </td>
                    <td style={{ padding: '8px 14px' }}>
                      {p.oom_killed && (
                        <span style={{ fontSize: 10, padding: '2px 5px', borderRadius: 4, background: RED + '22', color: RED, fontFamily: 'JetBrains Mono,monospace', fontWeight: 600 }}>OOM</span>
                      )}
                    </td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', fontFamily: 'JetBrains Mono,monospace', color: (p.restarts || 0) > 0 ? RED : 'var(--text-secondary)' }}>
                      {p.restarts || 0}
                    </td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', fontFamily: 'JetBrains Mono,monospace' }}>
                      {p.has_metrics ? fmtCPU(p.cpu_milli) : '—'}
                      {p.cpu_request_milli ? <span style={{ color: 'var(--text-muted)' }}> / {fmtCPU(p.cpu_request_milli)}</span> : null}
                    </td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', fontFamily: 'JetBrains Mono,monospace' }}>
                      {p.has_metrics ? fmtMem(p.mem_bytes) : '—'}
                      {p.mem_request_bytes ? <span style={{ color: 'var(--text-muted)' }}> / {fmtMem(p.mem_request_bytes)}</span> : null}
                    </td>
                    <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono,monospace' }}>{p.node || '—'}</td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', color: 'var(--text-secondary)' }}>{fmtAge(p.age_sec)}</td>
                  </tr>
                ))
              )}
              {components.flatMap(c => c.pods || []).length === 0 && (
                <tr><td colSpan={9} style={{ padding: '20px 14px', color: 'var(--text-muted)', textAlign: 'center' }}>No pod data</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
