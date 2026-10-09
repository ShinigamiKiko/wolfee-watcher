import { useNavigate } from 'react-router-dom';
import { useBridge } from '../context/BridgeContext';
import { useScanner } from '../context/ScannerContext';
import { useSensor } from '../context/SensorContext';
import { SevBadge } from '../components/ui';
import { Icon } from '../components/Icon';
import { PageHeader, Stat, Meter, Pane, Metrics, Ring, SevBar, SectionLabel, cx } from '../components/kit';
import { originOf } from '../utils/origin';

const SEVS = [
  ['CRITICAL', 'critical', 'var(--danger)'],
  ['HIGH', 'high', 'var(--orange)'],
  ['MEDIUM', 'medium', 'var(--warning)'],
  ['LOW', 'low', '#64748b'],
];

const num = n => Number(n || 0).toLocaleString();

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

const nodeIsReady = n => (n.status?.conditions || []).some(c => c.type === 'Ready' && c.status === 'True');

function timeLabel(v) {
  const t = v.ts ? new Date(v.ts).getTime() : (v._detectedAt || 0);
  if (!t) return '—';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(t).toLocaleDateString();
}

function HealthTile({ label, icon, value, ready, total, hint }) {
  const pct = total > 0 ? Math.round((ready / total) * 100) : null;
  return (
    <div className="stat-card">
      <div className="stat-top">
        <div className="stat-label">{label}</div>
        <span className="stat-icon"><Icon name={icon} /></span>
      </div>
      <div className="kpi-ring">
        {pct != null && <Ring pct={pct} tone={pct === 100 ? 'ok' : pct >= 50 ? 'warning' : 'danger'} />}
        <div className="stat-value">{value}</div>
      </div>
      <div className="stat-delta">{hint}</div>
    </div>
  );
}

export function Dashboard() {
  const { violations, auditViolations, anomalyEvents, connected, stats, components, kafkaStats } = useBridge();
  const { summary, results, agentOnline } = useScanner();
  const { nodes, pods, namespaces, sensorOnline, lastUpdated } = useSensor();
  const navigate = useNavigate();

  const cveCounts = SEVS.map(([, key, color]) => [key, summary?.[key] ?? 0, color]);
  const cveTotal = summary?.total ?? cveCounts.reduce((a, [, n]) => a + n, 0);

  const runtimeCounts = SEVS.map(([up, key, color]) => [key, violations.filter(v => String(v.sev || v.severity || '').toUpperCase() === up).length, color]);
  const critRuntime = runtimeCounts[0][1];

  const timeOf = v => (v.ts ? new Date(v.ts).getTime() : (v._detectedAt || 0));
  const recent = [...violations].sort((a, b) => timeOf(b) - timeOf(a)).slice(0, 5);

  const wlCounts = {};
  violations.forEach(v => {
    const wl = workloadName(v.pod);
    if (!wl) return;
    const key = `${v.namespace || '—'}|${wl}`;
    wlCounts[key] = (wlCounts[key] || 0) + 1;
  });
  const topWorkloads = Object.entries(wlCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const maxWl = topWorkloads[0]?.[1] || 1;

  const failedScans = (results || []).filter(r => r.status === 'error' || r.error).length;
  const scannedImages = (results || []).length - failedScans;

  const images = [...(results || [])]
    .filter(r => (r.summary?.total || 0) > 0)
    .sort((a, b) => (b.summary?.critical || 0) - (a.summary?.critical || 0) || (b.summary?.total || 0) - (a.summary?.total || 0))
    .slice(0, 5);
  const maxImg = images.reduce((m, r) => Math.max(m, r.summary?.total || 0), 1);

  const nodeList = nodes || [];
  const podList = pods || [];
  const readyNodes = nodeList.filter(nodeIsReady).length;
  const runningPods = podList.filter(p => p.status?.phase === 'Running' || p.status?.phase === 'Succeeded').length;
  const comps = (components || []).filter(c => c.found);
  const compAlive = comps.reduce((a, c) => a + (c.alive | 0), 0);
  const compTotal = comps.reduce((a, c) => a + (c.total | 0), 0);
  const nsCount = (namespaces || []).length;

  const k = kafkaStats?.kafka || {};
  const queueCap = stats?.ingest_queue_cap || 0;
  const queuePct = queueCap ? Math.round(((stats?.ingest_queue_len || 0) / queueCap) * 100) : 0;
  const degraded = comps.filter(c => (c.alive | 0) < (c.total | 0));

  return (
    <div className="page active dash" id="page-dashboard">
      <PageHeader title="Dashboard" subtitle="Security overview of the selected cluster"
        actions={<span className={cx('status-pill', connected ? 'status-pill--ok' : 'status-pill--danger')}>{connected ? 'Live data' : 'Disconnected'}</span>} />

      <div className="dash-kpis">
        <section>
          <SectionLabel>Runtime</SectionLabel>
          <div className="stats-grid stats-grid--3">
            <Stat label="Violations" icon="violations" tone="danger" value={num(violations.length)} sub={`${critRuntime} critical`} onClick={() => navigate('/violations')} />
            <Stat label="Anomalies" icon="alerts" tone="warning" value={num(anomalyEvents?.length)} sub="behaviour deviations" onClick={() => navigate('/alerts')} />
            <Stat label="Audit findings" icon="auditlogs" tone="accent" value={num(auditViolations?.length)} sub="Kubernetes API activity" onClick={() => navigate('/auditlogs')} />
          </div>
        </section>
        <section>
          <SectionLabel>Supply chain</SectionLabel>
          <div className="stats-grid stats-grid--3">
            <Stat label="Critical CVEs" icon="alert" tone="danger" value={num(summary?.critical)} sub={`${num(summary?.inKev)} in CISA KEV`} onClick={() => navigate('/vulnmgmt')} />
            <Stat label="Images" icon="package" value={num(scannedImages)}
              sub={!agentOnline ? 'scanner offline' : failedScans > 0 ? `${failedScans} failed to scan` : 'scanned with Trivy'} />
            <Stat label="Fixable" icon="circle-check" tone="ok" value={num(summary?.fixable)} sub={`of ${num(cveTotal)} findings`} />
          </div>
        </section>
      </div>

      <Pane accent icon="hexagon" title={<span className="row">Cluster health {degraded.length > 0
          ? <span className="status-pill status-pill--warning">{degraded.length} component{degraded.length === 1 ? '' : 's'} degraded</span>
          : comps.length > 0 && <span className="status-pill status-pill--ok">all components up</span>}</span>}
        sub={lastUpdated ? `Snapshot ${new Date(lastUpdated).toLocaleTimeString()}` : sensorOnline ? 'Waiting for the first snapshot' : 'Sensor offline'}
        tools={<button type="button" className="btn btn-outline" onClick={() => navigate('/violations')}><Icon name="alert" className="t-warning" />Review violations<Icon name="chevron-right" /></button>}
        flush bodyClassName="health-tiles">
        <HealthTile label="Nodes" icon="server" value={num(nodeList.length)} ready={readyNodes} total={nodeList.length} hint={`Ready ${readyNodes}/${nodeList.length}`} />
        <HealthTile label="Platform" icon="cpu" value={num(compAlive)} ready={compAlive} total={compTotal} hint={compTotal ? `Replicas alive ${compAlive}/${compTotal}` : 'No component data'} />
        <HealthTile label="Pods" icon="layers" value={num(podList.length)} ready={runningPods} total={podList.length} hint={`Running ${runningPods}/${podList.length}`} />
        <HealthTile label="Namespaces" icon="hexagon" value={num(nsCount)} ready={nsCount} total={nsCount} hint="watched by the sensor" />
      </Pane>

      <div className="grid-2">
        <Pane accent icon="cpu" title="Event pipeline" bodyClassName="pane-body--flush"
          footer={null}>
          <div className="pane-body">
            <div className="meter-row"><span>Bridge ingest queue</span><b>{queueCap ? `${queuePct}% full` : '—'}</b></div>
            <Meter value={queuePct} showValue={false} label="Ingest queue" color={queuePct > 80 ? 'var(--danger)' : queuePct > 50 ? 'var(--warning)' : undefined} />
            <div className="meter-row mt-16"><span>Kafka consumer lag</span><b>{k.total_lag != null ? `${num(k.total_lag)} messages` : '—'}</b></div>
          </div>
          <Metrics items={[
            { label: 'Events/s', value: (stats?.events_per_sec || 0).toFixed(1) },
            { label: 'Dropped', value: num(stats?.events_dropped), tone: (stats?.events_dropped || 0) > 0 ? 'danger' : undefined },
            { label: 'Brokers', value: k.broker_count ?? '—' },
            { label: 'Ingest avg', value: `${(stats?.ingest_avg_ms || 0).toFixed(1)} ms` },
          ]} />
        </Pane>

        <Pane accent icon="package" title="Image CVEs by severity" tools={<span className="pill-count">{num(cveTotal)} total</span>}>
          <SevBar counts={cveCounts} />
          <div className="stack mt-16">
            {cveCounts.map(([key, count, color]) => (
              <div key={key}>
                <div className="meter-row"><span className="t-primary">{key}</span><b>{num(count)}</b></div>
                <Meter value={count} max={cveTotal || 1} color={color} showValue={false} label={`${key} CVEs`} />
              </div>
            ))}
          </div>
        </Pane>
      </div>

      {comps.length > 0 && (
        <div className="strip">
          <span className="strip-lead"><Icon name="radio" />Agents reporting</span>
          {comps.slice(0, 8).map(c => (
            <span key={c.id} className={cx((c.alive | 0) < (c.total | 0) && 't-warning')}>{c.label || c.id} {c.alive | 0}/{c.total | 0}</span>
          ))}
          {stats?.uptime_sec != null && <span>bridge up {Math.round((stats.uptime_sec || 0) / 3600)} h</span>}
        </div>
      )}

      <div className="grid-2-1">
        <Pane accent="danger" icon="alert" title="Runtime violations"
          tools={<span className="status-pill status-pill--danger">{num(violations.length)} open</span>} bodyClassName="pane-body--flush">
          <div className="pane-body pb-6">
            <SevBar counts={runtimeCounts} />
          </div>
          {recent.length === 0
            ? <div className="empty-state empty-state--compact"><Icon name="circle-check" size={26} /><div className="empty-title">No runtime violations</div><div className="empty-sub">New matches appear here as Tracee reports them.</div></div>
            : recent.map((v, i) => (
              <button key={v._fp || i} type="button" className="issue" onClick={() => navigate('/violations')}>
                <SevBadge sev={String(v.sev || v.severity || '').toUpperCase()} />
                <span className="issue-main">
                  <span className="issue-title">{v._ruleName || v.syscall || v.name || 'Violation'}</span>
                  <span className="issue-sub">{originOf(v) ? `${originOf(v).title}${originOf(v).shortId ? ` · ${originOf(v).shortId}` : ''}` : `${v.namespace || '—'} / ${v.pod || '—'}`}</span>
                  <span className="issue-meta mono">{[v.syscall || v.eventName, v.process || v.processName].filter(Boolean).join(' · ') || '—'}</span>
                </span>
                <span className="issue-end">{timeLabel(v)}</span>
              </button>
            ))}
          {violations.length > recent.length && (
            <div className="pane-foot"><button type="button" className="link-btn" onClick={() => navigate('/violations')}>View all {num(violations.length)}<Icon name="chevron-right" /></button></div>
          )}
        </Pane>

        <Pane accent icon="package" title="Riskiest images" bodyClassName="pane-body--flush"
          tools={<span className={cx('status-pill', agentOnline ? 'status-pill--ok' : 'status-pill--muted')}>{agentOnline ? 'Fresh' : 'Scanner offline'}</span>}>
          {images.length === 0
            ? <div className="empty-state empty-state--compact"><div className="empty-title">No vulnerable images</div><div className="empty-sub">Scan results appear after the scanner finishes.</div></div>
            : images.map(r => (
              <button key={r.image} type="button" className="top-item" onClick={() => navigate('/vulnmgmt')}>
                <span className="top-row">
                  <span className="grow">
                    <span className="top-name clip">{r.image}</span>
                    <span className="top-sub">{num(r.summary?.critical)} critical · {num(r.summary?.high)} high</span>
                  </span>
                  <span className="top-val">{num(r.summary?.total)}<small>CVEs</small></span>
                </span>
                <Meter value={r.summary?.total || 0} max={maxImg} showValue={false} label={`${r.image} CVEs`}
                  color={(r.summary?.critical || 0) > 0 ? 'var(--danger)' : (r.summary?.high || 0) > 0 ? 'var(--orange)' : 'var(--warning)'} />
              </button>
            ))}
        </Pane>
      </div>

      {topWorkloads.length > 0 && (
        <Pane icon="layers" title="Top workloads by violations">
          <div className="stack">
            {topWorkloads.map(([key, count]) => {
              const [ns, wl] = key.split('|');
              return (
                <div key={key}>
                  <div className="meter-row"><span className="t-primary">{wl}<span className="t-muted"> · {ns}</span></span><b>{num(count)}</b></div>
                  <Meter value={count} max={maxWl} color="var(--danger)" showValue={false} label={`${wl} violations`} />
                </div>
              );
            })}
          </div>
        </Pane>
      )}
    </div>
  );
}
