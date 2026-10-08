import { useBridge }  from '../../context/BridgeContext';
import { useScanner } from '../../context/ScannerContext';
import { Stat, Metrics } from '../../components/kit';

const CARD_META = {
  'tracee-bridge':    { label: 'Tracee Bridge',    sub: (s) => s ? `${s.events_total || 0} events total` : 'No data' },
  'scanner-agent':    { label: 'Scanner Agent',    sub: (_s, sc) => sc?.dbUpdatedAt ? `Trivy DB ${sc.dbUpdatedAt.slice(0, 10)}` : 'scanner-agent:9090' },
  'tracee-ebpf':      { label: 'Tracee eBPF',      sub: () => 'DaemonSet · hostPID/Network' },
  'kafka':            { label: 'Kafka',            sub: (s) => s?.kafka_topic ? `Topic ${s.kafka_topic}` : 'Event streaming bus' },
  'postgres':         { label: 'PostgreSQL',       sub: () => 'Event history store' },
  'sensor':           { label: 'Sensor',           sub: () => 'Cluster state collector' },
  'sentry-audit':     { label: 'Sentry Audit',     sub: () => 'K8s audit webhook' },
  'anomaly-detector': { label: 'Anomaly Detector', sub: () => 'Behavior baseline' },
  'honey-operator':   { label: 'Honey Operator',   sub: () => 'Honeypot controller' },
  'audit-runner':     { label: 'Audit Runner',     sub: () => 'Compliance scanner' },
  'forensic-watcher': { label: 'Forensic Watcher', sub: () => 'DaemonSet · /proc snapshot' },
  'cert-server':      { label: 'Cert Server',      sub: () => 'mTLS CA' },
};

function fmtUptime(sec) {
  if (!sec) return '0s';
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${sec}s`;
}

function HealthCard({ label, alive, total, found, sub, dotOk }) {
  const hasReplicas = found && total > 0;
  const value = hasReplicas
    ? (alive === total ? 'Healthy' : (alive === 0 ? 'Offline' : 'Degraded'))
    : (dotOk ? 'Healthy' : 'Unknown');
  const tone = value === 'Healthy' ? 'ok' : value === 'Degraded' ? 'warning' : 'danger';
  const replicaLine = hasReplicas ? `${alive}/${total} replicas alive` : (found ? '0/0 replicas' : 'replicas: n/a');

  return (
    <div className="health-widget">
      <div className="health-label">
        {label}
        <span className={`dot dot--${tone}`} />
      </div>
      <div className={`health-value t-${tone}`}>{value}</div>
      <div className="health-sub">{replicaLine}</div>
      {sub && <div className="health-sub mt-4">{sub}</div>}
    </div>
  );
}

export function EvilComponents() {
  const { connected, stats, components, counts } = useBridge();
  const { agentOnline, agentInfo, summary: vulnSummary } = useScanner();

  const liveHints = { 'tracee-bridge': connected, 'scanner-agent': agentOnline };
  const sum = key => (counts?.[key] || 0) + (vulnSummary?.[key] || 0);

  const cards = (components && components.length)
    ? components
    : Object.keys(CARD_META).map(id => ({ id, found: false, alive: 0, total: 0 }));

  return (
    <>
      <div className="health-grid">
        {cards.map(c => {
          const meta = CARD_META[c.id] || { label: c.label || c.id, sub: () => `${c.kind || ''} ${c.name || ''}`.trim() };
          return (
            <HealthCard key={c.id} label={meta.label} alive={c.alive | 0} total={c.total | 0} found={!!c.found}
              dotOk={liveHints[c.id]} sub={meta.sub(stats, agentInfo)} />
          );
        })}
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Active Violations</div>
          <span className="card-sub">runtime + audit + image CVEs</span>
        </div>
        <Metrics cols={5} items={[
          { label: 'Total',    value: sum('total'),    tone: 'accent' },
          { label: 'Critical', value: sum('critical'), tone: 'danger' },
          { label: 'High',     value: sum('high'),     tone: 'warning' },
          { label: 'Medium',   value: sum('medium'),   tone: 'info' },
          { label: 'Low',      value: sum('low'),      tone: 'muted' },
        ]} />
      </div>

      {stats && (
        <div className="card">
          <div className="card-header"><div className="card-title">Bridge Statistics</div></div>
          <Metrics items={[
            { label: 'Events Total',  value: stats.events_total || 0 },
            { label: 'Events/s',      value: (stats.events_per_sec || 0).toFixed(1) },
            { label: 'Deduplicated',  value: stats.dedup_skipped || 0 },
            { label: 'Rate Limited',  value: stats.events_rate_limited || 0 },
            { label: 'Ingest avg ms', value: (stats.ingest_avg_ms || 0).toFixed(2) },
            { label: 'Query avg ms',  value: (stats.query_avg_ms || 0).toFixed(2) },
            { label: 'SSE Clients',   value: stats.clients || 0 },
            { label: 'Uptime',        value: fmtUptime(stats.uptime_sec || 0) },
          ]} />
        </div>
      )}
    </>
  );
}
