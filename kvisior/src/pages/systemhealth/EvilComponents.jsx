import { useBridge }  from '../../context/BridgeContext';
import { useScanner } from '../../context/ScannerContext';

const CARD_META = {
  'tracee-bridge':    { label: 'Tracee Bridge',    sub: (s) => s ? `${s.events_total || 0} events total` : 'No data' },
  'scanner-agent':    { label: 'Scanner Agent',    sub: (_s, sc) => sc?.grypeVersion ? `Grype ${sc.grypeVersion}` : 'scanner-agent:9090' },
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

function HealthCard({ id, label, alive, total, found, sub, dotOk }) {
  const hasReplicas = found && total > 0;
  const ok = hasReplicas ? (alive > 0 && alive === total) : !!dotOk;
  const value = hasReplicas
    ? (alive === total ? 'Healthy' : (alive === 0 ? 'Offline' : 'Degraded'))
    : (dotOk ? 'Healthy' : 'Unknown');
  const color = ok ? 'var(--accent-3)' : (value === 'Degraded' ? 'var(--warn,#f5a623)' : 'var(--danger)');
  const replicaLine = hasReplicas
    ? `${alive}/${total} replicas alive`
    : (found ? '0/0 replicas' : 'replicas: n/a');

  return (
    <div className="health-widget">
      <div className="health-label">
        {label}{' '}
        <span className={`status-dot status-${ok ? 'active' : 'error'}`} style={{ fontSize: 10 }} />
      </div>
      <div className="health-value" style={{ color }}>{value}</div>
      <div className="health-sub">{replicaLine}</div>
      {sub && <div className="health-sub" style={{ opacity: 0.7, marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

const SEV_COLORS = {
  critical: 'var(--danger,#e25c5c)',
  high:     'var(--warn,#f5a623)',
  medium:   '#5b8dee',
  low:      'var(--text-muted)',
};

export function EvilComponents() {
  const { connected, stats, components, counts } = useBridge();
  const { agentOnline, agentInfo, summary: vulnSummary } = useScanner();

  const liveHints = { 'tracee-bridge': connected, 'scanner-agent': agentOnline };

  const totalCounts = {
    critical: (counts?.critical || 0) + (vulnSummary?.critical || 0),
    high:     (counts?.high     || 0) + (vulnSummary?.high     || 0),
    medium:   (counts?.medium   || 0) + (vulnSummary?.medium   || 0),
    low:      (counts?.low      || 0) + (vulnSummary?.low      || 0),
    total:    (counts?.total    || 0) + (vulnSummary?.total    || 0),
  };

  const cards = (components && components.length)
    ? components
    : Object.keys(CARD_META).map(id => ({ id, found: false, alive: 0, total: 0 }));

  return (
    <>
      {}
      <div className="health-grid">
        {cards.map(c => {
          const meta = CARD_META[c.id] || { label: c.label || c.id, sub: () => `${c.kind || ''} ${c.name || ''}`.trim() };
          return (
            <HealthCard
              key={c.id}
              id={c.id}
              label={meta.label}
              alive={c.alive | 0}
              total={c.total | 0}
              found={!!c.found}
              dotOk={liveHints[c.id]}
              sub={meta.sub(stats, agentInfo)}
            />
          );
        })}
      </div>

      {}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <div className="card-title">Active Violations</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            runtime + audit + image CVEs
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 0 }}>
          {[
            ['Total',    totalCounts.total,    'var(--accent)'],
            ['Critical', totalCounts.critical, SEV_COLORS.critical],
            ['High',     totalCounts.high,     SEV_COLORS.high],
            ['Medium',   totalCounts.medium,   SEV_COLORS.medium],
            ['Low',      totalCounts.low,      SEV_COLORS.low],
          ].map(([label, val, color]) => (
            <div key={label} style={{ padding: '14px 20px', borderRight: '1px solid var(--border)', borderTop: '1px solid var(--border)' }}>
              <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.07em', color: 'var(--text-muted)', marginBottom: 6 }}>{label}</div>
              <div style={{ fontSize: 22, fontWeight: 300, fontFamily: 'JetBrains Mono,monospace', color }}>{val}</div>
            </div>
          ))}
        </div>
      </div>

      {}
      {stats && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header"><div className="card-title">Bridge Statistics</div></div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 0 }}>
            {[
              ['Events Total',    stats.events_total         || 0],
              ['Events/s',        (stats.events_per_sec      || 0).toFixed(1)],
              ['Deduplicated',    stats.dedup_skipped        || 0],
              ['Rate Limited',    stats.events_rate_limited  || 0],
              ['Ingest avg ms',   (stats.ingest_avg_ms       || 0).toFixed(2)],
              ['Query avg ms',    (stats.query_avg_ms        || 0).toFixed(2)],
              ['SSE Clients',     stats.clients              || 0],
              ['Uptime',          fmtUptime(stats.uptime_sec || 0)],
            ].map(([label, val]) => (
              <div key={label} style={{ padding: '14px 20px', borderRight: '1px solid var(--border)', borderTop: '1px solid var(--border)' }}>
                <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.07em', color: 'var(--text-muted)', marginBottom: 6 }}>{label}</div>
                <div style={{ fontSize: 20, fontWeight: 300, fontFamily: 'JetBrains Mono,monospace', color: 'var(--accent)' }}>{val}</div>
              </div>
            ))}
          </div>
        </div>
      )}

    </>
  );
}
