import { useBridge } from '../../context/BridgeContext';
import { Sparkline } from '../../components/Sparkline';

const GREEN  = 'var(--accent-3,#3ecf8e)';
const ORANGE = 'var(--warn,#f5a623)';
const RED    = 'var(--danger,#e25c5c)';
const BLUE   = '#5b8dee';
const MUTED  = 'var(--text-muted)';

function fmtBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function StatCell({ label, value, color, sub }) {
  return (
    <div style={{ padding: '14px 20px', borderRight: '1px solid var(--border)', borderTop: '1px solid var(--border)' }}>
      <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.07em', color: MUTED, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 300, fontFamily: 'JetBrains Mono,monospace', color: color || 'var(--accent)' }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: MUTED, marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function NoData({ msg }) {
  return (
    <div style={{ padding: 24, color: MUTED, fontSize: 13, textAlign: 'center' }}>
      {msg || 'No data — Kafka admin API unavailable or still loading.'}
    </div>
  );
}

export function EvilKafka() {
  const { stats, kafkaStats, kafkaSeries } = useBridge();

  const k          = kafkaStats?.kafka     || {};
  const pg         = kafkaStats?.postgres  || { enabled: false };
  const partitions = k.partitions          || [];

  const lagSeries = kafkaSeries?.totalLag         || [];
  const msgSeries = kafkaSeries?.totalMessages    || [];
  const bufSeries = kafkaSeries?.producerBuffered || [];

  return (
    <>
      {}
      <div className="health-grid">
        <div className="health-widget">
          <div className="health-label">Brokers</div>
          <div className="health-value" style={{ color: (k.broker_count || 0) > 0 ? GREEN : RED }}>{k.broker_count ?? '—'}</div>
          <div className="health-sub">{k.controller_id !== undefined ? `controller: ${k.controller_id}` : 'no metadata'}</div>
        </div>
        <div className="health-widget">
          <div className="health-label">Partitions</div>
          <div className="health-value" style={{ color: (k.partition_count || 0) > 0 ? GREEN : MUTED }}>{k.partition_count ?? '—'}</div>
          <div className="health-sub">{k.topic ? `topic: ${k.topic}` : '—'}</div>
        </div>
        <div className="health-widget">
          <div className="health-label">Total Lag</div>
          <div className="health-value" style={{ color: (k.total_lag || 0) > 100000 ? RED : (k.total_lag || 0) > 1000 ? ORANGE : GREEN }}>
            {(k.total_lag ?? '—').toLocaleString?.() ?? '—'}
          </div>
          <div className="health-sub">{`group: ${k.sink_group || '—'}`}</div>
        </div>
        <div className="health-widget">
          <div className="health-label">Under-Replicated</div>
          <div className="health-value" style={{ color: (k.under_replicated || 0) === 0 ? GREEN : RED }}>
            {k.under_replicated ?? '—'}
          </div>
          <div className="health-sub">partitions with ISR &lt; replicas</div>
        </div>
        <div className="health-widget">
          <div className="health-label">Consumer Group</div>
          <div className="health-value" style={{ color: k.sink_group_state === 'Stable' ? GREEN : k.sink_group_state ? ORANGE : RED }}>
            {k.sink_group_state || '—'}
          </div>
          <div className="health-sub">{k.sink_group_members ?? '—'} members · {k.sink_group || '—'}</div>
        </div>
      </div>

      {}
      {(k.total_lag || 0) > 0 && (k.sink_group_members || 0) === 0 && (
        <div className="card" style={{ marginBottom: 16, borderColor: RED }}>
          <div style={{ padding: '12px 16px', color: RED, fontSize: 12, fontWeight: 600 }}>
            Dead consumer group — lag {(k.total_lag || 0).toLocaleString()} and 0 active members. Events are accumulating unprocessed.
          </div>
        </div>
      )}

      {k.error && (() => {
        const isMissingTopic = /UNKNOWN_TOPIC_OR_PARTITION/i.test(k.error);
        return (
          <div className="card" style={{ marginBottom: 16, borderColor: isMissingTopic ? ORANGE : RED }}>
            <div style={{ padding: '12px 16px', color: isMissingTopic ? ORANGE : RED, fontSize: 12 }}>
              {isMissingTopic
                ? `Kafka topic "${k.topic || 'tracee-events'}" not yet created — waiting for the bridge to ensure it (auto-creates on first produce). Stats will populate once the topic exists.`
                : `Kafka admin error: ${k.error}`}
            </div>
          </div>
        );
      })()}

      {}
      {stats && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <div className="card-title">
              Kafka Pipeline (Bridge)
              {stats.kafka_topic && (
                <span style={{ marginLeft: 8, fontSize: 11, color: MUTED, fontFamily: 'JetBrains Mono,monospace' }}>
                  topic: {stats.kafka_topic}
                </span>
              )}
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 0 }}>
            <StatCell label="Ingest Queue"
              value={`${stats.ingest_queue_len || 0}/${stats.ingest_queue_cap || 0}`}
              sub={`${(stats.ingest_queue_pct || 0).toFixed(1)}% full`}
              color={(stats.ingest_queue_pct || 0) > 80 ? RED : (stats.ingest_queue_pct || 0) > 50 ? ORANGE : GREEN} />
            <StatCell label="Prod. Buffered" value={stats.kafka_buffered_records || 0} sub={fmtBytes(stats.kafka_buffered_bytes || 0)} />
            <StatCell label="Pushed to Kafka" value={(stats.hub_passed || 0).toLocaleString()} sub="passed filter + dedup" color={GREEN} />
            <StatCell label="Filter Rejected" value={(stats.hub_dropped || 0).toLocaleString()} sub="empty execpath/cmdline or kafka error" color={(stats.hub_dropped || 0) > 0 ? ORANGE : GREEN} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 0 }}>
            <StatCell label="Dedup Skipped"   value={(stats.dedup_skipped    || 0).toLocaleString()} />
            <StatCell label="Overflow Bypass" value={(stats.events_overflow  || 0).toLocaleString()} color={(stats.events_overflow || 0) > 0 ? ORANGE : undefined} />
            <StatCell label="SSE Clients"     value={stats.clients || 0} />
            <StatCell label="SSE Drops"       value={stats.sse_drops || 0} color={(stats.sse_drops || 0) > 0 ? RED : undefined} />
          </div>
        </div>
      )}

      {}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header"><div className="card-title">Kafka Trend (10 min rolling)</div></div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 0 }}>
          {[
            { label: 'MESSAGES (TOTAL)', points: msgSeries, color: 'var(--accent)', fmt: v => v.toLocaleString() },
            { label: 'CONSUMER LAG',     points: lagSeries, color: ORANGE,           fmt: v => v.toLocaleString() },
            { label: 'PRODUCER BUFFERED',points: bufSeries, color: BLUE,             fmt: v => String(v) },
          ].map(({ label, points, color, fmt }, i) => (
            <div key={label} style={{ padding: '14px 20px', borderRight: i < 2 ? '1px solid var(--border)' : 'none', borderTop: '1px solid var(--border)' }}>
              <div style={{ fontSize: 10, color: MUTED, marginBottom: 6, letterSpacing: '.06em' }}>{label}</div>
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
          <div className="card-title">Partitions</div>
          {partitions.length > 0 && (
            <div style={{ fontSize: 11, color: MUTED }}>
              {partitions.length} partitions · {(k.total_messages || 0).toLocaleString()} messages · lag {k.total_lag || 0}
            </div>
          )}
        </div>
        {partitions.length === 0 ? (
          <NoData msg="No partition metadata — Kafka not reachable or topic not found." />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)', color: MUTED, fontSize: 11, textAlign: 'right' }}>
                  {['#', 'Leader', 'ISR/Rep', 'Log Start', 'Log End', 'Messages', 'Group Offset', 'Lag'].map(h => (
                    <th key={h} style={{ padding: '10px 14px', textAlign: h === '#' || h === 'Leader' ? 'center' : 'right' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[...partitions].sort((a, b) => a.partition - b.partition).map(p => (
                  <tr key={p.partition} style={{ borderBottom: '1px solid var(--border)', fontFamily: 'JetBrains Mono,monospace' }}>
                    <td style={{ padding: '8px 14px', textAlign: 'center' }}>{p.partition}</td>
                    <td style={{ padding: '8px 14px', textAlign: 'center' }}>{p.leader}</td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', color: p.isr < p.replicas ? RED : 'var(--text-primary)' }}>
                      {p.isr} / {p.replicas}
                    </td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', color: MUTED }}>{p.log_start}</td>
                    <td style={{ padding: '8px 14px', textAlign: 'right' }}>{p.log_end}</td>
                    <td style={{ padding: '8px 14px', textAlign: 'right' }}>{p.messages}</td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', color: MUTED }}>{p.group_offset}</td>
                    <td style={{ padding: '8px 14px', textAlign: 'right', color: p.lag > 1000 ? ORANGE : 'var(--text-secondary)' }}>
                      {p.lag}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {}
      <div className="card">
        <div className="card-header">
          <div className="card-title">PostgreSQL — Event Store</div>
          {!pg.enabled && <span style={{ fontSize: 11, color: MUTED }}>PG disabled · in-memory mode</span>}
        </div>
        {!pg.enabled ? (
          <NoData msg="PostgreSQL not connected — running in-memory mode." />
        ) : (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 0 }}>
              <StatCell label="Ping"        value={`${(pg.ping_ms || 0).toFixed(2)} ms`}  color={GREEN} />
              <StatCell label="Connections" value={`${pg.active_conns || 0} / ${pg.total_conns || 0} / ${pg.max_conns || 0}`} sub="active / total / max" />
              <StatCell label="Events (24h)" value={(pg.events_last_24h  || 0).toLocaleString()} color={GREEN} />
              <StatCell label="Events (1h)"  value={(pg.events_last_hour || 0).toLocaleString()} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 0 }}>
              <StatCell label="Table Size"  value={fmtBytes(pg.table_size_bytes || 0)} />
              <StatCell label="Idle Conns"  value={pg.idle_conns || 0} />
              <StatCell label="Oldest Event" value={pg.oldest_event_ts ? pg.oldest_event_ts.slice(0, 19).replace('T', ' ') : '—'} />
              <StatCell label="Newest Event" value={pg.newest_event_ts ? pg.newest_event_ts.slice(0, 19).replace('T', ' ') : '—'} />
            </div>
            {pg.error && (
              <div style={{ padding: '10px 16px', color: RED, fontSize: 12 }}>PG error: {pg.error}</div>
            )}
          </>
        )}
      </div>
    </>
  );
}
