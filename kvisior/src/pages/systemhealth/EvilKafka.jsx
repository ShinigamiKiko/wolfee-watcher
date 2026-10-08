import { useBridge } from '../../context/BridgeContext';
import { Sparkline } from '../../components/Sparkline';
import { Stat, Metrics, Notice, cx } from '../../components/kit';

function fmtBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

const toPoints = list => (list || []).map((p, i) => ({ ts: i, value: p.y }));
const lastY = list => (list || []).length ? (list[list.length - 1]?.y ?? 0) : 0;
const num = v => (v ?? 0).toLocaleString();
const ts = v => (v ? v.slice(0, 19).replace('T', ' ') : '—');

function NoData({ msg }) {
  return <div className="empty-state empty-state--compact">{msg}</div>;
}

export function EvilKafka() {
  const { stats, kafkaStats, kafkaSeries } = useBridge();

  const k          = kafkaStats?.kafka    || {};
  const pg         = kafkaStats?.postgres || { enabled: false };
  const partitions = k.partitions         || [];
  const lag        = k.total_lag || 0;
  const queuePct   = stats?.ingest_queue_pct || 0;

  const lagSeries = kafkaSeries?.totalLag         || [];
  const msgSeries = kafkaSeries?.totalMessages    || [];
  const bufSeries = kafkaSeries?.producerBuffered || [];
  const missingTopic = k.error && /UNKNOWN_TOPIC_OR_PARTITION/i.test(k.error);

  return (
    <>
      <div className="stats-grid stats-grid--5">
        <Stat label="Brokers" value={k.broker_count ?? '—'} tone={(k.broker_count || 0) > 0 ? 'ok' : 'danger'}
          sub={k.controller_id !== undefined ? `controller: ${k.controller_id}` : 'no metadata'} />
        <Stat label="Partitions" value={k.partition_count ?? '—'} tone={(k.partition_count || 0) > 0 ? 'ok' : undefined}
          sub={k.topic ? `topic: ${k.topic}` : '—'} />
        <Stat label="Total Lag" value={k.total_lag != null ? num(k.total_lag) : '—'} tone={lag > 100000 ? 'danger' : lag > 1000 ? 'warning' : 'ok'}
          sub={`group: ${k.sink_group || '—'}`} />
        <Stat label="Under-Replicated" value={k.under_replicated ?? '—'} tone={(k.under_replicated || 0) === 0 ? 'ok' : 'danger'}
          sub="partitions with ISR < replicas" />
        <Stat label="Consumer Group" value={k.sink_group_state || '—'} tone={k.sink_group_state === 'Stable' ? 'ok' : k.sink_group_state ? 'warning' : 'danger'}
          sub={`${k.sink_group_members ?? '—'} members · ${k.sink_group || '—'}`} />
      </div>

      {lag > 0 && (k.sink_group_members || 0) === 0 && (
        <Notice tone="danger">
          <span className="t-strong">Dead consumer group</span> — lag {num(lag)} and 0 active members. Events are accumulating unprocessed.
        </Notice>
      )}

      {k.error && (
        <Notice tone={missingTopic ? 'warning' : 'danger'}>
          {missingTopic
            ? `Kafka topic "${k.topic || 'tracee-events'}" not yet created — waiting for the bridge to ensure it (auto-creates on first produce). Stats will populate once the topic exists.`
            : `Kafka admin error: ${k.error}`}
        </Notice>
      )}

      {stats && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              Kafka Pipeline <span className="card-sub">bridge</span>
              {stats.kafka_topic && <span className="card-sub mono">topic: {stats.kafka_topic}</span>}
            </div>
          </div>
          <Metrics items={[
            { label: 'Ingest Queue', value: `${stats.ingest_queue_len || 0}/${stats.ingest_queue_cap || 0}`, sub: `${queuePct.toFixed(1)}% full`,
              tone: queuePct > 80 ? 'danger' : queuePct > 50 ? 'warning' : 'ok' },
            { label: 'Prod. Buffered', value: stats.kafka_buffered_records || 0, sub: fmtBytes(stats.kafka_buffered_bytes || 0) },
            { label: 'Pushed to Kafka', value: num(stats.hub_passed), sub: 'passed filter + dedup', tone: 'ok' },
            { label: 'Filter Rejected', value: num(stats.hub_dropped), sub: 'empty execpath/cmdline or kafka error', tone: (stats.hub_dropped || 0) > 0 ? 'warning' : 'ok' },
            { label: 'Dedup Skipped', value: num(stats.dedup_skipped) },
            { label: 'Queue Dropped', value: num(stats.events_dropped), tone: (stats.events_dropped || 0) > 0 ? 'danger' : undefined },
            { label: 'SSE Clients', value: stats.clients || 0 },
            { label: 'SSE Drops', value: stats.sse_drops || 0, tone: (stats.sse_drops || 0) > 0 ? 'danger' : undefined },
          ]} />
        </div>
      )}

      <div className="card">
        <div className="card-header"><div className="card-title">Kafka Trend <span className="card-sub">10 min rolling</span></div></div>
        <Metrics cols={3} items={[
          { label: 'Messages (total)', children: <Sparkline fluid points={toPoints(msgSeries)} color="var(--accent)" height={72} width={300} label={num(lastY(msgSeries))} /> },
          { label: 'Consumer lag', children: <Sparkline fluid points={toPoints(lagSeries)} color="var(--warning)" height={72} width={300} label={num(lastY(lagSeries))} /> },
          { label: 'Producer buffered', children: <Sparkline fluid points={toPoints(bufSeries)} color="var(--violet-text)" height={72} width={300} label={String(lastY(bufSeries))} /> },
        ]} />
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Partitions</div>
          {partitions.length > 0 && (
            <span className="card-sub">{partitions.length} partitions · {num(k.total_messages)} messages · lag {lag}</span>
          )}
        </div>
        {partitions.length === 0 ? (
          <NoData msg="No partition metadata — Kafka not reachable or topic not found." />
        ) : (
          <div className="table-wrap">
            <table className="data-table data-table--static mono">
              <thead><tr>
                <th className="t-center">#</th><th className="t-center">Leader</th><th className="num">ISR/Rep</th><th className="num">Log Start</th>
                <th className="num">Log End</th><th className="num">Messages</th><th className="num">Group Offset</th><th className="num">Lag</th>
              </tr></thead>
              <tbody>
                {[...partitions].sort((a, b) => a.partition - b.partition).map(p => (
                  <tr key={p.partition}>
                    <td className="t-center">{p.partition}</td>
                    <td className="t-center">{p.leader}</td>
                    <td className={cx('num', p.isr < p.replicas ? 't-danger' : 't-primary')}>{p.isr} / {p.replicas}</td>
                    <td className="num t-muted">{p.log_start}</td>
                    <td className="num">{p.log_end}</td>
                    <td className="num">{p.messages}</td>
                    <td className="num t-muted">{p.group_offset}</td>
                    <td className={cx('num', p.lag > 1000 && 't-warning')}>{p.lag}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">PostgreSQL — Event Store</div>
          {!pg.enabled && <span className="card-sub">PG disabled · in-memory mode</span>}
        </div>
        {!pg.enabled ? (
          <NoData msg="PostgreSQL not connected — running in-memory mode." />
        ) : (
          <>
            <Metrics items={[
              { label: 'Ping', value: `${(pg.ping_ms || 0).toFixed(2)} ms`, tone: 'ok' },
              { label: 'Connections', value: `${pg.active_conns || 0} / ${pg.total_conns || 0} / ${pg.max_conns || 0}`, sub: 'active / total / max' },
              { label: 'Events (24h)', value: num(pg.events_last_24h), tone: 'ok' },
              { label: 'Events (1h)', value: num(pg.events_last_hour) },
              { label: 'Table Size', value: fmtBytes(pg.table_size_bytes || 0) },
              { label: 'Idle Conns', value: pg.idle_conns || 0 },
              { label: 'Oldest Event', value: ts(pg.oldest_event_ts) },
              { label: 'Newest Event', value: ts(pg.newest_event_ts) },
            ]} />
            {pg.error && <Notice tone="danger" className="mb-0">PG error: {pg.error}</Notice>}
          </>
        )}
      </div>
    </>
  );
}
