# Tracee Bridge High-Load Profile (Production)

Recommended starting point for clusters with large syscall volume.

## Goals

- Keep ingestion stable under burst traffic.
- Fail fast under overload (429/503/504), avoid OOM and unbounded latency.
- Protect SSE fanout from slow clients.

## Environment variables

| Variable | Default | High-load starting point | Notes |
|---|---:|---:|---|
| `TRACEE_INGEST_MAX_CONCURRENCY` | `8` | `16-32` | Concurrent `/tracee/event` handlers |
| `TRACEE_QUERY_MAX_CONCURRENCY` | `4` | `4-8` | Concurrent `/events/query` handlers |
| `TRACEE_INGEST_RATE_PER_MIN` | `6000` | `30000+` | Per-client token bucket, ingest |
| `TRACEE_QUERY_RATE_PER_MIN` | `240` | `600-1200` | Per-client token bucket, queries |
| `TRACEE_QUERY_TIMEOUT_MS` | `4000` | `2000-4000` | Query path timeout |
| `SSE_CLIENT_MAX_DROPS` | `256` | `64-256` | Evict slow SSE clients after repeated drops |

## Operational signals to watch

- `events_rejected`
- `events_rate_limited`
- `events_busy`
- `query_timeouts`
- `sse_drops`
- `sse_evictions`
- `history` / `clients`

If these counters rise quickly during normal traffic, raise capacity or tune limits.

## Suggested rollout

1. Start with defaults in staging.
2. Run burst + soak tests.
3. Increase ingest concurrency/rate in small increments.
4. Keep `query` limits stricter than ingest limits.
5. Confirm p95/p99 and drop rate SLO before production rollout.
