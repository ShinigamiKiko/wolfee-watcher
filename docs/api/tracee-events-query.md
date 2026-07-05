# Tracee Bridge: `GET /events/query`

Server-side window query for forensic snapshot export.

## Query params
- `hours` (int, optional): lookback window in hours, default `6`, max `24`.
- `limit` (int, optional): max events to return, default `20000`, max `50000`.
- `namespace` (string, optional): exact namespace filter.
- `pod` (string, optional): exact pod name filter.
- `container` (string, optional): exact container name filter.

## Response
```json
{
  "events": [
    {
      "id": 123,
      "ts": "2026-03-25T12:00:00Z",
      "syscall": "execve",
      "namespace": "wolfee-watcher",
      "pod": "sensor-abc",
      "container": "sensor"
    }
  ],
  "hours": 6,
  "truncated": false,
  "count": 1,
  "pg_mode": true
}
```

## Notes
- `truncated=true` means server hit `limit` and caller should reduce window or paginate (future enhancement).
- If PostgreSQL is disabled (no `POSTGRES_DSN`), data comes from in-memory bridge history.
