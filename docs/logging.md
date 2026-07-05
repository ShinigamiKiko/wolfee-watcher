# Logging

All Go services emit structured logs via `pkg/logging` (a thin wrapper over
`log/slog`). Output is ECS-style JSON to stdout/stderr, which any Kubernetes log
shipper can collect.

## Configuration

Two environment variables, per service:

| Variable     | Values                         | Default |
|--------------|--------------------------------|---------|
| `LOG_LEVEL`  | `debug` `info` `warn` `error`  | `info`  |
| `LOG_FORMAT` | `json` `text`                  | `json`  |

`text` is convenient for local runs; keep `json` in the cluster.

## Fields

Every line carries ECS core fields plus a service tag:

```json
{"@timestamp":"2026-07-05T12:51:39.2Z","log.level":"info","message":"kafka_consumer_started","service.name":"anomaly-detector","component":"anomaly-detector/consumer","group":"anomaly-v1"}
```

- `@timestamp`, `log.level`, `message` — ECS core
- `service.name` — which service produced the line
- `component` — subsystem within the service (`<service>/<part>`)
- plus any structured key/values the call site adds

Legacy `log.Printf` lines are bridged through the same handler, so they are valid
JSON too (the whole line lands in `message`, without split fields).

### Alerts

Security alerts posted to `kvisior`'s `/internal/alert-log` are logged one record
each, so they can be filtered directly in Kibana:

```json
{"@timestamp":"...","log.level":"error","message":"security_alert","service.name":"kvisior","component":"kvisior/alert-log","event.kind":"alert","alert.type":"syscall","alert.source":"tracee-bridge","rule.name":"Reverse shell","alert.severity":"CRITICAL","namespace":"prod","target":"api-7c9","syscall":"connect"}
```

Severity maps to `log.level`: `CRITICAL`/`HIGH` → `error`, `LOW`/`INFO` → `info`,
everything else → `warn`.

## Shipping to Elasticsearch

The services only write to stdout/stderr — a node agent does the shipping.

- **Already running Elastic Agent / Filebeat / Fluent Bit?** Point it at the
  `wolfee-watcher` namespace. Because the logs are already ECS JSON, decode the
  JSON (`json.keys_under_root`) and no extra parsing is needed.
- **Nothing yet?** Apply the example DaemonSet:
  [`deploy/logging/filebeat.yaml`](../deploy/logging/filebeat.yaml). Create the ES
  credentials secret first — instructions are in the file header.

## Example queries

```
# all alerts
message:"security_alert"

# critical/high only
message:"security_alert" and log.level:"error"

# errors from one service
service.name:"scanner-agent" and log.level:"error"

# everything for a namespace
kubernetes.namespace:"wolfee-watcher" and namespace:"prod"
```
