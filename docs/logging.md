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
{"@timestamp":"...","log.level":"error","message":"security_alert","service.name":"kvisior","component":"kvisior/alert-log","event.kind":"alert","cluster.id":"prod-eu","cluster.name":"Production EU","event.created":"2026-10-04T09:00:00Z","alert.type":"syscall","alert.source":"tracee-bridge","rule.id":"reverse-shell","rule.name":"Reverse shell","alert.severity":"CRITICAL","namespace":"prod","target":"api-7c9","kubernetes.pod.name":"api-7c9","host.name":"worker-2","syscall":"connect"}
```

Severity maps to `log.level`: `CRITICAL`/`HIGH` → `error`, `LOW`/`INFO` → `info`,
everything else → `warn`.

`cluster.id` identifies the cluster where the event occurred; `cluster.name` is
its display name from the shared `clusters` table. The receiver takes the ID
from the existing authenticated push context (certificate, trusted header or
local Edge configuration), ignoring cluster fields in the JSON body. Names
fall back to the ID when registration or a database lookup is unavailable.
The Edge caches names for up to 30 seconds and invalidates its cache on local
cluster edits.

Known event metadata is added to security logs when available: pod, node,
container, process/PID, source/destination IP and port, actor, event ID, action
and resource. Raw JSON bodies and credentials are not added as context fields.
Tracee and anomaly direct-database fallback alerts use the same structured
logger.

### Discord and Mattermost

Both notification formats include cluster name and stable ID, the database
alert ID, event time in UTC, source, rule, namespace/target and syscall when
available. Severity-less notifications also carry cluster identity. The worker
reads `alerts.cluster_id` and joins the current `clusters.name` at delivery time,
so renamed clusters and direct-database fallback alerts are covered. Missing
cluster registration does not exclude an alert.

Example notification:

```text
HIGH · Shell spawned
Cluster: Production EU (prod-eu)
Cluster ID: prod-eu
Alert ID: 42
Time (UTC): 2026-10-04T09:00:00Z
Source: tracee-bridge
Rule ID: shell
Namespace / target: prod / api-123
Syscall: execve
unexpected shell
```

Each managed cluster must have a unique `global.clusterId`; assign its display
name in the HUB cluster settings. Until named, the ID is shown in both fields.
Additional metadata such as IPs, node, process and actor stays in local logs;
the webhook formatter does not export these fields from the raw event payload.
Long notification fields are shortened to fit
[Discord embed limits](https://docs.discord.com/developers/resources/message#embed-limits).

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

# alerts from one cluster
message:"security_alert" and cluster.id:"prod-eu"

# critical/high only
message:"security_alert" and log.level:"error"

# errors from one service
service.name:"scanner-agent" and log.level:"error"

# everything for a namespace
kubernetes.namespace:"wolfee-watcher" and namespace:"prod"
```
