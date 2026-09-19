# Multi-cluster and database scaling

One `kvisior` and one PostgreSQL serve any number of managed clusters. Every
event row carries a `cluster_id`, the UI has a cluster switcher, and the id is
taken from the pushing agent's mTLS certificate rather than from the request
body.

## Cluster identity

`global.clusterId` in the Helm chart is the identity of the cluster a release is
installed into. It must be stable and unique — it is written into every row and
stamped into every client certificate issued by that cluster's `cert-server`, as
an `OU=cluster:<id>` entry. The chart rejects anything that is not a valid
lowercase DNS-style label.

kvisior resolves the cluster of an incoming push in this order:

1. `OU=cluster:<id>` in the client certificate — authoritative, and the only
   option that a compromised agent cannot forge.
2. The `X-Cluster-ID` header, but only when `global.trustClusterHeader=true`.
   Use this for development, or for a topology where mTLS terminates before
   kvisior. It lets any agent that holds the push secret claim any cluster, so
   do not enable it in production.
3. `KVISIOR_CLUSTER_ID`, the cluster kvisior itself runs in.

Clusters register themselves: the first push from an unknown id inserts a row in
`clusters` and it appears in the UI switcher. `last_seen_at` is refreshed at most
once every five minutes per cluster.

Reads are scoped by the `X-Cluster-ID` header, which the UI sets from the
switcher; the SSE stream at `/v1/stream?cluster=<id>` is filtered server-side.

## Topology: one kvisior per cluster, one database

Every cluster runs its own kvisior next to its agents. All of them write to the
same PostgreSQL, each stamping its own `global.clusterId`. Any of them can serve
the UI; the one users open is the hub.

Data that lives in the database — violations, alerts, audit events, forensic
history, container logs, binary exec events, image scans and workloads,
honeypot events, anomalies, scanner state — is read by the hub directly, scoped
by the cluster selected in the UI.

Live views cannot come from the database: node and pod lists, forensic
tarballs, the network graph, starting a scan or an audit run, honeypot
management, pod syscall watches and the SSE event stream. For those the hub
forwards the request to the selected cluster's kvisior:

- on start, each kvisior writes its own address into `clusters.endpoint`
  (`ui.advertiseURL`, defaulting to its in-cluster service URL);
- when the UI selects a cluster other than the hub's own, the hub proxies the
  live paths to that endpoint with `X-Federation-Token` and the acting user and
  role, and drops the user's cookie;
- the receiving kvisior accepts the request only with the same
  `global.federationToken`, and applies the forwarded role to mutations as
  usual;
- a cluster without an endpoint answers 502 with the reason, and the UI shows a
  banner that only stored history is available for it. It never shows the
  hub's own live data under another cluster's name.

For clusters in different networks, set `ui.advertiseURL` to an address the hub
can reach (an ingress with TLS) and list the hub's namespace — or allow its
source — in `networkPolicy.federationNamespaces` / `networkPolicy.extraIngress`.

A second cluster needs:

```yaml
global:
  namespace: <its namespace>
  clusterId: <its id>
  federationToken: <same as the hub>
  certServerAddr: https://cert-server.<its namespace>.svc.cluster.local:8090
postgres:
  enabled: false
  external: { enabled: true, host: <hub postgres>, port: 5432, sslMode: require }
centralMigrate:
  enabled: false
kafka:
  enabled: false
  brokers: ''
```

plus whichever agents that cluster should run. Service names, certificate SANs
and the default cert-server address follow `POD_NAMESPACE`, so the release can
live in any namespace. Spokes can share the hub's CA or use an intermediate.

## External hub

The hub can run outside Kubernetes: `KVISIOR_MODE=hub` gives a kvisior with no
local cluster — no collector, Kafka consumers, pod watches or push endpoints —
that serves the UI from the database and forwards every live request to the
selected cluster's edge. It refuses to start without the database. Edges then
expose federation on a TLS NodePort (`ui.federation`) restricted by network
policy to the hub's address, and verify the database certificate
(`postgres.external.sslMode: verify-ca` with `caBundle`). See
[`deploy/hub/README.md`](../deploy/hub/README.md).

## Database

### Partitioning

`container_logs` and `audit_events` are `PARTITION BY RANGE (ts)` with hourly
partitions. Retention drops whole partitions instead of deleting rows, which is
what keeps the table from bloating faster than autovacuum can follow — the old
hourly `DELETE ... WHERE ts < now() - interval` across three large tables was the
first thing that would have fallen over as clusters were added.

Partition maintenance runs in kvisior's retention loop, hourly and at startup,
through `ww_maintain_partitions(retention_hours, ahead_hours)`. The function is
`SECURITY DEFINER` and `EXECUTE` is granted to `ww_ui`, so kvisior can create and
drop partitions without owning the tables. It pre-creates 48 hours ahead; since
kvisior is itself the only writer to these tables, partitions can never be needed
while it is down.

`alerts` is deliberately not partitioned. It is a delivery queue with a
five-minute TTL, so partitioning buys nothing; it gets aggressive per-table
autovacuum settings and a lower fillfactor instead. `forensic_events`,
`anomaly_events` and `binary_exec_events` keep row-level retention because their
dedup constraints span time and cannot include the partition key; they are swept
in bounded `ctid` batches outside the retention transaction.

### Uniqueness

Every per-cluster primary key and unique index now starts with `cluster_id`, and
`store.Fingerprint` hashes the cluster in. Without this, two clusters with the
same namespace and pod names — `kube-system/coredns`, say — would collapse into
one violation row and silently lose events. The same applied to `image_scans`
keyed by image reference, `honeypot_events`, `forensic_events`, `log_cursors`,
`snapshot_cache` and the rest.

### Connection pooling

`pgbouncer.enabled=true` puts PgBouncer in transaction mode in front of
PostgreSQL. Application DSNs then carry `default_query_exec_mode=exec`, because
pgx's default prepared-statement caching does not survive transaction pooling.
`central-migrate` always connects directly to PostgreSQL — DDL and role
management need a session.

Retention holds `pg_try_advisory_xact_lock` inside a transaction rather than a
session-level lock, which is what makes it correct behind a transaction pooler.

### Running PostgreSQL elsewhere

The in-chart StatefulSet is a single replica with no backups. It is fine for a
single cluster and a development stand; for a hub serving several clusters it is
both the bottleneck and the single point of failure. Point the chart at a managed
or operator-run PostgreSQL instead:

```yaml
postgres:
  enabled: false
  external:
    enabled: true
    host: pg.internal.example.com
    port: 5432
    sslMode: require
```

Use an operator (CloudNativePG, Zalando) for a synchronous replica, automatic
failover and PITR. Without it, losing the volume loses the history of every
cluster at once.

`ui.controlPlaneDSN` optionally moves accounts, sessions and tokens onto a
separate database, so that pressure on the telemetry tables cannot take
authentication down with it.

### Retention

| Table | TTL | Mechanism |
|---|---|---|
| `alerts` | 5 min | row delete, tuned autovacuum |
| `container_logs` | 24 h | drop partition |
| `audit_events` | 24 h | drop partition |
| `forensic_events` | 24 h | batched row delete |
| `binary_exec_events` | 24 h | batched row delete |
| `audit_runs` | 14 d, 50 per tool per cluster | row delete |
| `kvisior_violations` | 30 d | row delete |
| `honeypot_events` | 30 d | row delete |

## Upgrading an existing install

Schema `0012-multicluster` converts in place and is idempotent. It has been run
against a copy of the k8s-test stand's live database (schema
`0011-image-scan-workloads`) with every row preserved. Existing rows get
`cluster_id = 'default'`; set `global.clusterId` to the real id before upgrading
if you want the existing data attributed to a named cluster instead.

The conversion rewrites `container_logs` and `audit_events` into partitioned
tables, copying rows into hourly partitions. Anything already past the 26-hour
retention window is dropped during the conversion, which is within both tables'
24-hour TTL.

`central-migrate` is a plain Job named after the release revision, not a hook.
It runs alongside the rollout while the services wait for the expected schema
in an init container, so both `helm install --wait` and `helm upgrade --wait`
complete. Finished Jobs are removed after a day.

Two things to know when upgrading a release installed from an older chart:

- `postgres.storage.size` cannot be changed on an existing StatefulSet. Pass the
  size the release already uses, or recreate the StatefulSet first with
  `kubectl delete sts postgres -n <ns> --cascade=orphan`, which leaves the pod
  and the PVC running.
- A release installed from a chart that stamped `helm.sh/chart` onto the
  `volumeClaimTemplates` needs that same orphan delete once, because the label
  changes with every chart version and volume claim templates are immutable.
  This chart no longer sets it.

Verified end to end on the k8s-test stand: schema `0012-multicluster` applied to
the live database, all thirteen pods healthy, and every event ingested since the
upgrade carries `cluster_id = k8s-test` while the existing history stays under
`default`.
