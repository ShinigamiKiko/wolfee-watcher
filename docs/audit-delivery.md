# Durable audit delivery

Audit admission and informer events are durably queued by each sentry-audit
replica before background HTTP delivery. Admission waits at most 100 ms for
local persistence; it never waits for PostgreSQL or the remote receiver.
The webhook allows the Kubernetes request even when local persistence fails.
`failurePolicy: Ignore` and a one-second webhook timeout bound transport failures.
The 100 ms limit only bounds the admission wait: a record that misses it is still
written and delivered, and `/health` counts it as `late`. Event IDs make retries
safe. Local disk failures or a full spool lose events; `/health` counts them as
`rejected` and they are logged, rather than blocking the Kubernetes API.

The default chart now uses a StatefulSet with a separate 2 GiB PVC per webhook
replica and a 1 GiB delivery limit. The limit counts whole 4 KiB filesystem
blocks, so it matches real disk usage. While the receiver is unreachable the
spool merges small pending files, in order, into gzip segments of up to 4000
records; a long outage therefore costs a few hundred bytes per event instead of
a block each, and the backlog is sent in large batches once the receiver is
back. A crash during merging can only duplicate records, which the receiver
deduplicates. Between retries the spool and the log reader check
`/internal/pull/audit-delivery` every two seconds, so the backlog starts moving
as soon as kvisior answers instead of waiting out the retry delay (up to 30
seconds).

Above `sentryAudit.delivery.shedAt` (80%) of the limit each actor may add
`sentryAudit.delivery.shedPerActor` (60) events per minute; events beyond that
are dropped and counted per actor. One flooding identity therefore cannot push
out rare actions of other users, and the flood itself shows up by name.

With the apiserver audit log connected, a lost or shed admission event is not
gone for good. The webhook marks every request it answers in the audit log, and
kvisior keeps the matching log record. If the admission event has not arrived
five minutes after that record, kvisior stores the record as the event (origin
`apilog`) and runs the rules on it. When the admission event arrives later, its
command, container, ports and object details are added to the same row, which
becomes `both`, and rules that need those fields fire then; rules that already
fired do not fire again.

Every webhook replica reports its queue to kvisior every 15 seconds. Settings ->
Audit log source shows the fill level, pending files and events lost since the
pod started (rejected, shed, quarantined). kvisior raises an alert, delivered to
the configured integrations, when a queue passes 80%, passes 95% or loses
events; a level alerts once, again only after an hour or after an escalation,
and a healthy report resets it once ten minutes have passed since the alert. The ingest and processor deployments get a
PodDisruptionBudget and are spread across nodes. `sentryAudit.delivery.persistence.storageClass`
selects storage. PVCs remain when pods restart or the StatefulSet is removed.
Do not delete undelivered PVCs when reducing replicas; restore those ordinals to
send their backlog. Disabling persistence uses emptyDir and cannot survive pod
replacement. Migrating the previous Deployment to the StatefulSet requires a
Helm upgrade; check that the storage class can provision all claims beforehand.

The apiserver log reader still uses the original audit files and a persistent
read checkpoint. It advances only after the receiver ACK. Keep rotated audit
files long enough for the longest expected outage; compressed/removed files
cannot be replayed. The reader reports how far behind it is: `backlogBytes`,
`backlogFiles` and `lagSeconds`, and, while it is reading a rotated file,
`headroom`, the number of kept rotated files that rotation deletes before it
reaches unread data. Headroom 0 or 1 is logged as `audit_log_backlog_at_risk`
and shown in red in Settings → Audit log source.

RequestResponse is optional. Without it a change seen by the informer is linked
to the API request by object revision or, failing that, by time. When several
requests on the same object fit the time window the event is stored with
`attribution: unconfirmed` and the UI marks the author as unconfirmed.

`/internal/push/audit` and `/internal/push/audit-log` now return 202 only after
committing the raw batch to `audit_inbox` (schema 0015-audit-inbox; queue status needs 0016-audit-spool-status). Batches are
bounded to 512 records and 4 MiB. Identical retries are deduplicated per cluster
and source; processed batch keys remain for the audit retention interval.
The receiver reserves capacity before it reads a request body: at most
`auditDelivery.perClusterConcurrency` concurrent writes per cluster, 16 overall,
and `auditDelivery.receiveBudgetBytes` (24 MiB) of request bodies in flight,
counted by Content-Length or 4 MiB when it is absent. A request over these
limits, a full cluster backlog (`auditDelivery.maxPendingPerCluster`) or a
database outage returns 503 and the source retries; a body declared larger than
4 MiB returns 413. The receiver accepts at most
`auditDelivery.ingest.maxConnections` connections.

A record that PostgreSQL rejects as invalid data returns 400 instead of 503, so
one bad record cannot stop a source. The log reader splits the batch until it
finds the record, skips it and counts it as rejected. The webhook spool sends
the file record by record and moves the rejected ones to `dead/` in the spool
directory; `quarantined`, `deadFiles` and `deadBytes` appear in `/health`, and
dead files count against the spool capacity. To retry them after fixing the
cause, move a file from `dead/` back into the spool directory under a name that
sorts after the newest pending file and restart the pod.

Workers process clusters independently and serialize processing within each
cluster across replicas. Existing audit event/rule transactions prevent repeat
hits or alerts when a worker crashes after processing but before marking the
batch complete. Failed batches retry with capped backoff indefinitely. Pending
batches are never removed by inbox retention; processed payloads are removed,
and completed keys expire after the configured audit retention. Every five
minutes each worker deletes expired keys in chunks until none are left; replicas
share the work. Workers find the next batch of every cluster through the pending
index, so the cost of a poll does not grow with the backlog. Audit history
still follows its configured retention, including events delayed beyond it.

## Separate receiver and processing deployments

```yaml
auditDelivery:
  ingest:
    enabled: true
    replicaCount: 2
    workers: 0
  processor:
    enabled: true
    replicaCount: 2
    workers: 4
```

This deploys the existing kvisior image with `KVISIOR_MODE=ingest` and
`KVISIOR_MODE=audit-worker`. The UI forwards raw audit pushes to the ingestion
service, so these pushes no longer write through the edge UI's database pool.
The default combined deployment remains supported. For a central receiver in
another network set `auditDelivery.receiverURL` to its HTTPS origin. It must
use the existing shared INTERNAL_PUSH_SECRET and enable
KVISIOR_TRUST_CLUSTER_HEADER=true. Provide a server TLS certificate with
`auditDelivery.ingest.tlsSecret` and expose the HTTPS service through your
existing ingress. This change retains the current shared-secret identity model.

The processor publishes live audit updates over the existing Kafka UI bus when
KAFKA_BROKERS is configured. Without a shared bus, separate processes still
persist history, but live SSE delivery across those processes is unavailable.

Only the audit ingestion path is separated here. Existing federation, history,
log-source configuration, and other telemetry services retain their database
access and deployment model. A complete database-free edge would require
moving those additional APIs and writers separately.

`KVISIOR_AUDIT_WORKERS` sets concurrency (0 disables processing in a receiver).
`KVISIOR_AUDIT_INBOX_MAX_PENDING` limits outstanding batches per cluster.
`GET /internal/pull/audit-delivery`, protected by the existing push secret,
reports pending batches, oldest enqueue time, and retry attempts. Source
`/health` reports local spool bytes, capacity, pending files and failures.
Alert on growing age/bytes, repeated failures, and local durability rejection.

## PostgreSQL availability

Configure replication, failover, backups and recovery outside this application.
Use a stable read/write endpoint targeting the primary. kvisior also starts while
PostgreSQL is unreachable: once the database answers it registers the cluster
and its federation endpoint, loads forensic watches and starts retention, alert
cleanup and webhook delivery. A separate control-plane database keeps its own
connection pool through an outage instead of falling back to the data database. Ingestion retains its
connection pool during startup outages; HTTP writes fail without ACK and
sources retain their backlog. Worker failures are retried and ambiguous commits
are safe to replay. PgBouncer limits connection pressure; it does not provide
replication or increase PostgreSQL's write capacity. Size pool limits across
all receiver/worker replicas, leaving room for UI and maintenance connections.

Before rollout, migrate PostgreSQL, then update the receiver/UI, then the source
StatefulSet. Test network disconnection, a PostgreSQL restart, process crashes,
repeated batches, and disk capacity exhaustion. Switch remote clusters one at a
time and monitor both the local backlog and central processing delay.
